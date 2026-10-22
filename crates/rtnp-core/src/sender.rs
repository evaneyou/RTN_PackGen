//! Flow sender engine: UDP, TCP, SCTP (stream-style) and, with the `icmp` feature, ICMP echo.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use socket2::SockRef;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpStream, UdpSocket, lookup_host};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio::time::{Instant, sleep};

use crate::error::{Error, Result};
use crate::flow::{Meter, PayloadData, Proto, ResolvedFlow};
use crate::log::{LogHandle, LogRecord};
use crate::pacer::Pacer;
use crate::proto::{
    FLAG_ECHO_REPLY, FLAG_ECHO_REQ, HEADER_LEN, Header, MAX_TCP_FRAME, MAX_UDP_PACKET,
    RTP_HEADER_LEN, write_rtp,
};
use crate::stats::Summary;
use crate::time::now_ns;

/// How long to wait for outstanding echoes after the last packet in round-trip mode.
const RTT_DRAIN: Duration = Duration::from_secs(1);

#[derive(Debug, Clone)]
pub struct FlowOutcome {
    pub session: u32,
    pub flow: u32,
    pub name: String,
    pub proto: Proto,
    pub sent: u64,
    pub bytes: u64,
    /// Departures that were more than 1 ms behind schedule.
    pub late: u64,
    pub send_errors: u64,
    pub elapsed: Duration,
    /// ICMP and `meter = rtt` flows: round-trip times in milliseconds, ordered by sequence.
    pub rtts_ms: Vec<f64>,
    /// Two-way calls: the return stream as seen by the sender.
    pub reverse: Option<Summary>,
}

/// Live counters of a running flow, readable from another task (interval reporting).
/// Round-trip samples accumulate here until [`take_rtts`](Self::take_rtts) drains them.
#[derive(Debug, Default)]
pub struct FlowProgress {
    sent: AtomicU64,
    bytes: AtomicU64,
    late: AtomicU64,
    replies: AtomicU64,
    failed: AtomicU64,
    rtts: Mutex<Vec<(u64, f64)>>,
    reverse: Mutex<crate::track::Tracked>,
    has_reverse: std::sync::atomic::AtomicBool,
}

impl FlowProgress {
    /// Packets (probes) sent so far.
    pub fn sent(&self) -> u64 {
        self.sent.load(Ordering::Relaxed)
    }

    pub fn bytes(&self) -> u64 {
        self.bytes.load(Ordering::Relaxed)
    }

    pub fn late(&self) -> u64 {
        self.late.load(Ordering::Relaxed)
    }

    /// Round-trip replies received so far (all-time, not reset by draining).
    pub fn replies(&self) -> u64 {
        self.replies.load(Ordering::Relaxed)
    }

    /// ICMP probes that timed out (all-time).
    pub fn failed(&self) -> u64 {
        self.failed.load(Ordering::Relaxed)
    }

    /// Remove and return the round-trip times (ms) collected since the last call, ordered by
    /// sequence number.
    pub fn take_rtts(&self) -> Vec<f64> {
        let mut v = std::mem::take(&mut *self.rtts.lock().unwrap_or_else(|e| e.into_inner()));
        v.sort_by_key(|(s, _)| *s);
        v.into_iter().map(|(_, r)| r).collect()
    }

    /// Whether a return stream (two-way call) is being measured.
    pub fn has_reverse(&self) -> bool {
        self.has_reverse.load(Ordering::Relaxed)
    }

    pub(crate) fn enable_reverse(&self) {
        self.has_reverse.store(true, Ordering::Relaxed);
    }

    pub(crate) fn observe_reverse(
        &self,
        h: &crate::proto::RtpHeader,
        size: usize,
        rx_ns: u64,
        tos: Option<u8>,
    ) {
        let mut t = self.reverse.lock().unwrap_or_else(|e| e.into_inner());
        t.observe_rtp(h, size, rx_ns);
        t.note_tos(tos);
    }

    /// The return stream since the previous call (two-way calls), then start a new window.
    pub fn take_reverse_window(&self) -> Option<Summary> {
        self.has_reverse().then(|| {
            self.reverse
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .take_window()
        })
    }

    /// Whole-run view of the return stream (two-way calls).
    pub fn reverse_total(&self) -> Option<Summary> {
        self.has_reverse().then(|| {
            self.reverse
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .summary()
        })
    }

    pub(crate) fn update(&self, sent: u64, bytes: u64, late: u64) {
        self.sent.store(sent, Ordering::Relaxed);
        self.bytes.store(bytes, Ordering::Relaxed);
        self.late.store(late, Ordering::Relaxed);
    }

    pub(crate) fn push_rtt(&self, seq: u64, ms: f64) {
        self.rtts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push((seq, ms));
        self.replies.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn mark_failed(&self) {
        self.failed.fetch_add(1, Ordering::Relaxed);
    }
}

type RttStore = Arc<FlowProgress>;

enum Writer {
    Udp(Arc<UdpSocket>),
    Stream(OwnedWriteHalf),
}

impl Writer {
    async fn send(&mut self, buf: &[u8]) -> std::io::Result<()> {
        match self {
            Writer::Udp(s) => s.send(buf).await.map(|_| ()),
            Writer::Stream(s) => s.write_all(buf).await,
        }
    }
}

pub(crate) async fn resolve_target(target: &str) -> Result<SocketAddr> {
    let mut addrs = lookup_host(target)
        .await
        .map_err(|e| Error::Config(format!("cannot resolve '{target}': {e}")))?;
    addrs
        .next()
        .ok_or_else(|| Error::Config(format!("'{target}' resolved to no addresses")))
}

pub(crate) fn apply_socket_opts<S>(sock: &S, addr: &SocketAddr, cfg: &ResolvedFlow) -> Result<()>
where
    for<'a> SockRef<'a>: From<&'a S>,
{
    let r = SockRef::from(sock);
    if let Some(ttl) = cfg.ttl {
        if addr.is_ipv4() {
            r.set_ttl_v4(ttl)?;
        } else {
            r.set_unicast_hops_v6(ttl)?;
        }
    }
    if let Some(tos) = cfg.tos
        && addr.is_ipv4()
    {
        r.set_tos_v4(tos as u32)?;
    }
    Ok(())
}

/// Stream-style (one-to-one) SCTP connection, wrapped in a tokio `TcpStream` since the
/// socket API and our framing are identical. Requires kernel SCTP support.
#[cfg(unix)]
async fn connect_sctp(addr: SocketAddr) -> Result<TcpStream> {
    use socket2::{Domain, Protocol, Socket, Type};
    const IPPROTO_SCTP: i32 = 132;
    let sock = Socket::new(
        Domain::for_address(addr),
        Type::STREAM,
        Some(Protocol::from(IPPROTO_SCTP)),
    )
    .map_err(|e| Error::Config(format!("SCTP sockets are not available here: {e}")))?;
    let target = addr.into();
    let sock = tokio::task::spawn_blocking(move || {
        sock.connect_timeout(&target, Duration::from_secs(5))
            .map(|_| sock)
    })
    .await
    .map_err(|e| Error::Protocol(format!("connect task failed: {e}")))??;
    sock.set_nonblocking(true)?;
    Ok(TcpStream::from_std(std::net::TcpStream::from(sock))?)
}

#[cfg(not(unix))]
async fn connect_sctp(_addr: SocketAddr) -> Result<TcpStream> {
    Err(Error::Config("SCTP is only supported on Unix".into()))
}

fn handle_reply(h: &Header, session: u32, flow: u32, log: &LogHandle, store: &RttStore) {
    if h.flags & FLAG_ECHO_REPLY == 0 || h.session != session || h.flow != flow {
        return;
    }
    let t = now_ns();
    let rtt_ns = t.saturating_sub(h.tx_ns);
    log.send(LogRecord::Rtt {
        session,
        flow,
        seq: h.seq,
        size: h.len,
        t_ns: t,
        rtt_ns,
    });
    store.push_rtt(h.seq, rtt_ns as f64 / 1e6);
}

fn spawn_udp_echo_reader(
    sock: Arc<UdpSocket>,
    session: u32,
    flow: u32,
    log: LogHandle,
    store: RttStore,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65_536];
        loop {
            match sock.recv(&mut buf).await {
                Ok(n) => {
                    if let Ok(h) = Header::decode(&buf[..n]) {
                        handle_reply(&h, session, flow, &log, &store);
                    }
                }
                // ECONNREFUSED from an earlier ICMP error: not fatal
                Err(_) => tokio::task::yield_now().await,
            }
        }
    })
}

fn spawn_stream_echo_reader(
    mut r: OwnedReadHalf,
    session: u32,
    flow: u32,
    log: LogHandle,
    store: RttStore,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut hdr = [0u8; HEADER_LEN];
        loop {
            if r.read_exact(&mut hdr).await.is_err() {
                return;
            }
            let Ok(h) = Header::decode(&hdr) else { return };
            if h.len as usize > MAX_TCP_FRAME {
                return;
            }
            let rem = h.len as u64 - HEADER_LEN as u64;
            if rem > 0 {
                match tokio::io::copy(&mut (&mut r).take(rem), &mut tokio::io::sink()).await {
                    Ok(n) if n == rem => {}
                    _ => return,
                }
            }
            handle_reply(&h, session, flow, &log, &store);
        }
    })
}

async fn connect_flow(
    cfg: &ResolvedFlow,
    addr: SocketAddr,
    session: u32,
    flow: u32,
    log: &LogHandle,
    store: &RttStore,
) -> Result<(Writer, Option<JoinHandle<()>>)> {
    let rtt = cfg.meter == Meter::Rtt;
    match cfg.proto {
        Proto::Udp => {
            let bind = if addr.is_ipv4() {
                "0.0.0.0:0"
            } else {
                "[::]:0"
            };
            let s = UdpSocket::bind(bind).await?;
            apply_socket_opts(&s, &addr, cfg)?;
            s.connect(addr).await?;
            let s = Arc::new(s);
            let reader = rtt.then(|| {
                spawn_udp_echo_reader(s.clone(), session, flow, log.clone(), store.clone())
            });
            Ok((Writer::Udp(s), reader))
        }
        Proto::Tcp | Proto::Sctp => {
            let s = if cfg.proto == Proto::Tcp {
                let s = TcpStream::connect(addr).await?;
                s.set_nodelay(true)?;
                s
            } else {
                connect_sctp(addr).await?
            };
            apply_socket_opts(&s, &addr, cfg)?;
            let (r, w) = s.into_split();
            let reader = if rtt {
                Some(spawn_stream_echo_reader(
                    r,
                    session,
                    flow,
                    log.clone(),
                    store.clone(),
                ))
            } else {
                drop(r);
                None
            };
            Ok((Writer::Stream(w), reader))
        }
        Proto::Icmp => unreachable!("ICMP flows use their own engine"),
    }
}

/// Cycles through payload bytes so successive packets carry successive content.
pub(crate) struct PayloadGen {
    data: Option<Arc<Vec<u8>>>,
    off: usize,
}

impl PayloadGen {
    pub(crate) fn new(p: &PayloadData) -> Self {
        PayloadGen {
            data: match p {
                PayloadData::Zero => None,
                PayloadData::Bytes(b) => Some(b.clone()),
            },
            off: 0,
        }
    }

    pub(crate) fn fill(&mut self, out: &mut [u8]) {
        let Some(data) = &self.data else { return }; // zero payload: buffer is already zero
        let mut i = 0;
        while i < out.len() {
            let n = (data.len() - self.off).min(out.len() - i);
            out[i..i + n].copy_from_slice(&data[self.off..self.off + n]);
            i += n;
            self.off = (self.off + n) % data.len();
        }
    }
}

/// Run one flow to completion (or until `stop` flips to `true`).
pub async fn run_flow(
    session: u32,
    flow: u32,
    cfg: ResolvedFlow,
    log: LogHandle,
    log_packets: bool,
    stop: watch::Receiver<bool>,
) -> Result<FlowOutcome> {
    run_flow_with_progress(
        session,
        flow,
        cfg,
        log,
        log_packets,
        stop,
        Arc::new(FlowProgress::default()),
    )
    .await
}

/// Like [`run_flow`], publishing live counters through `progress`. Whoever drains
/// [`FlowProgress::take_rtts`] during the run owns those samples: the returned outcome only
/// holds what was left at the end.
pub async fn run_flow_with_progress(
    session: u32,
    flow: u32,
    cfg: ResolvedFlow,
    log: LogHandle,
    log_packets: bool,
    mut stop: watch::Receiver<bool>,
    progress: Arc<FlowProgress>,
) -> Result<FlowOutcome> {
    if !cfg.start_delay.is_zero() {
        tokio::select! {
            _ = sleep(cfg.start_delay) => {}
            _ = stop.changed() => {}
        }
    }

    if cfg.wire == crate::flow::Wire::Rtp {
        return crate::rtpsend::run(session, flow, cfg, log, log_packets, stop, progress).await;
    }

    if cfg.proto == Proto::Icmp {
        #[cfg(feature = "icmp")]
        return crate::icmp::run(session, flow, cfg, log, stop, progress).await;
        #[cfg(not(feature = "icmp"))]
        return Err(Error::Config(
            "this build does not include ICMP support".into(),
        ));
    }

    let addr = resolve_target(&cfg.target).await?;
    let rtt_mode = cfg.meter == Meter::Rtt;
    let store: RttStore = progress;
    let (mut writer, reader) = connect_flow(&cfg, addr, session, flow, &log, &store).await?;

    let rtp_len = if cfg.rtp.is_some() { RTP_HEADER_LEN } else { 0 };
    let body_start = HEADER_LEN + rtp_len;
    let max_size = if cfg.proto == Proto::Udp {
        MAX_UDP_PACKET
    } else {
        MAX_TCP_FRAME
    };
    let mut pacer = Pacer::new(&cfg, body_start, max_size)?;
    let mut payload = PayloadGen::new(&cfg.payload);
    let ssrc = session ^ flow.rotate_left(16);
    let flags = if rtt_mode { FLAG_ECHO_REQ } else { 0 };
    let mut buf = vec![0u8; 2048];

    log.send(LogRecord::FlowStart {
        session,
        flow,
        role: "tx".into(),
        name: cfg.name.clone(),
        proto: cfg.proto.as_str().into(),
        peer: addr.to_string(),
        t_ns: now_ns(),
    });

    pacer.restart();
    let mut send_errors = 0u64;
    let mut fatal: Option<Error> = None;

    while let Some(size) = pacer.wait(&mut stop).await {
        if buf.len() < size {
            buf.resize(size, 0);
        }
        let t = now_ns();
        Header {
            flags,
            session,
            flow,
            seq: pacer.seq,
            tx_ns: t,
            len: size as u32,
        }
        .encode(&mut buf);
        if let Some(codec) = cfg.rtp {
            // 8 kHz RTP clock: 8 ticks per millisecond of scheduled flow time
            let ts = (pacer.scheduled_offset().as_millis() as u32).wrapping_mul(8);
            write_rtp(
                &mut buf[HEADER_LEN..body_start],
                codec.payload_type(),
                pacer.new_talkspurt,
                pacer.seq as u16,
                ts,
                ssrc,
            );
            pacer.new_talkspurt = false;
        }
        payload.fill(&mut buf[body_start..size]);

        match writer.send(&buf[..size]).await {
            Ok(()) => {
                if log_packets {
                    log.send(LogRecord::Tx {
                        session,
                        flow,
                        seq: pacer.seq,
                        size: size as u32,
                        t_ns: t,
                    });
                }
                pacer.advance(size);
                store.update(pacer.seq - send_errors, pacer.bytes, pacer.late);
            }
            Err(_) if cfg.proto == Proto::Udp => {
                // e.g. ECONNREFUSED after an ICMP port-unreachable: keep sending, count it
                send_errors += 1;
                pacer.advance(0);
                store.update(pacer.seq - send_errors, pacer.bytes, pacer.late);
            }
            Err(e) => {
                fatal = Some(e.into());
                break;
            }
        }
    }

    let sent = pacer.seq - send_errors;

    if let Some(reader) = reader {
        // give outstanding echoes a moment to come home, then stop listening
        if fatal.is_none() {
            let deadline = Instant::now() + RTT_DRAIN;
            while store.replies() < sent && Instant::now() < deadline {
                sleep(Duration::from_millis(5)).await;
            }
        }
        reader.abort();
    }
    if let Writer::Stream(w) = &mut writer {
        let _ = w.shutdown().await;
    }

    log.send(LogRecord::FlowEnd {
        session,
        flow,
        t_ns: now_ns(),
        sent,
        bytes: pacer.bytes,
        late: pacer.late,
    });

    if let Some(e) = fatal {
        return Err(e);
    }
    Ok(FlowOutcome {
        session,
        flow,
        name: cfg.name,
        proto: cfg.proto,
        sent,
        bytes: pacer.bytes,
        late: pacer.late,
        send_errors,
        elapsed: pacer.elapsed(),
        rtts_ms: store.take_rtts(),
        reverse: None,
    })
}
