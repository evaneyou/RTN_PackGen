//! Receiver engine: UDP, TCP and SCTP data listeners, the control channel (optionally
//! authenticated, optionally able to launch flows on behalf of a trusted controller) and an
//! optional Prometheus metrics endpoint.

use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt, sink};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{Notify, Semaphore, watch};
use tokio::task::JoinSet;
use tokio::time::timeout;

use crate::auth;
use crate::client::{self, SessionOptions};
use crate::control::{
    ClientMsg, FlowAnnounce, RemoteFlowSummary, ReverseSpec, ServerMsg, read_msg, write_msg,
};
use crate::error::{Error, Result};
use crate::flow::{Proto, ResolveOpts};
use crate::log::{LogHandle, LogRecord, LogSink};
use crate::metrics;
use crate::proto::{
    FLAG_ECHO_REPLY, FLAG_ECHO_REQ, HEADER_LEN, Header, MAX_TCP_FRAME, RTP_HEADER_LEN, RtpHeader,
    VERSION,
};
use crate::stats::Summary;
use crate::time::now_ns;
use crate::track::Tracked;

pub type FlowKey = (u32, u32);

const MAX_GRACE: Duration = Duration::from_secs(5);
const AUTH_TIMEOUT: Duration = Duration::from_secs(5);
/// Bound on distinct (session, flow) pairs tracked in memory; further ones are counted and ignored.
pub const MAX_TRACKED_FLOWS: usize = 10_000;
/// When the flow table is full, flows idle for longer than this may be evicted for new ones.
const IDLE_EVICT_NS: u64 = 300 * 1_000_000_000;
/// Limits applied to flows launched on behalf of a remote controller.
pub const MAX_LAUNCH_FLOWS: usize = 64;
pub const MAX_LAUNCH_DURATION: Duration = Duration::from_secs(3600);
/// Most return streams (two-way calls) a receiver sends at once.
pub const MAX_REVERSE_STREAMS: usize = 64;
/// A return stream stops when its forward stream has been silent this long.
const REVERSE_IDLE_NS: u64 = 5 * 1_000_000_000;
const MAX_CONCURRENT_LAUNCHES: usize = 2;

#[derive(Debug, Clone)]
pub struct ReceiverConfig {
    pub bind: IpAddr,
    /// `Some(0)` picks a free port; `None` disables the listener.
    pub udp_port: Option<u16>,
    pub tcp_port: Option<u16>,
    /// Stream-style SCTP data listener (needs kernel support).
    pub sctp_port: Option<u16>,
    pub control_port: Option<u16>,
    /// Prometheus text-format endpoint (`GET /metrics`).
    pub metrics_port: Option<u16>,
    /// Stop after the first session reports `Done`.
    pub one_shot: bool,
    /// Require control-channel peers to prove knowledge of this key.
    pub auth_key: Option<Vec<u8>>,
    /// Let authenticated controllers make this host generate traffic. Requires `auth_key`.
    pub allow_launch: bool,
    /// Send constant return streams to senders that ask for a two-way call. Each stream is
    /// bounded (10-200 ms cadence, up to 1400-byte packets), goes only to the address its
    /// forward stream came from, and stops 5 s after that stream goes quiet.
    pub allow_reverse: bool,
    /// Expect SRTP (AES_CM_128_HMAC_SHA1_80) on the UDP data port with this master key. Packets
    /// that fail authentication, and plain RTP, are counted as malformed and dropped.
    pub srtp_key: Option<crate::srtp::MasterKey>,
    /// Answer SIP INVITEs on this UDP port (`Some(0)` picks one). Needs `udp_port`. Callers learn
    /// the RTP port from the SDP answer; SRTP keys offered in SDP (SDES) are accepted per call
    /// unless a fixed `srtp_key` is set, in which case offers must carry that key.
    pub sip_port: Option<u16>,
    /// Serve the control channel over TLS with this certificate.
    pub tls: Option<crate::tls::TlsServer>,
}

impl Default for ReceiverConfig {
    fn default() -> Self {
        ReceiverConfig {
            bind: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            udp_port: None,
            tcp_port: None,
            sctp_port: None,
            control_port: None,
            metrics_port: None,
            one_shot: false,
            auth_key: None,
            allow_launch: false,
            allow_reverse: false,
            srtp_key: None,
            sip_port: None,
            tls: None,
        }
    }
}

/// Drop the longest-idle flow if the table is full. Returns `false` if there is no room.
fn make_room(m: &mut HashMap<FlowKey, Tracked>, key: &FlowKey, rx_ns: u64) -> bool {
    if m.len() < MAX_TRACKED_FLOWS || m.contains_key(key) {
        return true;
    }
    let cutoff = rx_ns.saturating_sub(IDLE_EVICT_NS);
    let victim = m
        .iter()
        .filter(|(_, t)| t.last_seen_ns() < cutoff)
        .min_by_key(|(_, t)| t.last_seen_ns())
        .map(|(k, _)| *k);
    match victim {
        Some(k) => {
            m.remove(&k);
            true
        }
        None => false,
    }
}

/// State shared between the listeners and whoever wants live numbers.
#[derive(Default)]
pub struct Shared {
    stats: Mutex<HashMap<FlowKey, Tracked>>,
    announced: Mutex<HashMap<u32, Vec<FlowAnnounce>>>,
    /// Plain-RTP streams announced over the control channel: SSRC -> (session, flow, has a
    /// return stream to send).
    ssrc_map: Mutex<HashMap<u32, (FlowKey, bool)>>,
    /// Return streams requested by announced flows, and the ones currently running.
    reverse_specs: Mutex<HashMap<FlowKey, ReverseSpec>>,
    reverse_tasks: Mutex<HashMap<FlowKey, Arc<watch::Sender<bool>>>>,
    allow_reverse: AtomicBool,
    pub malformed: AtomicU64,
    /// Packets ignored because [`MAX_TRACKED_FLOWS`] was reached.
    pub overflow: AtomicU64,
    done: Notify,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

impl Shared {
    pub fn snapshot(&self) -> Vec<(FlowKey, Summary)> {
        let mut v: Vec<_> = lock(&self.stats)
            .iter()
            .map(|(k, t)| (*k, t.summary()))
            .collect();
        v.sort_by_key(|(k, _)| *k);
        v
    }

    pub fn session_report(&self, session: u32) -> Vec<RemoteFlowSummary> {
        let stats = lock(&self.stats);
        let announced = lock(&self.announced);
        let mut out: Vec<RemoteFlowSummary> = Vec::new();
        if let Some(flows) = announced.get(&session) {
            for f in flows {
                let summary = stats
                    .get(&(session, f.flow))
                    .map(|t| t.summary())
                    .unwrap_or_default();
                out.push(RemoteFlowSummary {
                    flow: f.flow,
                    name: f.name.clone(),
                    summary,
                });
            }
        }
        for ((s, flow), t) in stats.iter() {
            if *s == session && !out.iter().any(|r| r.flow == *flow) {
                out.push(RemoteFlowSummary {
                    flow: *flow,
                    name: String::new(),
                    summary: t.summary(),
                });
            }
        }
        out.sort_by_key(|r| r.flow);
        out
    }

    /// What arrived for `session` since the previous call, then start a new window. Loss is
    /// measured by sequence gaps, so packets still in flight at a window edge are not
    /// mistaken for loss; gaps show up in the first window that sees a later packet.
    pub fn take_window(&self, session: u32) -> Vec<RemoteFlowSummary> {
        let mut stats = lock(&self.stats);
        let announced = lock(&self.announced);
        let names = announced.get(&session);
        let name_of = |flow: u32| {
            names
                .and_then(|v| v.iter().find(|a| a.flow == flow))
                .map(|a| a.name.clone())
                .unwrap_or_default()
        };
        let mut out: Vec<RemoteFlowSummary> = Vec::new();
        for ((s, flow), t) in stats.iter_mut() {
            if *s != session {
                continue;
            }
            let summary = t.take_window();
            out.push(RemoteFlowSummary {
                flow: *flow,
                name: name_of(*flow),
                summary,
            });
        }
        for f in names.into_iter().flatten() {
            if !out.iter().any(|r| r.flow == f.flow) {
                out.push(RemoteFlowSummary {
                    flow: f.flow,
                    name: f.name.clone(),
                    summary: Summary::default(),
                });
            }
        }
        out.sort_by_key(|r| r.flow);
        out
    }

    fn forget_session(&self, session: u32) {
        lock(&self.announced).remove(&session);
        lock(&self.ssrc_map).retain(|_, ((s, _), _)| *s != session);
        lock(&self.reverse_specs).retain(|(s, _), _| *s != session);
        // stop this session's return streams
        for ((s, _), stop) in lock(&self.reverse_tasks).iter() {
            if *s == session {
                let _ = stop.send(true);
            }
        }
    }

    /// Register a session's flows. Refuses return-stream requests this receiver does not allow
    /// or that are out of bounds.
    fn announce(&self, session: u32, flows: Vec<FlowAnnounce>) -> std::result::Result<(), String> {
        let wants_reverse = flows.iter().any(|f| f.reverse.is_some());
        if wants_reverse && !self.allow_reverse.load(Ordering::Relaxed) {
            return Err(
                "this receiver does not send return streams (start it with --allow-reverse)".into(),
            );
        }
        for f in &flows {
            if let Some(r) = &f.reverse {
                r.validate()?;
            }
        }
        {
            let mut map = lock(&self.ssrc_map);
            let mut specs = lock(&self.reverse_specs);
            for f in &flows {
                if let Some(ssrc) = f.ssrc
                    && (map.len() < MAX_TRACKED_FLOWS || map.contains_key(&ssrc))
                {
                    map.insert(ssrc, ((session, f.flow), f.reverse.is_some()));
                }
                if let Some(r) = &f.reverse {
                    specs.insert((session, f.flow), r.clone());
                }
            }
        }
        lock(&self.announced).insert(session, flows);
        Ok(())
    }

    /// Latch onto the peer of a flow that asked for a return stream and start sending to it.
    /// The stream stops when the session ends or the forward stream goes quiet.
    fn ensure_reverse(self: &Arc<Self>, sock: &Arc<UdpSocket>, peer: SocketAddr, key: FlowKey) {
        let Some(spec) = lock(&self.reverse_specs).get(&key).cloned() else {
            return;
        };
        let stop = {
            let mut tasks = lock(&self.reverse_tasks);
            if tasks.contains_key(&key) || tasks.len() >= MAX_REVERSE_STREAMS {
                return;
            }
            let (tx, _) = watch::channel(false);
            let tx = Arc::new(tx);
            tasks.insert(key, tx.clone());
            tx
        };
        let shared = self.clone();
        let sock = sock.clone();
        tokio::spawn(async move {
            let mut run = Box::pin(crate::rtpsend::run_reverse(
                sock,
                peer,
                spec,
                stop.subscribe(),
            ));
            loop {
                tokio::select! {
                    _ = &mut run => break,
                    _ = tokio::time::sleep(Duration::from_millis(500)) => {
                        let idle = lock(&shared.stats)
                            .get(&key)
                            .is_none_or(|t| now_ns().saturating_sub(t.last_seen_ns()) > REVERSE_IDLE_NS);
                        if idle {
                            let _ = stop.send(true);
                        }
                    }
                }
            }
            lock(&shared.reverse_tasks).remove(&key);
        });
    }

    /// A plain-RTP packet (UDP payload `pkt`). Streams the sender announced are attributed to
    /// their session and flow; any other RTP source is tracked as session 0, flow = SSRC.
    fn record_rtp(
        self: &Arc<Self>,
        sock: &Arc<UdpSocket>,
        log: &LogHandle,
        peer: SocketAddr,
        pkt: &[u8],
        rx_ns: u64,
        tos: Option<u8>,
    ) {
        let Some(h) = RtpHeader::parse(pkt) else {
            self.malformed.fetch_add(1, Ordering::Relaxed);
            return;
        };
        let (key, wants_reverse) = lock(&self.ssrc_map)
            .get(&h.ssrc)
            .copied()
            .unwrap_or(((0, h.ssrc), false));
        let (is_new, seq, tx_ns) = {
            let mut m = lock(&self.stats);
            if !make_room(&mut m, &key, rx_ns) {
                self.overflow.fetch_add(1, Ordering::Relaxed);
                return;
            }
            let entry = m.entry(key);
            let is_new = matches!(entry, Entry::Vacant(_));
            let t = entry.or_default();
            let Some((seq, tx_ns)) = t.observe_rtp(&h, pkt.len(), rx_ns) else {
                return;
            };
            t.note_tos(tos);
            (is_new, seq, tx_ns)
        };
        if wants_reverse {
            self.ensure_reverse(sock, peer, key);
        }
        if is_new {
            log.send(LogRecord::FlowStart {
                session: key.0,
                flow: key.1,
                role: "rx".into(),
                name: String::new(),
                proto: "udp".into(),
                peer: peer.to_string(),
                t_ns: rx_ns,
            });
        }
        log.send(LogRecord::Rx {
            session: key.0,
            flow: key.1,
            seq,
            size: pkt.len() as u32,
            tx_ns,
            t_ns: rx_ns,
        });
    }

    fn record(
        &self,
        log: &LogHandle,
        peer: SocketAddr,
        proto: Proto,
        h: &Header,
        rx_ns: u64,
        tos: Option<u8>,
    ) {
        let key = (h.session, h.flow);
        let is_new = {
            let mut m = lock(&self.stats);
            // make room by dropping the longest-idle flow, if any has been quiet long enough
            if !make_room(&mut m, &key, rx_ns) {
                self.overflow.fetch_add(1, Ordering::Relaxed);
                return;
            }
            let entry = m.entry(key);
            let new = matches!(entry, Entry::Vacant(_));
            let t = entry.or_default();
            t.observe(h.seq, h.len as usize, h.tx_ns, rx_ns);
            t.note_tos(tos);
            new
        };
        if is_new {
            log.send(LogRecord::FlowStart {
                session: h.session,
                flow: h.flow,
                role: "rx".into(),
                name: String::new(),
                proto: proto.as_str().into(),
                peer: peer.to_string(),
                t_ns: rx_ns,
            });
        }
        log.send(LogRecord::Rx {
            session: h.session,
            flow: h.flow,
            seq: h.seq,
            size: h.len,
            tx_ns: h.tx_ns,
            t_ns: rx_ns,
        });
    }
}

struct ControlCtx {
    shared: Arc<Shared>,
    one_shot: bool,
    key: Option<Vec<u8>>,
    allow_launch: bool,
    launch_slots: Semaphore,
    tls: Option<crate::tls::TlsServer>,
}

pub struct Receiver {
    one_shot: bool,
    auth_key: Option<Vec<u8>>,
    allow_launch: bool,
    srtp_key: Option<crate::srtp::MasterKey>,
    sip: Option<UdpSocket>,
    tls: Option<crate::tls::TlsServer>,
    call_keys: Arc<crate::sip::CallKeys>,
    udp: Option<UdpSocket>,
    tcp: Option<TcpListener>,
    sctp: Option<TcpListener>,
    ctl: Option<TcpListener>,
    metrics: Option<TcpListener>,
    shared: Arc<Shared>,
    log: LogHandle,
}

#[cfg(unix)]
fn bind_sctp(addr: SocketAddr) -> Result<TcpListener> {
    use socket2::{Domain, Protocol, Socket, Type};
    const IPPROTO_SCTP: i32 = 132;
    let sock = Socket::new(
        Domain::for_address(addr),
        Type::STREAM,
        Some(Protocol::from(IPPROTO_SCTP)),
    )
    .map_err(|e| Error::Config(format!("SCTP sockets are not available here: {e}")))?;
    sock.set_reuse_address(true)?;
    sock.bind(&addr.into())?;
    sock.listen(128)?;
    sock.set_nonblocking(true)?;
    Ok(TcpListener::from_std(std::net::TcpListener::from(sock))?)
}

#[cfg(not(unix))]
fn bind_sctp(_addr: SocketAddr) -> Result<TcpListener> {
    Err(Error::Config("SCTP is only supported on Unix".into()))
}

impl Receiver {
    pub async fn bind(cfg: ReceiverConfig, log: LogHandle) -> Result<Receiver> {
        if cfg.udp_port.is_none()
            && cfg.tcp_port.is_none()
            && cfg.sctp_port.is_none()
            && cfg.control_port.is_none()
        {
            return Err(Error::Config("all receiver listeners are disabled".into()));
        }
        if cfg.allow_launch && (cfg.auth_key.is_none() || cfg.control_port.is_none()) {
            return Err(Error::Config(
                "remote launch needs both a control port and an authentication key".into(),
            ));
        }
        let udp = match cfg.udp_port {
            Some(p) => Some(UdpSocket::bind((cfg.bind, p)).await?),
            None => None,
        };
        let sip = match cfg.sip_port {
            Some(p) => {
                if udp.is_none() {
                    return Err(Error::Config(
                        "the SIP responder needs a UDP data port".into(),
                    ));
                }
                Some(UdpSocket::bind((cfg.bind, p)).await?)
            }
            None => None,
        };
        let tcp = match cfg.tcp_port {
            Some(p) => Some(TcpListener::bind((cfg.bind, p)).await?),
            None => None,
        };
        let sctp = match cfg.sctp_port {
            Some(p) => Some(bind_sctp(SocketAddr::new(cfg.bind, p))?),
            None => None,
        };
        let ctl = match cfg.control_port {
            Some(p) => Some(TcpListener::bind((cfg.bind, p)).await?),
            None => None,
        };
        let metrics = match cfg.metrics_port {
            Some(p) => Some(TcpListener::bind((cfg.bind, p)).await?),
            None => None,
        };
        Ok(Receiver {
            one_shot: cfg.one_shot,
            auth_key: cfg.auth_key,
            allow_launch: cfg.allow_launch,
            srtp_key: cfg.srtp_key,
            sip,
            tls: cfg.tls,
            call_keys: Arc::default(),
            udp,
            tcp,
            sctp,
            ctl,
            metrics,
            shared: {
                let shared = Shared::default();
                shared
                    .allow_reverse
                    .store(cfg.allow_reverse, Ordering::Relaxed);
                Arc::new(shared)
            },
            log,
        })
    }

    pub fn udp_addr(&self) -> Option<SocketAddr> {
        self.udp.as_ref().and_then(|s| s.local_addr().ok())
    }

    pub fn sip_addr(&self) -> Option<SocketAddr> {
        self.sip.as_ref().and_then(|s| s.local_addr().ok())
    }

    /// Calls with an SRTP key learned from SDP that have not hung up yet.
    pub fn call_keys(&self) -> Arc<crate::sip::CallKeys> {
        self.call_keys.clone()
    }

    pub fn tcp_addr(&self) -> Option<SocketAddr> {
        self.tcp.as_ref().and_then(|s| s.local_addr().ok())
    }

    pub fn sctp_addr(&self) -> Option<SocketAddr> {
        self.sctp.as_ref().and_then(|s| s.local_addr().ok())
    }

    pub fn control_addr(&self) -> Option<SocketAddr> {
        self.ctl.as_ref().and_then(|s| s.local_addr().ok())
    }

    pub fn metrics_addr(&self) -> Option<SocketAddr> {
        self.metrics.as_ref().and_then(|s| s.local_addr().ok())
    }

    pub fn shared(&self) -> Arc<Shared> {
        self.shared.clone()
    }

    /// Serve until `shutdown` resolves, a listener fails, or (in one-shot mode) a session completes.
    pub async fn serve<F: Future<Output = ()>>(self, shutdown: F) -> Result<()> {
        let mut set: JoinSet<Result<()>> = JoinSet::new();
        let srtp = self.srtp_key.as_ref().map(crate::srtp::SrtpReceiver::new);
        if let (Some(s), Some(u)) = (
            self.sip,
            self.udp.as_ref().and_then(|u| u.local_addr().ok()),
        ) {
            let policy = crate::sip::Policy {
                media_port: u.port(),
                static_key: self.srtp_key.clone(),
            };
            set.spawn(crate::sip::serve(s, policy, self.call_keys.clone()));
        }
        if let Some(s) = self.udp {
            set.spawn(udp_loop(
                s,
                self.shared.clone(),
                self.log.clone(),
                srtp,
                self.call_keys.clone(),
            ));
        }
        if let Some(l) = self.tcp {
            set.spawn(stream_accept_loop(
                l,
                Proto::Tcp,
                self.shared.clone(),
                self.log.clone(),
            ));
        }
        if let Some(l) = self.sctp {
            set.spawn(stream_accept_loop(
                l,
                Proto::Sctp,
                self.shared.clone(),
                self.log.clone(),
            ));
        }
        if let Some(l) = self.ctl {
            let ctx = Arc::new(ControlCtx {
                shared: self.shared.clone(),
                one_shot: self.one_shot,
                key: self.auth_key.clone(),
                allow_launch: self.allow_launch,
                launch_slots: Semaphore::new(MAX_CONCURRENT_LAUNCHES),
                tls: self.tls.clone(),
            });
            set.spawn(control_loop(l, ctx));
        }
        if let Some(l) = self.metrics {
            set.spawn(metrics::serve(l, self.shared.clone()));
        }

        let mut result = Ok(());
        tokio::select! {
            _ = shutdown => {}
            _ = self.shared.done.notified() => {}
            r = set.join_next() => {
                match r {
                    Some(Ok(Err(e))) => result = Err(e),
                    Some(Err(e)) => result = Err(Error::Protocol(format!("listener task failed: {e}"))),
                    _ => {}
                }
            }
        }
        set.abort_all();
        while set.join_next().await.is_some() {}
        result
    }
}

/// Receiver report for the first sender report in `pkt` (immediate, so DLSR is ~0).
fn rtcp_reply(pkt: &[u8]) -> Option<Vec<u8>> {
    use crate::rtcp::{self, Rtcp};
    for p in rtcp::parse(pkt) {
        if let Rtcp::Sr { ssrc, info, .. } = p {
            let block = rtcp::ReportBlock {
                ssrc,
                lsr: rtcp::middle32(info.ntp_msw, info.ntp_lsw),
                dlsr: 0,
                ..Default::default()
            };
            return Some(rtcp::build_rr(0xD17C_0001, Some(&block), "rtnp-recv@rtnp"));
        }
    }
    None
}

async fn udp_loop(
    sock: UdpSocket,
    shared: Arc<Shared>,
    log: LogHandle,
    mut srtp: Option<crate::srtp::SrtpReceiver>,
    call_keys: Arc<crate::sip::CallKeys>,
) -> Result<()> {
    crate::tos::enable_recv_tos(&sock);
    let sock = Arc::new(sock);
    let mut buf = vec![0u8; 65_536];
    loop {
        let (n, peer, tos) = match crate::tos::recv_from(&sock, &mut buf).await {
            Ok(v) => v,
            // Windows reports ICMP port-unreachable as a recv error; Linux does not for unconnected sockets.
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => continue,
            Err(e) => return Err(e.into()),
        };
        let rx_ns = now_ns();
        // RTCP shares the RTP port (RFC 5761): answer sender reports so the sender can time the
        // round trip. The answer is no larger than the report, so this cannot amplify.
        if crate::rtcp::is_rtcp(&buf[..n]) {
            if let Some(reply) = rtcp_reply(&buf[..n]) {
                let _ = crate::tos::send_to(&sock, &reply, peer, None).await;
            }
            continue;
        }
        // Plain RTP starts with version 2 (0b10..); our own header starts with 0x44 ('D').
        if n >= RTP_HEADER_LEN && buf[0] >> 6 == 2 {
            let n = match srtp.as_mut() {
                Some(rx) => match rx.unprotect(&mut buf[..n]) {
                    Some(len) => len,
                    None => {
                        shared.malformed.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                },
                // SRTP learned from a SIP call, looked up by the source the caller announced
                None => match call_keys.unprotect(peer, &mut buf[..n]) {
                    Some(Some(len)) => len,
                    Some(None) => {
                        shared.malformed.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                    None => n,
                },
            };
            shared.record_rtp(&sock, &log, peer, &buf[..n], rx_ns, tos);
            continue;
        }
        match Header::decode(&buf[..n]) {
            Ok(h) if h.len as usize == n => {
                if h.flags & FLAG_ECHO_REPLY != 0 {
                    continue; // stray reflected packet, not forward traffic
                }
                shared.record(&log, peer, Proto::Udp, &h, rx_ns, tos);
                if h.flags & FLAG_ECHO_REQ != 0 {
                    // reflect the packet unchanged apart from the flags (same size: no amplification)
                    buf[3] = (h.flags & !FLAG_ECHO_REQ) | FLAG_ECHO_REPLY;
                    let _ = sock.send_to(&buf[..n], peer).await;
                }
            }
            _ => {
                shared.malformed.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

async fn stream_accept_loop(
    listener: TcpListener,
    proto: Proto,
    shared: Arc<Shared>,
    log: LogHandle,
) -> Result<()> {
    let mut conns: JoinSet<()> = JoinSet::new();
    loop {
        tokio::select! {
            r = listener.accept() => {
                let (stream, peer) = r?;
                conns.spawn(stream_conn(stream, peer, proto, shared.clone(), log.clone()));
            }
            Some(_) = conns.join_next(), if !conns.is_empty() => {}
        }
    }
}

async fn stream_conn(
    s: TcpStream,
    peer: SocketAddr,
    proto: Proto,
    shared: Arc<Shared>,
    log: LogHandle,
) {
    // Reflected frames must not wait for Nagle/delayed-ACK; SCTP may reject the option, which is fine.
    let _ = s.set_nodelay(true);
    let (mut r, mut w): (OwnedReadHalf, OwnedWriteHalf) = s.into_split();
    let mut hdr = [0u8; HEADER_LEN];
    let mut body = Vec::new();
    loop {
        if r.read_exact(&mut hdr).await.is_err() {
            return; // EOF or reset
        }
        let h = match Header::decode(&hdr) {
            Ok(h) if (h.len as usize) <= MAX_TCP_FRAME => h,
            _ => {
                shared.malformed.fetch_add(1, Ordering::Relaxed);
                return;
            }
        };
        let remaining = h.len as u64 - HEADER_LEN as u64;
        let echo = h.flags & FLAG_ECHO_REQ != 0;
        if echo {
            body.clear();
            body.resize(remaining as usize, 0);
            if r.read_exact(&mut body).await.is_err() {
                return;
            }
        } else if remaining > 0 {
            match tokio::io::copy(&mut (&mut r).take(remaining), &mut sink()).await {
                Ok(n) if n == remaining => {}
                _ => return,
            }
        }
        shared.record(&log, peer, proto, &h, now_ns(), None);
        if echo {
            hdr[3] = (h.flags & !FLAG_ECHO_REQ) | FLAG_ECHO_REPLY;
            if w.write_all(&hdr).await.is_err() || w.write_all(&body).await.is_err() {
                return;
            }
        }
    }
}

async fn control_loop(listener: TcpListener, ctx: Arc<ControlCtx>) -> Result<()> {
    let mut conns: JoinSet<()> = JoinSet::new();
    loop {
        tokio::select! {
            r = listener.accept() => {
                let (stream, _) = r?;
                let ctx = ctx.clone();
                conns.spawn(async move {
                    // the TLS handshake runs here, so a slow client cannot stall the accept loop
                    if let Ok(s) = crate::tls::accept_optional(ctx.tls.as_ref(), stream).await {
                        control_conn(s, ctx).await;
                    }
                });
            }
            Some(_) = conns.join_next(), if !conns.is_empty() => {}
        }
    }
}

async fn send_error(s: &mut crate::tls::Stream, message: impl Into<String>) {
    let _ = write_msg(
        s,
        &ServerMsg::Error {
            message: message.into(),
        },
    )
    .await;
}

async fn control_conn(mut s: crate::tls::Stream, ctx: Arc<ControlCtx>) {
    if let Some(key) = &ctx.key {
        match timeout(AUTH_TIMEOUT, auth::server_handshake(&mut s, key)).await {
            Ok(Ok(())) => {}
            _ => return, // wrong key, garbage or timeout: drop silently
        }
    }
    loop {
        let msg: ClientMsg = match read_msg(&mut s).await {
            Ok(Some(m)) => m,
            _ => return,
        };
        match msg {
            ClientMsg::Hello {
                version,
                session,
                flows,
            } => {
                if version != VERSION {
                    send_error(
                        &mut s,
                        format!(
                            "unsupported protocol version {version}, receiver speaks {VERSION}"
                        ),
                    )
                    .await;
                    return;
                }
                if let Err(message) = ctx.shared.announce(session, flows) {
                    send_error(&mut s, message).await;
                    return;
                }
                let reply = ServerMsg::Ready {
                    version: VERSION,
                    reverse: ctx.shared.allow_reverse.load(Ordering::Relaxed),
                };
                if write_msg(&mut s, &reply).await.is_err() {
                    return;
                }
            }
            ClientMsg::Done { session, grace_ms } => {
                tokio::time::sleep(Duration::from_millis(grace_ms).min(MAX_GRACE)).await;
                let flows = ctx.shared.session_report(session);
                ctx.shared.forget_session(session);
                let _ = write_msg(&mut s, &ServerMsg::Report { session, flows }).await;
                if ctx.one_shot {
                    ctx.shared.done.notify_one();
                }
            }
            ClientMsg::Poll { session } => {
                let flows = ctx.shared.take_window(session);
                if write_msg(&mut s, &ServerMsg::Window { session, flows })
                    .await
                    .is_err()
                {
                    return;
                }
            }
            ClientMsg::Launch { flows, control } => {
                if !handle_launch(&mut s, &ctx, flows, control).await {
                    return;
                }
            }
        }
    }
}

/// Returns `false` when the connection should be closed.
async fn handle_launch(
    s: &mut crate::tls::Stream,
    ctx: &ControlCtx,
    specs: Vec<crate::flow::FlowSpec>,
    control: Option<String>,
) -> bool {
    if !ctx.allow_launch {
        send_error(
            s,
            "remote launch is disabled on this receiver (start it with --allow-launch and a key)",
        )
        .await;
        return true;
    }
    if specs.is_empty() || specs.len() > MAX_LAUNCH_FLOWS {
        send_error(
            s,
            format!("a launch must contain between 1 and {MAX_LAUNCH_FLOWS} flows"),
        )
        .await;
        return true;
    }
    // Flows from a remote peer never read local files and are time-boxed.
    let opts = ResolveOpts {
        allow_file_payload: false,
        max_duration: Some(MAX_LAUNCH_DURATION),
    };
    let mut resolved = Vec::new();
    for (i, spec) in specs.iter().enumerate() {
        match spec.resolve_with(i, &opts) {
            Ok(f) => resolved.push(f),
            Err(e) => {
                send_error(s, format!("flow {} rejected: {e}", i + 1)).await;
                return true;
            }
        }
    }
    let Ok(_slot) = ctx.launch_slots.try_acquire() else {
        send_error(s, "agent is busy with other launches").await;
        return true;
    };

    let (stop_tx, stop_rx) = watch::channel(false);
    let mut sess = SessionOptions::new(LogSink::none().handle());
    sess.control = control;
    sess.key = ctx.key.clone();
    let mut task = tokio::spawn(client::run_session(resolved, sess, stop_rx));

    let mut probe = [0u8; 1];
    loop {
        tokio::select! {
            r = &mut task => {
                let reply = match r {
                    Ok(Ok(res)) => {
                        let mut errors = res.errors;
                        errors.extend(res.warnings);
                        ServerMsg::LaunchReport { reports: res.reports, errors }
                    }
                    Ok(Err(e)) => ServerMsg::Error { message: e.to_string() },
                    Err(e) => ServerMsg::Error { message: format!("launch task failed: {e}") },
                };
                return write_msg(s, &reply).await.is_ok();
            }
            n = s.read(&mut probe) => {
                if matches!(n, Ok(0) | Err(_)) {
                    // controller went away: stop generating traffic
                    let _ = stop_tx.send(true);
                    task.abort();
                    return false;
                }
            }
        }
    }
}
