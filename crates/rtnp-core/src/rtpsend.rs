//! Plain-RTP sender: the UDP payload is exactly an RTP packet (RFC 3550), as a phone or video
//! encoder would emit. Voice follows the usual codec cadence (with optional talkspurt/silence
//! gaps and the marker bit on the first packet of a talkspurt); video sends frames at a fixed
//! rate, split into packets that share a timestamp, with the marker bit on the last one.
//!
//! The initial sequence number and timestamp are random and the SSRC is derived from the
//! session and flow, so the receiver can attribute the stream when told about it.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use rand::{Rng, SeedableRng, rngs::StdRng};
use tokio::net::UdpSocket;
use tokio::sync::watch;
use tokio::time::{Instant, sleep_until};

use crate::control::ReverseSpec;
use crate::dist::Dist;
use crate::error::Result;
use crate::flow::{Meter, PayloadData, Proto, ResolvedFlow, StopCond, VideoSpec, Wire};
use crate::log::{LogHandle, LogRecord};
use crate::pacer::Pacer;
use crate::proto::{MAX_UDP_PACKET, RTP_HEADER_LEN, RtpHeader, reverse_ssrc, ssrc_for, write_rtp};
use crate::sender::{FlowOutcome, FlowProgress, PayloadGen, apply_socket_opts, resolve_target};
use crate::time::now_ns;

const LATE_THRESHOLD: Duration = Duration::from_millis(1);
const RESYNC_THRESHOLD: Duration = Duration::from_secs(1);

/// Counters shared by the audio and video loops.
struct Tx {
    sock: Arc<UdpSocket>,
    /// Unconnected sockets (return streams) send to this address.
    dest: Option<SocketAddr>,
    /// Per-packet TOS for datagrams sent with `dest` (the socket is shared, so it cannot be
    /// set socket-wide).
    tos: Option<u8>,
    session: u32,
    flow: u32,
    log: LogHandle,
    log_packets: bool,
    progress: Arc<FlowProgress>,
    packets: u64,
    bytes: u64,
    late: u64,
    errors: u64,
    /// SRTP: session keys and the rollover-counter tracker.
    srtp: Option<(crate::srtp::SessionKeys, crate::srtp::TxIndex)>,
}

impl Tx {
    /// Send `buf[..len]`; with SRTP the payload is encrypted in place and a tag appended
    /// (`buf` needs `TAG_LEN` spare bytes).
    async fn send(&mut self, buf: &mut [u8], len: usize) {
        let len = match &self.srtp {
            Some((keys, idx)) => {
                // sequence numbers advance on every attempt, sent or not
                let roc = idx.roc(self.packets.wrapping_add(self.errors));
                keys.protect(buf, len, roc)
            }
            None => len,
        };
        let pkt = &buf[..len];
        let sent = match self.dest {
            Some(d) => crate::tos::send_to(&self.sock, pkt, d, self.tos).await,
            None => self.sock.send(pkt).await,
        };
        match sent {
            Ok(_) => {
                if self.log_packets {
                    self.log.send(LogRecord::Tx {
                        session: self.session,
                        flow: self.flow,
                        seq: self.packets,
                        size: pkt.len() as u32,
                        t_ns: now_ns(),
                    });
                }
                self.packets += 1;
                self.bytes += pkt.len() as u64;
            }
            // e.g. ECONNREFUSED after an ICMP port-unreachable: keep going, count it
            Err(_) => self.errors += 1,
        }
        self.progress.update(self.packets, self.bytes, self.late);
    }
}

pub(crate) async fn run(
    session: u32,
    flow: u32,
    cfg: ResolvedFlow,
    log: LogHandle,
    log_packets: bool,
    mut stop: watch::Receiver<bool>,
    progress: Arc<FlowProgress>,
) -> Result<FlowOutcome> {
    let addr = resolve_target(&cfg.target).await?;
    let bind = if addr.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let sock = UdpSocket::bind(bind).await?;
    // With SIP the target is the callee's SIP port; media goes where the answer says.
    let mut call = None;
    let addr = if cfg.sip {
        let codec = cfg.rtp.expect("resolve guarantees a codec for SIP calls");
        let ptime_ms = match &cfg.idt_ms {
            crate::dist::Dist::Constant { value } => Some(value.round() as u32),
            _ => None,
        };
        let c = crate::sip::invite(crate::sip::Offer {
            sip_target: addr,
            media_port: sock.local_addr()?.port(),
            pt: codec.payload_type(),
            ptime_ms,
            key: cfg.srtp_key.as_ref(),
        })
        .await?;
        let media = c.media;
        call = Some(c);
        media
    } else {
        addr
    };
    apply_socket_opts(&sock, &addr, &cfg)?;
    sock.connect(addr).await?;

    let mut rng = StdRng::seed_from_u64(cfg.seed.unwrap_or_else(rand::random));
    let seq0: u16 = rng.random();
    let ts0: u32 = rng.random();
    let ssrc = ssrc_for(session, flow);

    log.send(LogRecord::FlowStart {
        session,
        flow,
        role: "tx".into(),
        name: cfg.name.clone(),
        proto: Proto::Udp.as_str().into(),
        peer: addr.to_string(),
        t_ns: now_ns(),
    });

    let sock = Arc::new(sock);
    if cfg.bidirectional {
        progress.enable_reverse();
    }
    let reader = (cfg.bidirectional || cfg.rtcp_interval.is_some()).then(|| {
        spawn_reader(
            sock.clone(),
            ssrc,
            cfg.bidirectional.then(|| reverse_ssrc(session, flow)),
            // the return stream of a two-way SRTP call is protected with the same master key
            cfg.srtp_key
                .as_ref()
                .filter(|_| cfg.bidirectional)
                .map(crate::srtp::SrtpReceiver::new),
            progress.clone(),
        )
    });
    let rtcp = cfg.rtcp_interval.map(|every| {
        tokio::spawn(rtcp_sender(
            sock.clone(),
            ssrc,
            ts0,
            cfg.video.is_some(),
            every,
            progress.clone(),
        ))
    });
    let mut tx = Tx {
        sock,
        dest: None,
        tos: None,
        session,
        flow,
        log: log.clone(),
        log_packets,
        progress,
        packets: 0,
        bytes: 0,
        late: 0,
        errors: 0,
        srtp: cfg
            .srtp_key
            .as_ref()
            .map(|k| (k.session(), crate::srtp::TxIndex::new(seq0))),
    };

    let started = Instant::now();
    match &cfg.video {
        Some(v) => run_video(&mut tx, &cfg, v, rng, seq0, ts0, ssrc, &mut stop).await?,
        None => run_audio(&mut tx, &cfg, seq0, ts0, ssrc, &mut stop).await?,
    }

    if let Some(t) = rtcp {
        t.abort();
    }
    if let Some(reader) = reader {
        // let the last return packets (and RTCP answers) arrive before we stop listening
        tokio::time::sleep(REVERSE_DRAIN).await;
        reader.abort();
    }
    if let Some(c) = call {
        c.bye().await;
    }
    let sent = tx.packets;
    log.send(LogRecord::FlowEnd {
        session,
        flow,
        t_ns: now_ns(),
        sent,
        bytes: tx.bytes,
        late: tx.late,
    });
    Ok(FlowOutcome {
        session,
        flow,
        name: cfg.name,
        proto: Proto::Udp,
        sent,
        bytes: tx.bytes,
        late: tx.late,
        send_errors: tx.errors,
        elapsed: started.elapsed(),
        rtts_ms: tx.progress.take_rtts(),
        reverse: tx.progress.reverse_total(),
    })
}

const REVERSE_DRAIN: Duration = Duration::from_millis(300);

/// Listen on the flow's own socket for RTCP answers to our sender reports and, for two-way
/// calls, the far end's return stream (symmetric RTP).
fn spawn_reader(
    sock: Arc<UdpSocket>,
    ssrc: u32,
    reverse_ssrc: Option<u32>,
    mut reverse_srtp: Option<crate::srtp::SrtpReceiver>,
    progress: Arc<FlowProgress>,
) -> tokio::task::JoinHandle<()> {
    crate::tos::enable_recv_tos(&sock);
    tokio::spawn(async move {
        let mut buf = vec![0u8; 2048];
        loop {
            match crate::tos::recv_from(&sock, &mut buf).await {
                Ok((n, _, tos)) => {
                    let rx_ns = now_ns();
                    if crate::rtcp::is_rtcp(&buf[..n]) {
                        let arrival = crate::rtcp::ntp_mid_now();
                        for p in crate::rtcp::parse(&buf[..n]) {
                            if let crate::rtcp::Rtcp::Rr { blocks, .. }
                            | crate::rtcp::Rtcp::Sr { blocks, .. } = p
                            {
                                for b in blocks.iter().filter(|b| b.ssrc == ssrc) {
                                    if let Some(ms) = crate::rtcp::rtt_ms(b, arrival) {
                                        progress.push_rtt(progress.replies(), ms);
                                    }
                                }
                            }
                        }
                    } else if let Some(h) = RtpHeader::parse(&buf[..n])
                        && Some(h.ssrc) == reverse_ssrc
                    {
                        // SRTP: packets that fail authentication are dropped (they show as
                        // loss); sizes are counted after decryption, like the forward stream
                        let len = match reverse_srtp.as_mut() {
                            Some(rx) => match rx.unprotect(&mut buf[..n]) {
                                Some(len) => len,
                                None => continue,
                            },
                            None => n,
                        };
                        progress.observe_reverse(&h, len, rx_ns, tos);
                    }
                }
                // ECONNREFUSED from an earlier ICMP error: not fatal
                Err(_) => tokio::task::yield_now().await,
            }
        }
    })
}

/// Send an RTCP sender report (plus CNAME) every `every`; the first goes out immediately so a
/// round trip is available early.
async fn rtcp_sender(
    sock: Arc<UdpSocket>,
    ssrc: u32,
    ts0: u32,
    video: bool,
    every: Duration,
    progress: Arc<FlowProgress>,
) {
    let clock = if video { 90_000.0 } else { 8_000.0 };
    let start = Instant::now();
    let cname = format!("rtnp-{ssrc:08x}@rtnp");
    let mut tick = tokio::time::interval(every);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tick.tick().await;
        let (msw, lsw) = crate::rtcp::ntp_now();
        let ts = ts0.wrapping_add((start.elapsed().as_secs_f64() * clock) as u32);
        let info = crate::rtcp::SenderInfo {
            ntp_msw: msw,
            ntp_lsw: lsw,
            rtp_ts: ts,
            packets: progress.sent() as u32,
            octets: progress.bytes() as u32,
        };
        // a refused or dropped report just means one less sample
        let _ = sock.send(&crate::rtcp::build_sr(ssrc, &info, &cname)).await;
    }
}

/// The receiver's half of a two-way call: constant plain-RTP voice from the receiver's data
/// socket to `dest`, until `stop` flips. Bounds were checked when the request was accepted.
pub(crate) async fn run_reverse(
    sock: Arc<UdpSocket>,
    dest: SocketAddr,
    spec: ReverseSpec,
    srtp_key: Option<crate::srtp::MasterKey>,
    mut stop: watch::Receiver<bool>,
) {
    let payload = match spec.codec.silence_byte() {
        Some(b) => PayloadData::Bytes(Arc::new(vec![b])),
        None => PayloadData::Zero,
    };
    let cfg = ResolvedFlow {
        name: "reverse".into(),
        proto: Proto::Udp,
        target: dest.to_string(),
        idt_ms: Dist::Constant { value: spec.idt_ms },
        size: Dist::Constant {
            value: spec.packet_bytes as f64,
        },
        stop: StopCond::default(),
        start_delay: Duration::ZERO,
        ttl: None,
        tos: None,
        seed: None,
        meter: Meter::Owd,
        payload,
        rtp: Some(spec.codec),
        vad: None,
        wire: Wire::Rtp,
        video: None,
        bidirectional: false,
        rtcp_interval: None,
        first_marker: false,
        srtp_key: None,
        sip: false,
    };
    let mut tx = Tx {
        sock,
        dest: Some(dest),
        tos: spec.tos,
        session: 0,
        flow: 0,
        log: crate::log::LogSink::none().handle(),
        log_packets: false,
        progress: Arc::default(),
        packets: 0,
        bytes: 0,
        late: 0,
        errors: 0,
        srtp: None,
    };
    let seq0: u16 = rand::random();
    let ts0: u32 = rand::random();
    tx.srtp = srtp_key.map(|k| (k.session(), crate::srtp::TxIndex::new(seq0)));
    let _ = run_audio(&mut tx, &cfg, seq0, ts0, spec.ssrc, &mut stop).await;
}

async fn run_audio(
    tx: &mut Tx,
    cfg: &ResolvedFlow,
    seq0: u16,
    ts0: u32,
    ssrc: u32,
    stop: &mut watch::Receiver<bool>,
) -> Result<()> {
    let codec = cfg
        .rtp
        .expect("resolve guarantees a codec for plain-RTP audio");
    let mut pacer = Pacer::new(cfg, RTP_HEADER_LEN, MAX_UDP_PACKET)?;
    let mut payload = PayloadGen::new(&cfg.payload);
    let mut buf = vec![0u8; 2048];
    let vad = cfg.vad.is_some();

    pacer.restart();
    while let Some(size) = pacer.wait(stop).await {
        if buf.len() < size + crate::srtp::TAG_LEN {
            buf.resize(size + crate::srtp::TAG_LEN, 0);
        }
        // 8 kHz clock; follows the schedule, so silences show up as timestamp jumps (RFC 3551)
        let ticks = ((pacer.scheduled_offset().as_nanos() + 62_500) / 125_000) as u32;
        write_rtp(
            &mut buf[..RTP_HEADER_LEN],
            codec.payload_type(),
            (vad && pacer.new_talkspurt) || (cfg.first_marker && tx.packets + tx.errors == 0),
            seq0.wrapping_add(tx.packets.wrapping_add(tx.errors) as u16),
            ts0.wrapping_add(ticks),
            ssrc,
        );
        pacer.new_talkspurt = false;
        payload.fill(&mut buf[RTP_HEADER_LEN..size]);
        tx.late = pacer.late;
        tx.send(&mut buf, size).await;
        pacer.advance(size);
    }
    tx.late = pacer.late;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn run_video(
    tx: &mut Tx,
    cfg: &ResolvedFlow,
    v: &VideoSpec,
    mut rng: StdRng,
    seq0: u16,
    ts0: u32,
    ssrc: u32,
    stop: &mut watch::Receiver<bool>,
) -> Result<()> {
    let i_size = v.i_bytes.build()?;
    let p_size = v.p_bytes.build()?;
    let frame_dt = Duration::from_secs_f64(1.0 / v.fps);
    let mut payload = PayloadGen::new(&cfg.payload);
    let mut buf = vec![0u8; RTP_HEADER_LEN + v.payload_bytes + crate::srtp::TAG_LEN];
    let mut start = Instant::now();
    let mut frame = 0u64;
    let mut seq = 0u64; // sequence counter including packets that failed to send

    'frames: loop {
        if *stop.borrow() {
            break;
        }
        let offset = frame_dt.mul_f64(frame as f64);
        if cfg.stop.duration.is_some_and(|d| offset >= d) {
            break;
        }
        let due = start + offset;
        let now = Instant::now();
        if due > now {
            tokio::select! {
                _ = sleep_until(due) => {}
                _ = stop.changed() => break,
            }
        } else {
            let lag = now - due;
            if lag > LATE_THRESHOLD {
                tx.late += 1;
            }
            if lag > RESYNC_THRESHOLD {
                start = now - offset; // avoid an unbounded catch-up burst
            }
        }

        let gen_size = if frame.is_multiple_of(v.gop as u64) {
            &i_size
        } else {
            &p_size
        };
        let frame_bytes = gen_size.sample_clamped(&mut rng, 1, 4 * 1024 * 1024);
        // 90 kHz clock
        let ticks = ((offset.as_nanos() * 9 + 50_000) / 100_000) as u32;
        let ts = ts0.wrapping_add(ticks);

        let mut remaining = frame_bytes;
        while remaining > 0 {
            if cfg.stop.count.is_some_and(|c| tx.packets >= c)
                || cfg.stop.bytes.is_some_and(|b| tx.bytes >= b)
                || *stop.borrow()
            {
                break 'frames;
            }
            let chunk = remaining.min(v.payload_bytes);
            remaining -= chunk;
            write_rtp(
                &mut buf[..RTP_HEADER_LEN],
                v.payload_type,
                remaining == 0,
                seq0.wrapping_add(seq as u16),
                ts,
                ssrc,
            );
            payload.fill(&mut buf[RTP_HEADER_LEN..RTP_HEADER_LEN + chunk]);
            tx.send(&mut buf, RTP_HEADER_LEN + chunk).await;
            seq += 1;
        }
        frame += 1;
    }
    Ok(())
}
