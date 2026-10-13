//! Plain-RTP wire mode: what goes on the wire, and what the receiver makes of it.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use rtnp_core::client::{SessionOptions, run_session};
use rtnp_core::dist::Dist;
use rtnp_core::flow::{Codec, FlowSpec, VideoSpec, Wire};
use rtnp_core::log::LogSink;
use rtnp_core::receiver::{Receiver, ReceiverConfig};
use rtnp_core::sender::run_flow;
use tokio::net::UdpSocket;
use tokio::sync::watch;
use tokio::time::timeout;

const LO: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

/// Independent RTP parser (deliberately not the library's).
#[derive(Debug)]
struct Pkt {
    len: usize,
    pt: u8,
    marker: bool,
    seq: u16,
    ts: u32,
    ssrc: u32,
}

fn parse(b: &[u8]) -> Pkt {
    assert!(b.len() >= 12, "too short for RTP");
    assert_eq!(b[0], 0x80, "version 2, no padding/extension/CSRC");
    Pkt {
        len: b.len(),
        pt: b[1] & 0x7f,
        marker: b[1] & 0x80 != 0,
        seq: u16::from_be_bytes([b[2], b[3]]),
        ts: u32::from_be_bytes([b[4], b[5], b[6], b[7]]),
        ssrc: u32::from_be_bytes([b[8], b[9], b[10], b[11]]),
    }
}

/// Run a flow against a raw UDP sink and return everything it sent.
async fn capture(spec: FlowSpec) -> Vec<Pkt> {
    let sink = UdpSocket::bind((LO, 0)).await.unwrap();
    let spec = FlowSpec {
        target: sink.local_addr().unwrap().to_string(),
        ..spec
    };
    let (_tx, stop) = watch::channel(false);
    let log = LogSink::none();
    let flow = spec.resolve(0).unwrap();
    let run = tokio::spawn(run_flow(1, 1, flow, log.handle(), false, stop));
    let mut out = Vec::new();
    let mut buf = vec![0u8; 65_536];
    while let Ok(Ok(n)) = timeout(Duration::from_millis(400), sink.recv(&mut buf)).await {
        out.push(parse(&buf[..n]));
    }
    run.await.unwrap().unwrap();
    out
}

fn recv_cfg() -> ReceiverConfig {
    ReceiverConfig {
        bind: LO,
        udp_port: Some(0),
        control_port: Some(0),
        ..Default::default()
    }
}

#[tokio::test]
async fn voice_is_a_bare_rtp_stream() {
    let pkts = capture(FlowSpec {
        preset: Some("voip-g711".into()),
        wire: Some(Wire::Rtp),
        rtcp_interval_ms: Some(0),
        count: Some(25),
        ..Default::default()
    })
    .await;
    assert_eq!(pkts.len(), 25);
    for (i, p) in pkts.iter().enumerate() {
        assert_eq!(p.len, 172, "12-byte RTP header + 160-byte G.711 frame");
        assert_eq!(p.pt, 0, "PCMU");
        assert_eq!(p.ssrc, pkts[0].ssrc);
        assert_eq!(p.seq, pkts[0].seq.wrapping_add(i as u16));
        assert_eq!(
            p.ts,
            pkts[0].ts.wrapping_add(160 * i as u32),
            "20 ms at 8 kHz"
        );
        assert!(!p.marker, "no talkspurts without VAD");
    }
}

#[tokio::test]
async fn first_marker_is_optional_and_marks_only_the_first_packet() {
    let spec = |first_marker| FlowSpec {
        preset: Some("voip-g711a".into()),
        ptime_ms: Some(30.0),
        wire: Some(Wire::Rtp),
        rtcp_interval_ms: Some(0),
        first_marker,
        count: Some(10),
        ..Default::default()
    };
    let on = capture(spec(true)).await;
    assert_eq!(on.len(), 10);
    assert_eq!(on.iter().filter(|p| p.marker).count(), 1);
    assert!(on[0].marker);
    assert!(on.iter().all(|p| p.len == 252 && p.pt == 8));
    let off = capture(spec(false)).await;
    assert!(off.iter().all(|p| !p.marker));
}

#[tokio::test]
async fn vad_sets_marker_on_talkspurt_start_and_skips_timestamps() {
    let pkts = capture(FlowSpec {
        rtp: Some(Codec::G711),
        wire: Some(Wire::Rtp),
        rtcp_interval_ms: Some(0),
        vad: true,
        vad_talk_ms: Some(Dist::Constant { value: 100.0 }),
        vad_silence_ms: Some(Dist::Constant { value: 200.0 }),
        duration_ms: Some(1000),
        ..Default::default()
    })
    .await;
    assert!(pkts[0].marker);
    let markers = pkts.iter().filter(|p| p.marker).count();
    assert!(markers >= 3, "markers={markers}");
    // a silence shows up as a timestamp jump bigger than one packet interval, never a seq gap
    let mut jumps = 0;
    for w in pkts.windows(2) {
        assert_eq!(w[1].seq, w[0].seq.wrapping_add(1));
        if w[1].ts.wrapping_sub(w[0].ts) > 160 {
            assert!(w[1].marker, "silence must end with a marker");
            jumps += 1;
        }
    }
    assert!(jumps >= 2, "jumps={jumps}");
}

#[tokio::test]
async fn video_frames_share_a_timestamp_and_mark_the_last_packet() {
    let video = VideoSpec {
        fps: 25.0,
        gop: 5,
        i_bytes: Dist::Constant { value: 5000.0 },
        p_bytes: Dist::Constant { value: 1000.0 },
        ..VideoSpec::default()
    };
    let pkts = capture(FlowSpec {
        video: Some(video),
        rtcp_interval_ms: Some(0),
        duration_ms: Some(600), // 15 frames
        ..Default::default()
    })
    .await;

    for (i, p) in pkts.iter().enumerate() {
        assert_eq!(p.pt, 96);
        assert_eq!(p.seq, pkts[0].seq.wrapping_add(i as u16));
        assert!(p.len <= 12 + 1200);
    }
    // group by timestamp
    let mut frames: Vec<Vec<&Pkt>> = Vec::new();
    for p in &pkts {
        match frames.last_mut() {
            Some(f) if f[0].ts == p.ts => f.push(p),
            _ => frames.push(vec![p]),
        }
    }
    assert_eq!(frames.len(), 15);
    for (i, f) in frames.iter().enumerate() {
        let payload: usize = f.iter().map(|p| p.len - 12).sum();
        assert_eq!(payload, if i % 5 == 0 { 5000 } else { 1000 }, "frame {i}");
        assert!(f.last().unwrap().marker);
        assert!(f[..f.len() - 1].iter().all(|p| !p.marker));
        if i > 0 {
            assert_eq!(
                f[0].ts.wrapping_sub(frames[i - 1][0].ts),
                3600,
                "90 kHz / 25 fps"
            );
        }
    }
}

#[tokio::test]
async fn receiver_measures_announced_rtp_with_rfc3550_jitter() {
    let log = LogSink::none();
    let rx = Receiver::bind(recv_cfg(), log.handle()).await.unwrap();
    let (udp, ctl) = (rx.udp_addr().unwrap(), rx.control_addr().unwrap());
    let server = tokio::spawn(rx.serve(std::future::pending()));

    let spec = FlowSpec {
        target: udp.to_string(),
        name: Some("call".into()),
        preset: Some("voip-g711".into()),
        wire: Some(Wire::Rtp),
        rtcp_interval_ms: Some(0),
        count: Some(100),
        ..Default::default()
    };
    let mut opts = SessionOptions::new(log.handle());
    opts.control = Some(ctl.to_string());
    opts.grace = Duration::from_millis(200);
    let (_tx, stop) = watch::channel(false);
    let res = run_session(vec![spec.resolve(0).unwrap()], opts, stop)
        .await
        .unwrap();
    let r = &res.reports[0];
    let rx =
        r.rx.as_ref()
            .expect("receiver saw the stream under its flow id");
    assert_eq!(rx.packets, 100);
    assert_eq!(rx.lost, 0);
    assert_eq!(rx.bytes, 100 * 172);
    assert!(rx.delay_relative);
    assert!(rx.jitter_rfc3550_ms < 2.0, "{}", rx.jitter_rfc3550_ms);
    assert_eq!(r.lost_vs_tx, Some(0));
    server.abort();
}

#[tokio::test]
async fn loss_is_seen_through_sequence_gaps() {
    let log = LogSink::none();
    let rx = Receiver::bind(recv_cfg(), log.handle()).await.unwrap();
    let (udp, ctl) = (rx.udp_addr().unwrap(), rx.control_addr().unwrap());
    let server = tokio::spawn(rx.serve(std::future::pending()));

    // a lossy middlebox: forwards everything except every 10th packet
    let proxy = UdpSocket::bind((LO, 0)).await.unwrap();
    let proxy_addr: SocketAddr = proxy.local_addr().unwrap();
    let _fwd = tokio::spawn(async move {
        let mut buf = vec![0u8; 2048];
        let mut n = 0u64;
        loop {
            let Ok(len) = proxy.recv(&mut buf).await else {
                continue;
            };
            n += 1;
            if n % 10 != 5 {
                let _ = proxy.send_to(&buf[..len], udp).await;
            }
        }
    });

    let spec = FlowSpec {
        target: proxy_addr.to_string(),
        preset: Some("voip-g711".into()),
        wire: Some(Wire::Rtp),
        rtcp_interval_ms: Some(0),
        count: Some(100),
        ..Default::default()
    };
    let mut opts = SessionOptions::new(log.handle());
    opts.control = Some(ctl.to_string());
    opts.grace = Duration::from_millis(200);
    let (_tx, stop) = watch::channel(false);
    let res = run_session(vec![spec.resolve(0).unwrap()], opts, stop)
        .await
        .unwrap();
    let rx = res.reports[0].rx.as_ref().unwrap();
    assert_eq!(rx.packets, 90);
    assert_eq!(rx.lost, 10);
    assert!((rx.loss_pct - 10.0).abs() < 0.01);
    server.abort();
}

#[tokio::test]
async fn foreign_rtp_is_tracked_by_ssrc_with_wraparound_and_reordering() {
    let log = LogSink::none();
    let rx = Receiver::bind(recv_cfg(), log.handle()).await.unwrap();
    let udp = rx.udp_addr().unwrap();
    let shared = rx.shared();
    let server = tokio::spawn(rx.serve(std::future::pending()));

    let src = UdpSocket::bind((LO, 0)).await.unwrap();
    let ssrc = 0xCAFE_F00D_u32;
    let send = |seq: u16, ts: u32| {
        let mut b = vec![0u8; 12 + 20];
        rtnp_core::proto::write_rtp(&mut b, 18, false, seq, ts, ssrc);
        let src = &src;
        async move {
            src.send_to(&b, udp).await.unwrap();
            tokio::time::sleep(Duration::from_millis(3)).await;
        }
    };
    // seq 65530.. wraps through 0; one packet swapped; seq 65535 -> ts wraps as well
    let start_ts = u32::MAX - 400;
    let order = [0u16, 1, 2, 3, 5, 4, 6, 7, 8, 9, 10, 11];
    for i in order {
        send(
            65530u16.wrapping_add(i),
            start_ts.wrapping_add(i as u32 * 160),
        )
        .await;
    }
    tokio::time::sleep(Duration::from_millis(100)).await;

    let snap = shared.snapshot();
    assert_eq!(snap.len(), 1);
    let ((session, flow), s) = &snap[0];
    assert_eq!((*session, *flow), (0, ssrc));
    assert_eq!(s.packets, 12);
    assert_eq!(s.lost, 0);
    assert_eq!(s.reordered, 1);
    assert!(s.delay_relative);
    server.abort();
}
