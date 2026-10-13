//! G.711 A-law voice and two-way (bidirectional) calls.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rtnp_core::client::{IntervalReport, SessionOptions, connect_control, run_session};
use rtnp_core::control::{ClientMsg, FlowAnnounce, ReverseSpec, ServerMsg, read_msg, write_msg};
use rtnp_core::flow::{Codec, FlowSpec, Proto, Wire};
use rtnp_core::log::LogSink;
use rtnp_core::proto::{VERSION, write_rtp};
use rtnp_core::receiver::{Receiver, ReceiverConfig};
use rtnp_core::sender::run_flow;
use tokio::net::UdpSocket;
use tokio::sync::watch;
use tokio::time::timeout;

const LO: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

fn recv_cfg(allow_reverse: bool) -> ReceiverConfig {
    ReceiverConfig {
        bind: LO,
        udp_port: Some(0),
        control_port: Some(0),
        allow_reverse,
        ..Default::default()
    }
}

fn call(target: String) -> FlowSpec {
    FlowSpec {
        target,
        name: Some("call".into()),
        wire: Some(Wire::Rtp),
        rtp: Some(Codec::G711a),
        ptime_ms: Some(20.0),
        bidirectional: true,
        ..Default::default()
    }
}

#[tokio::test]
async fn g711a_with_30ms_ptime_is_the_captured_stream() {
    let sink = UdpSocket::bind((LO, 0)).await.unwrap();
    let spec = FlowSpec {
        target: sink.local_addr().unwrap().to_string(),
        wire: Some(Wire::Rtp),
        rtp: Some(Codec::G711a),
        ptime_ms: Some(30.0),
        count: Some(20),
        rtcp_interval_ms: Some(0),
        ..Default::default()
    };
    let (_tx, stop) = watch::channel(false);
    let log = LogSink::none();
    let run = tokio::spawn(run_flow(
        1,
        1,
        spec.resolve(0).unwrap(),
        log.handle(),
        false,
        stop,
    ));
    let mut pkts: Vec<Vec<u8>> = Vec::new();
    let mut buf = vec![0u8; 2048];
    while let Ok(Ok(n)) = timeout(Duration::from_millis(300), sink.recv(&mut buf)).await {
        pkts.push(buf[..n].to_vec());
    }
    run.await.unwrap().unwrap();
    assert_eq!(pkts.len(), 20);
    let ts = |p: &[u8]| u32::from_be_bytes([p[4], p[5], p[6], p[7]]);
    for (i, p) in pkts.iter().enumerate() {
        assert_eq!(p.len(), 252, "12 + 240 bytes");
        assert_eq!(p[1] & 0x7f, 8, "PCMA");
        assert!(p[12..].iter().all(|&b| b == 0xd5), "A-law silence");
        assert_eq!(ts(p), ts(&pkts[0]).wrapping_add(240 * i as u32));
    }
}

#[tokio::test]
async fn two_way_call_reports_both_directions() {
    let log = LogSink::none();
    let rx = Receiver::bind(recv_cfg(true), log.handle()).await.unwrap();
    let (udp, ctl) = (rx.udp_addr().unwrap(), rx.control_addr().unwrap());
    let server = tokio::spawn(rx.serve(std::future::pending()));

    let spec = FlowSpec {
        count: Some(150), // 3 s
        ..call(udp.to_string())
    };
    let mut opts = SessionOptions::new(log.handle());
    opts.control = Some(ctl.to_string());
    opts.grace = Duration::from_millis(200);
    let (_tx, stop) = watch::channel(false);
    let res = run_session(vec![spec.resolve(0).unwrap()], opts, stop)
        .await
        .unwrap();
    let r = &res.reports[0];
    let fwd = r.rx.as_ref().unwrap();
    assert_eq!((fwd.packets, fwd.lost), (150, 0));
    let rev = r
        .reverse
        .as_ref()
        .expect("return stream measured at the sender");
    assert!(rev.packets >= 140, "return packets {}", rev.packets);
    assert_eq!(rev.lost, 0);
    assert_eq!(rev.bytes, rev.packets * 172);
    assert!(rev.delay_relative);
    assert!(rev.jitter_rfc3550_ms < 3.0, "{}", rev.jitter_rfc3550_ms);
    server.abort();
}

#[tokio::test]
async fn return_streams_need_consent_and_the_control_channel() {
    let log = LogSink::none();
    let rx = Receiver::bind(recv_cfg(false), log.handle()).await.unwrap();
    let (udp, ctl) = (rx.udp_addr().unwrap(), rx.control_addr().unwrap());
    let server = tokio::spawn(rx.serve(std::future::pending()));

    let flows = vec![call(udp.to_string()).resolve(0).unwrap()];
    let mut opts = SessionOptions::new(log.handle());
    opts.control = Some(ctl.to_string());
    let (_tx, stop) = watch::channel(false);
    let err = run_session(flows.clone(), opts, stop).await.unwrap_err();
    assert!(err.to_string().contains("--allow-reverse"), "{err}");

    let (_tx, stop) = watch::channel(false);
    let err = run_session(flows, SessionOptions::new(log.handle()), stop)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("control"), "{err}");
    server.abort();
}

#[test]
fn bidirectional_resolve_rules() {
    let ok = call("x:1".into());
    assert!(ok.resolve(0).is_ok());
    let bad = |f: FlowSpec| f.resolve(0).is_err();
    assert!(bad(FlowSpec {
        vad: true,
        ..ok.clone()
    }));
    assert!(bad(FlowSpec {
        wire: Some(Wire::Rtnp),
        ..ok.clone()
    }));
    assert!(bad(FlowSpec {
        rtp: None,
        ptime_ms: None,
        ..ok.clone()
    }));
    assert!(bad(FlowSpec {
        ptime_ms: None,
        idt_ms: Some("exp:20".parse().unwrap()),
        size: Some("172".parse().unwrap()),
        ..ok.clone()
    }));
    assert!(bad(FlowSpec {
        ptime_ms: Some(5.0),
        ..ok.clone()
    }));
    assert!(bad(FlowSpec {
        rtp: Some(Codec::G729),
        ptime_ms: Some(25.0),
        ..ok.clone()
    }));
    assert!(bad(FlowSpec {
        rtp: Some(Codec::G723),
        ptime_ms: Some(30.0),
        ..ok.clone()
    }));
}

fn announce(reverse: Option<ReverseSpec>) -> ClientMsg {
    ClientMsg::Hello {
        version: VERSION,
        session: 7,
        flows: vec![FlowAnnounce {
            flow: 1,
            name: "raw".into(),
            proto: Proto::Udp,
            ssrc: Some(0x1111),
            reverse,
        }],
    }
}

fn spec(idt_ms: f64) -> ReverseSpec {
    ReverseSpec {
        codec: Codec::G711a,
        idt_ms,
        packet_bytes: 172,
        ssrc: 0x2222,
        tos: None,
    }
}

async fn forward_packet(src: &UdpSocket, to: std::net::SocketAddr, seq: u16) {
    let mut b = vec![0u8; 172];
    write_rtp(&mut b, 8, false, seq, seq as u32 * 160, 0x1111);
    src.send_to(&b, to).await.unwrap();
}

/// Count packets from the receiver arriving within `window`.
async fn count_for(src: &UdpSocket, window: Duration) -> Vec<Vec<u8>> {
    let mut got = Vec::new();
    let mut buf = vec![0u8; 2048];
    let end = tokio::time::Instant::now() + window;
    while let Ok(Ok(n)) = tokio::time::timeout_at(end, src.recv(&mut buf)).await {
        got.push(buf[..n].to_vec());
    }
    got
}

#[tokio::test]
async fn return_stream_latches_runs_constantly_and_stops_with_the_session() {
    let log = LogSink::none();
    let rx = Receiver::bind(recv_cfg(true), log.handle()).await.unwrap();
    let (udp, ctl) = (rx.udp_addr().unwrap(), rx.control_addr().unwrap());
    let server = tokio::spawn(rx.serve(std::future::pending()));

    let mut c = connect_control(&ctl.to_string(), None).await.unwrap();
    write_msg(&mut c, &announce(Some(spec(20.0))))
        .await
        .unwrap();
    match read_msg::<_, ServerMsg>(&mut c).await.unwrap() {
        Some(ServerMsg::Ready { reverse, .. }) => assert!(reverse),
        other => panic!("{other:?}"),
    }

    // nothing is sent before the peer shows itself
    let src = UdpSocket::bind((LO, 0)).await.unwrap();
    assert!(count_for(&src, Duration::from_millis(200)).await.is_empty());

    // one forward packet latches the destination; the return stream then runs by itself
    forward_packet(&src, udp, 1).await;
    let got = count_for(&src, Duration::from_millis(1000)).await;
    assert!(
        (40..=55).contains(&got.len()),
        "expected ~50 packets/s, got {}",
        got.len()
    );
    let mut last: Option<(u16, u32)> = None;
    for p in &got {
        assert_eq!((p.len(), p[0], p[1] & 0x7f), (172, 0x80, 8));
        assert_eq!(&p[8..12], &0x2222u32.to_be_bytes());
        assert!(p[12..].iter().all(|&b| b == 0xd5));
        let (seq, ts) = (
            u16::from_be_bytes([p[2], p[3]]),
            u32::from_be_bytes([p[4], p[5], p[6], p[7]]),
        );
        if let Some((s, t)) = last {
            assert_eq!(seq, s.wrapping_add(1));
            assert_eq!(ts.wrapping_sub(t) % 160, 0, "whole 20 ms steps");
        }
        last = Some((seq, ts));
    }

    // ending the session stops it
    write_msg(
        &mut c,
        &ClientMsg::Done {
            session: 7,
            grace_ms: 0,
        },
    )
    .await
    .unwrap();
    let _ = read_msg::<_, ServerMsg>(&mut c).await;
    let _ = count_for(&src, Duration::from_millis(200)).await; // in flight
    assert!(count_for(&src, Duration::from_millis(400)).await.is_empty());
    server.abort();
}

#[tokio::test]
async fn return_stream_stops_when_the_forward_stream_goes_quiet() {
    let log = LogSink::none();
    let rx = Receiver::bind(recv_cfg(true), log.handle()).await.unwrap();
    let (udp, ctl) = (rx.udp_addr().unwrap(), rx.control_addr().unwrap());
    let server = tokio::spawn(rx.serve(std::future::pending()));

    let mut c = connect_control(&ctl.to_string(), None).await.unwrap();
    write_msg(&mut c, &announce(Some(spec(20.0))))
        .await
        .unwrap();
    let _ = read_msg::<_, ServerMsg>(&mut c).await;
    let src = UdpSocket::bind((LO, 0)).await.unwrap();
    forward_packet(&src, udp, 1).await;
    assert!(!count_for(&src, Duration::from_millis(300)).await.is_empty());
    // no more forward packets and no Done: the stream must give up by itself (~5 s idle)
    let _ = count_for(&src, Duration::from_millis(6500)).await;
    assert!(count_for(&src, Duration::from_millis(500)).await.is_empty());
    server.abort();
}

#[tokio::test]
async fn out_of_bounds_return_requests_are_refused() {
    let log = LogSink::none();
    let rx = Receiver::bind(recv_cfg(true), log.handle()).await.unwrap();
    let ctl = rx.control_addr().unwrap();
    let server = tokio::spawn(rx.serve(std::future::pending()));
    for bad in [
        ReverseSpec {
            idt_ms: 1.0,
            ..spec(20.0)
        },
        ReverseSpec {
            packet_bytes: 60_000,
            ..spec(20.0)
        },
    ] {
        let mut c = connect_control(&ctl.to_string(), None).await.unwrap();
        write_msg(&mut c, &announce(Some(bad))).await.unwrap();
        assert!(matches!(
            read_msg::<_, ServerMsg>(&mut c).await.unwrap(),
            Some(ServerMsg::Error { .. })
        ));
    }
    server.abort();
}

#[tokio::test]
async fn interval_reports_cover_the_return_stream() {
    let log = LogSink::none();
    let rx = Receiver::bind(recv_cfg(true), log.handle()).await.unwrap();
    let (udp, ctl) = (rx.udp_addr().unwrap(), rx.control_addr().unwrap());
    let server = tokio::spawn(rx.serve(std::future::pending()));

    let reports: Arc<Mutex<Vec<IntervalReport>>> = Arc::default();
    let sink = reports.clone();
    let mut opts = SessionOptions::new(log.handle());
    opts.control = Some(ctl.to_string());
    opts.interval = Some(Duration::from_millis(300));
    opts.grace = Duration::from_millis(150);
    opts.on_interval = Some(Box::new(move |r| sink.lock().unwrap().push(r.clone())));
    let spec = FlowSpec {
        forever: true,
        ..call(udp.to_string())
    };
    let (stop_tx, stop_rx) = watch::channel(false);
    let task = tokio::spawn(run_session(vec![spec.resolve(0).unwrap()], opts, stop_rx));
    tokio::time::sleep(Duration::from_millis(1500)).await;
    stop_tx.send(true).unwrap();
    task.await.unwrap().unwrap();

    let got = reports.lock().unwrap().clone();
    assert!(got.len() >= 4, "{} reports", got.len());
    for r in &got[1..] {
        let f = &r.flows[0];
        let rev = f.reverse.as_ref().expect("reverse window");
        assert!(
            (10..=20).contains(&rev.packets),
            "rev packets {}",
            rev.packets
        );
        assert_eq!(f.reverse_lost, Some(0));
        assert_eq!(f.lost, Some(0));
    }
    server.abort();
}
