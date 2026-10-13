//! Integration tests for payloads, RTP/VAD, round-trip metering, auth, remote launch,
//! the log server, metrics and SCTP.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use rtnp_core::client::{SessionOptions, connect_control, remote_launch, run_session};
use rtnp_core::dist::Dist;
use rtnp_core::flow::{Codec, FlowSpec, Meter, Payload, Proto};
use rtnp_core::log::{LogRecord, LogSink, read_records};
use rtnp_core::logd::{LogdConfig, serve as logd_serve};
use rtnp_core::proto::{FLAG_ECHO_REPLY, HEADER_LEN, Header, RTP_HEADER_LEN};
use rtnp_core::receiver::{Receiver, ReceiverConfig};
use rtnp_core::sender::run_flow;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::watch;

const LO: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

fn base() -> ReceiverConfig {
    ReceiverConfig {
        bind: LO,
        udp_port: Some(0),
        tcp_port: Some(0),
        ..Default::default()
    }
}

fn no_stop() -> (watch::Sender<bool>, watch::Receiver<bool>) {
    watch::channel(false)
}

#[tokio::test]
async fn round_trip_metering_over_udp_and_tcp() {
    let log = LogSink::none();
    let rx = Receiver::bind(base(), log.handle()).await.unwrap();
    let (udp, tcp) = (rx.udp_addr().unwrap(), rx.tcp_addr().unwrap());
    let server = tokio::spawn(rx.serve(std::future::pending()));

    for (proto, addr) in [(Proto::Udp, udp), (Proto::Tcp, tcp)] {
        let spec = FlowSpec {
            target: addr.to_string(),
            proto: Some(proto),
            meter: Some(Meter::Rtt),
            rate_pps: Some(500.0),
            count: Some(50),
            size: Some(Dist::Constant { value: 300.0 }),
            ..Default::default()
        };
        let (_tx, stop) = no_stop();
        let out = run_flow(1, 1, spec.resolve(0).unwrap(), log.handle(), false, stop)
            .await
            .unwrap();
        assert_eq!(out.sent, 50, "{proto:?}");
        assert_eq!(
            out.rtts_ms.len(),
            50,
            "{proto:?}: every probe should be answered"
        );
        assert!(
            out.rtts_ms.iter().all(|r| *r > 0.0 && *r < 100.0),
            "{proto:?}"
        );
    }
    server.abort();
}

#[tokio::test]
async fn rtp_header_and_payload_pattern_on_the_wire() {
    let sink = UdpSocket::bind((LO, 0)).await.unwrap();
    let addr = sink.local_addr().unwrap();
    let spec = FlowSpec {
        target: addr.to_string(),
        preset: Some("voip-g729".into()),
        payload: Some("pattern:abcd".parse::<Payload>().unwrap()),
        count: Some(5),
        rate_pps: Some(1000.0),
        ..Default::default()
    };
    let (_tx, stop) = no_stop();
    let log = LogSink::none();
    let send = tokio::spawn(run_flow(
        7,
        3,
        spec.resolve(0).unwrap(),
        log.handle(),
        false,
        stop,
    ));

    let mut buf = vec![0u8; 2048];
    let mut markers = Vec::new();
    for i in 0..5 {
        let n = tokio::time::timeout(Duration::from_secs(2), sink.recv(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(n, 64, "voip-g729 packet size");
        let h = Header::decode(&buf[..n]).unwrap();
        assert_eq!((h.session, h.flow, h.seq), (7, 3, i));
        let rtp = &buf[HEADER_LEN..HEADER_LEN + RTP_HEADER_LEN];
        assert_eq!(rtp[0], 0x80, "RTP v2");
        assert_eq!(rtp[1] & 0x7f, Codec::G729.payload_type());
        assert_eq!(u16::from_be_bytes([rtp[2], rtp[3]]), i as u16);
        markers.push(rtp[1] & 0x80 != 0);
        let body = &buf[HEADER_LEN + RTP_HEADER_LEN..n];
        assert!(body.chunks(2).all(|c| c == [0xab, 0xcd]), "pattern payload");
    }
    assert_eq!(
        markers,
        vec![true, false, false, false, false],
        "marker only on talkspurt start"
    );
    send.await.unwrap().unwrap();
}

#[tokio::test]
async fn vad_produces_silences() {
    let sink = UdpSocket::bind((LO, 0)).await.unwrap();
    let addr = sink.local_addr().unwrap();
    let spec = FlowSpec {
        target: addr.to_string(),
        rate_pps: Some(100.0),
        duration_ms: Some(1500),
        vad: true,
        vad_talk_ms: Some(Dist::Constant { value: 100.0 }),
        vad_silence_ms: Some(Dist::Constant { value: 300.0 }),
        rtp: Some(Codec::G711),
        seed: Some(5),
        ..Default::default()
    };
    let (_tx, stop) = no_stop();
    let log = LogSink::none();
    let send = tokio::spawn(run_flow(
        1,
        1,
        spec.resolve(0).unwrap(),
        log.handle(),
        false,
        stop,
    ));

    let mut buf = vec![0u8; 2048];
    let mut times = Vec::new();
    let mut markers = 0;
    while let Ok(Ok(n)) =
        tokio::time::timeout(Duration::from_millis(600), sink.recv(&mut buf)).await
    {
        let h = Header::decode(&buf[..n]).unwrap();
        times.push(h.tx_ns);
        if buf[HEADER_LEN + 1] & 0x80 != 0 {
            markers += 1;
        }
    }
    send.await.unwrap().unwrap();
    // 1.5 s without VAD would be ~150 packets; with 100 ms talk / 300 ms silence it is ~40
    assert!(
        times.len() > 15 && times.len() < 80,
        "got {} packets",
        times.len()
    );
    let max_gap = times.windows(2).map(|w| w[1] - w[0]).max().unwrap();
    assert!(
        max_gap > 250_000_000,
        "expected a silence of ~300 ms, max gap {} ms",
        max_gap / 1_000_000
    );
    assert!(markers >= 3, "expected several talkspurts, got {markers}");
}

fn keyed(allow_launch: bool) -> ReceiverConfig {
    ReceiverConfig {
        control_port: Some(0),
        auth_key: Some(b"s3cret".to_vec()),
        allow_launch,
        ..base()
    }
}

fn flows(target: SocketAddr, count: u64) -> Vec<FlowSpec> {
    vec![FlowSpec {
        target: target.to_string(),
        name: Some("f".into()),
        rate_pps: Some(500.0),
        count: Some(count),
        ..Default::default()
    }]
}

#[tokio::test]
async fn control_channel_authentication() {
    let log = LogSink::none();
    let rx = Receiver::bind(keyed(false), log.handle()).await.unwrap();
    let (udp, ctl) = (rx.udp_addr().unwrap(), rx.control_addr().unwrap());
    let server = tokio::spawn(rx.serve(std::future::pending()));

    let run = |key: Option<&[u8]>| {
        let mut opts = SessionOptions::new(LogSink::none().handle());
        opts.control = Some(ctl.to_string());
        opts.key = key.map(|k| k.to_vec());
        opts.grace = Duration::from_millis(150);
        let resolved: Vec<_> = flows(udp, 40)
            .iter()
            .enumerate()
            .map(|(i, f)| f.resolve(i).unwrap())
            .collect();
        async move {
            let (_tx, stop) = no_stop();
            run_session(resolved, opts, stop).await
        }
    };

    let ok = run(Some(b"s3cret")).await.unwrap();
    assert_eq!(ok.reports[0].rx.as_ref().unwrap().packets, 40);

    let wrong = run(Some(b"nope")).await;
    assert!(wrong.is_err(), "wrong key must be rejected");

    let none = run(None).await.unwrap_err().to_string();
    assert!(
        none.contains("--key") || none.contains("require"),
        "unhelpful error: {none}"
    );
    server.abort();
}

#[tokio::test]
async fn remote_launch_runs_flows_on_the_agent_and_is_guarded() {
    let log = LogSink::none();
    // far end: plain receiver with the same key (the agent authenticates to it)
    let far = Receiver::bind(
        ReceiverConfig {
            allow_launch: false,
            ..keyed(false)
        },
        log.handle(),
    )
    .await
    .unwrap();
    let (far_udp, far_ctl) = (far.udp_addr().unwrap(), far.control_addr().unwrap());
    let far_task = tokio::spawn(far.serve(std::future::pending()));

    let agent = Receiver::bind(keyed(true), log.handle()).await.unwrap();
    let agent_ctl = agent.control_addr().unwrap();
    let agent_task = tokio::spawn(agent.serve(std::future::pending()));

    let (_tx, stop) = no_stop();
    let res = remote_launch(
        &agent_ctl.to_string(),
        Some(b"s3cret"),
        flows(far_udp, 60),
        Some(far_ctl.to_string()),
        stop,
    )
    .await
    .unwrap();
    assert!(res.errors.is_empty(), "{:?}", res.errors);
    assert_eq!(res.reports[0].sent, Some(60));
    assert_eq!(res.reports[0].rx.as_ref().unwrap().packets, 60);

    // file payloads from a remote peer are refused
    let mut evil = flows(far_udp, 5);
    evil[0].payload = Some(Payload::File("/etc/passwd".into()));
    let (_tx, stop) = no_stop();
    let err = remote_launch(&agent_ctl.to_string(), Some(b"s3cret"), evil, None, stop)
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("rejected"), "{err}");

    // an agent without --allow-launch refuses
    let (_tx, stop) = no_stop();
    let err = remote_launch(
        &far_ctl.to_string(),
        Some(b"s3cret"),
        flows(far_udp, 5),
        None,
        stop,
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(err.contains("disabled"), "{err}");

    agent_task.abort();
    far_task.abort();
}

#[tokio::test]
async fn launch_requires_key_and_control_port() {
    let log = LogSink::none();
    let no_key = ReceiverConfig {
        control_port: Some(0),
        allow_launch: true,
        ..base()
    };
    assert!(Receiver::bind(no_key, log.handle()).await.is_err());
    let no_ctl = ReceiverConfig {
        auth_key: Some(b"k".to_vec()),
        allow_launch: true,
        ..base()
    };
    assert!(Receiver::bind(no_ctl, log.handle()).await.is_err());
}

#[tokio::test]
async fn log_server_stores_streams_and_checks_keys() {
    let dir = std::env::temp_dir().join(format!("rtnp-logd-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let listener = TcpListener::bind((LO, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let events = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let ev = events.clone();
    let server = tokio::spawn(logd_serve(
        listener,
        LogdConfig {
            out_dir: dir.clone(),
            key: Some(b"k3y".to_vec()),
            max_bytes_per_conn: 1 << 20,
            on_event: Arc::new(move |m| ev.lock().unwrap().push(m)),
        },
    ));

    // wrong key is refused before anything is written
    assert!(LogSink::to_remote(&addr, "x", Some(b"bad")).await.is_err());

    let sink = LogSink::to_remote(&addr, "../evil/tag", Some(b"k3y"))
        .await
        .unwrap();
    let h = sink.handle();
    for seq in 0..10 {
        h.send(LogRecord::Tx {
            session: 1,
            flow: 1,
            seq,
            size: 100,
            t_ns: seq,
        });
    }
    sink.close().await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    server.abort();

    let files: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    assert_eq!(files.len(), 1, "{files:?}");
    let name = files[0].file_name().unwrap().to_string_lossy().to_string();
    assert!(name.starts_with("___evil_tag-127.0.0.1-"), "{name}");
    assert_eq!(read_records(&files[0]).unwrap().len(), 10);
    std::fs::remove_dir_all(dir).ok();
}

#[tokio::test]
async fn prometheus_endpoint_exposes_flow_counters() {
    let log = LogSink::none();
    let rx = Receiver::bind(
        ReceiverConfig {
            metrics_port: Some(0),
            ..base()
        },
        log.handle(),
    )
    .await
    .unwrap();
    let (udp, metrics) = (rx.udp_addr().unwrap(), rx.metrics_addr().unwrap());
    let server = tokio::spawn(rx.serve(std::future::pending()));

    let (_tx, stop) = no_stop();
    run_flow(
        0xabc,
        2,
        flows(udp, 100)[0].resolve(0).unwrap(),
        log.handle(),
        false,
        stop,
    )
    .await
    .unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;

    let get = |path: &'static str| async move {
        let mut s = TcpStream::connect(metrics).await.unwrap();
        s.write_all(format!("GET {path} HTTP/1.1\r\nHost: x\r\n\r\n").as_bytes())
            .await
            .unwrap();
        let mut out = String::new();
        s.read_to_string(&mut out).await.unwrap();
        out
    };
    let ok = get("/metrics").await;
    assert!(ok.starts_with("HTTP/1.1 200"), "{ok}");
    assert!(
        ok.contains("rtnp_rx_packets_total{session=\"00000abc\",flow=\"2\"} 100"),
        "{ok}"
    );
    assert!(ok.contains("# TYPE rtnp_rx_jitter_seconds gauge"));
    assert!(get("/other").await.starts_with("HTTP/1.1 404"));
    server.abort();
}

#[tokio::test]
async fn echo_replies_are_not_counted_as_forward_traffic() {
    // a stray packet already marked as a reply must not create flow state
    let log = LogSink::none();
    let rx = Receiver::bind(base(), log.handle()).await.unwrap();
    let udp = rx.udp_addr().unwrap();
    let shared = rx.shared();
    let server = tokio::spawn(rx.serve(std::future::pending()));
    let s = UdpSocket::bind((LO, 0)).await.unwrap();
    let mut pkt = vec![0u8; 64];
    Header {
        flags: FLAG_ECHO_REPLY,
        session: 1,
        flow: 1,
        seq: 0,
        tx_ns: 0,
        len: 64,
    }
    .encode(&mut pkt);
    s.send_to(&pkt, udp).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(shared.snapshot().is_empty());
    server.abort();
}

#[tokio::test]
async fn sctp_flow_if_kernel_supports_it() {
    let log = LogSink::none();
    let cfg = ReceiverConfig {
        sctp_port: Some(0),
        tcp_port: None,
        udp_port: None,
        control_port: Some(0),
        ..base()
    };
    let rx = match Receiver::bind(cfg, log.handle()).await {
        Ok(rx) => rx,
        Err(e) => {
            eprintln!("SKIPPED: SCTP not available in this environment: {e}");
            return;
        }
    };
    let addr = rx.sctp_addr().unwrap();
    let shared = rx.shared();
    let server = tokio::spawn(rx.serve(std::future::pending()));
    let spec = FlowSpec {
        target: addr.to_string(),
        proto: Some(Proto::Sctp),
        rate_pps: Some(500.0),
        count: Some(50),
        ..Default::default()
    };
    let (_tx, stop) = no_stop();
    run_flow(1, 1, spec.resolve(0).unwrap(), log.handle(), false, stop)
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(shared.snapshot()[0].1.packets, 50);
    server.abort();
    let _ = connect_control; // keep the import used on all paths
}
