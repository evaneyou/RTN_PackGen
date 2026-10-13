use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use rtnp_core::control::{ClientMsg, FlowAnnounce, ServerMsg, read_msg, write_msg};
use rtnp_core::flow::{FlowSpec, Proto};
use rtnp_core::log::LogSink;
use rtnp_core::proto::VERSION;
use rtnp_core::receiver::{Receiver, ReceiverConfig};
use rtnp_core::sender::run_flow;
use tokio::net::TcpStream;
use tokio::sync::watch;

fn cfg(control: bool) -> ReceiverConfig {
    ReceiverConfig {
        bind: IpAddr::V4(Ipv4Addr::LOCALHOST),
        udp_port: Some(0),
        tcp_port: Some(0),
        control_port: control.then_some(0),
        ..Default::default()
    }
}

#[tokio::test]
async fn udp_flow_is_measured_end_to_end() {
    let log = LogSink::none();
    let rx = Receiver::bind(cfg(false), log.handle()).await.unwrap();
    let addr = rx.udp_addr().unwrap();
    let shared = rx.shared();
    let server = tokio::spawn(rx.serve(std::future::pending()));

    let spec = FlowSpec {
        target: addr.to_string(),
        rate_pps: Some(2000.0),
        count: Some(200),
        size: Some("normal:300,80".parse().unwrap()),
        seed: Some(42),
        ..Default::default()
    };
    let (_stop_tx, stop_rx) = watch::channel(false);
    let out = run_flow(1, 1, spec.resolve(0).unwrap(), log.handle(), false, stop_rx)
        .await
        .unwrap();
    assert_eq!(out.sent, 200);

    tokio::time::sleep(Duration::from_millis(200)).await;
    let snap = shared.snapshot();
    assert_eq!(snap.len(), 1);
    let s = &snap[0].1;
    assert_eq!(
        s.packets, 200,
        "loopback UDP should not drop 200 packets at 2 kpps"
    );
    assert_eq!(s.lost, 0);
    assert!(
        s.delay_min_ms >= 0.0 && s.delay_avg_ms < 50.0,
        "delay {}",
        s.delay_avg_ms
    );
    server.abort();
}

#[tokio::test]
async fn tcp_flow_with_control_report() {
    let log = LogSink::none();
    let rx = Receiver::bind(cfg(true), log.handle()).await.unwrap();
    let tcp_addr = rx.tcp_addr().unwrap();
    let ctl_addr = rx.control_addr().unwrap();
    let server = tokio::spawn(rx.serve(std::future::pending()));

    let mut ctl = TcpStream::connect(ctl_addr).await.unwrap();
    write_msg(
        &mut ctl,
        &ClientMsg::Hello {
            version: VERSION,
            session: 99,
            flows: vec![FlowAnnounce {
                flow: 1,
                name: "bulk".into(),
                proto: Proto::Tcp,
                ssrc: None,
                reverse: None,
            }],
        },
    )
    .await
    .unwrap();
    assert!(matches!(
        read_msg::<_, ServerMsg>(&mut ctl).await.unwrap(),
        Some(ServerMsg::Ready { .. })
    ));

    let spec = FlowSpec {
        target: tcp_addr.to_string(),
        proto: Some(Proto::Tcp),
        rate_pps: Some(1000.0),
        count: Some(100),
        size: Some("const:1200".parse().unwrap()),
        ..Default::default()
    };
    let (_stop_tx, stop_rx) = watch::channel(false);
    let out = run_flow(
        99,
        1,
        spec.resolve(0).unwrap(),
        log.handle(),
        false,
        stop_rx,
    )
    .await
    .unwrap();
    assert_eq!(out.sent, 100);
    assert_eq!(out.bytes, 100 * 1200);

    write_msg(
        &mut ctl,
        &ClientMsg::Done {
            session: 99,
            grace_ms: 200,
        },
    )
    .await
    .unwrap();
    match read_msg::<_, ServerMsg>(&mut ctl).await.unwrap() {
        Some(ServerMsg::Report { session, flows }) => {
            assert_eq!(session, 99);
            assert_eq!(flows.len(), 1);
            assert_eq!(flows[0].name, "bulk");
            assert_eq!(flows[0].summary.packets, 100);
            assert_eq!(flows[0].summary.bytes, 100 * 1200);
        }
        other => panic!("unexpected reply: {other:?}"),
    }
    server.abort();
}

#[tokio::test]
async fn jsonl_log_roundtrips_into_report() {
    let dir = std::env::temp_dir().join(format!("rtnp-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let rx_log = dir.join("rx.jsonl");
    let tx_log = dir.join("tx.jsonl");

    let rx_sink = LogSink::to_file(&rx_log).await.unwrap();
    let tx_sink = LogSink::to_file(&tx_log).await.unwrap();
    let rx = Receiver::bind(cfg(false), rx_sink.handle()).await.unwrap();
    let addr = rx.udp_addr().unwrap();
    let server = tokio::spawn(rx.serve(std::future::pending()));

    let spec = FlowSpec {
        target: addr.to_string(),
        name: Some("t".into()),
        rate_pps: Some(1000.0),
        count: Some(100),
        ..Default::default()
    };
    let (_stop_tx, stop_rx) = watch::channel(false);
    run_flow(
        5,
        1,
        spec.resolve(0).unwrap(),
        tx_sink.handle(),
        true,
        stop_rx,
    )
    .await
    .unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    server.abort();
    let _ = server.await;
    rx_sink.close().await.unwrap();
    tx_sink.close().await.unwrap();

    let mut recs = rtnp_core::log::read_records(&tx_log).unwrap();
    recs.extend(rtnp_core::log::read_records(&rx_log).unwrap());
    let rep = rtnp_core::report::aggregate(&recs, None);
    assert_eq!(rep.len(), 1);
    assert_eq!(rep[0].name, "t");
    assert_eq!(rep[0].sent, Some(100));
    assert_eq!(rep[0].rx.as_ref().unwrap().packets, 100);
    assert_eq!(rep[0].lost_vs_tx, Some(0));
    std::fs::remove_dir_all(dir).ok();
}
