//! Open-ended flows and rolling interval reports.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rtnp_core::client::{IntervalReport, SessionOptions, run_session};
use rtnp_core::flow::FlowSpec;
use rtnp_core::log::LogSink;
use rtnp_core::receiver::{Receiver, ReceiverConfig};
use tokio::net::UdpSocket;
use tokio::sync::watch;

const LO: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

fn recv_cfg() -> ReceiverConfig {
    ReceiverConfig {
        bind: LO,
        udp_port: Some(0),
        control_port: Some(0),
        ..Default::default()
    }
}

/// Run `spec` as an open-ended session for `run_for`, collecting interval reports.
async fn run_forever(
    spec: FlowSpec,
    ctl: Option<String>,
    run_for: Duration,
) -> (rtnp_core::client::SessionResult, Vec<IntervalReport>) {
    let reports: Arc<Mutex<Vec<IntervalReport>>> = Arc::default();
    let sink = reports.clone();
    let mut opts = SessionOptions::new(LogSink::none().handle());
    opts.control = ctl;
    opts.interval = Some(Duration::from_millis(250));
    opts.grace = Duration::from_millis(150);
    opts.on_interval = Some(Box::new(move |r| sink.lock().unwrap().push(r.clone())));
    let (stop_tx, stop_rx) = watch::channel(false);
    let flows = vec![spec.resolve(0).unwrap()];
    let task = tokio::spawn(run_session(flows, opts, stop_rx));
    tokio::time::sleep(run_for).await;
    stop_tx.send(true).unwrap();
    let res = task.await.unwrap().unwrap();
    let got = reports.lock().unwrap().clone();
    (res, got)
}

#[tokio::test]
async fn forever_flow_reports_every_interval_until_stopped() {
    let log = LogSink::none();
    let rx = Receiver::bind(recv_cfg(), log.handle()).await.unwrap();
    let (udp, ctl) = (rx.udp_addr().unwrap(), rx.control_addr().unwrap());
    let server = tokio::spawn(rx.serve(std::future::pending()));

    let spec = FlowSpec {
        target: udp.to_string(),
        name: Some("probe".into()),
        rate_pps: Some(200.0),
        size: Some("100".parse().unwrap()),
        forever: true,
        ..Default::default()
    };
    let (res, reports) =
        run_forever(spec, Some(ctl.to_string()), Duration::from_millis(1400)).await;

    assert!(reports.len() >= 4, "got {} reports", reports.len());
    let mut window_total = 0;
    for (i, r) in reports.iter().enumerate() {
        assert_eq!(r.index, i as u64 + 1);
        assert!(
            (r.interval_s - 0.25).abs() < 0.1,
            "interval {}",
            r.interval_s
        );
        let f = &r.flows[0];
        assert_eq!(f.name, "probe");
        assert!(f.sent > 30 && f.sent < 70, "sent {}", f.sent);
        let rx = f.rx.as_ref().expect("receiver view");
        assert!(rx.packets > 30, "rx {}", rx.packets);
        assert_eq!(f.lost, Some(0));
        assert_eq!(f.loss_pct, Some(0.0));
        window_total += rx.packets;
    }
    let report = &res.reports[0];
    let total = report.rx.as_ref().unwrap().packets;
    assert_eq!(report.lost_vs_tx, Some(0));
    // windows never double count and only miss the unreported tail after the last tick
    assert!(window_total <= total && total - window_total < 100);
    assert_eq!(report.sent, Some(total));
    server.abort();
}

#[tokio::test]
async fn silent_interval_is_reported_as_loss() {
    // the receiver speaks control, but the data goes to a socket that swallows it
    let log = LogSink::none();
    let rx = Receiver::bind(recv_cfg(), log.handle()).await.unwrap();
    let ctl = rx.control_addr().unwrap();
    let server = tokio::spawn(rx.serve(std::future::pending()));
    let sink = UdpSocket::bind((LO, 0)).await.unwrap();

    let spec = FlowSpec {
        target: sink.local_addr().unwrap().to_string(),
        rate_pps: Some(100.0),
        forever: true,
        ..Default::default()
    };
    let (_res, reports) =
        run_forever(spec, Some(ctl.to_string()), Duration::from_millis(1200)).await;

    assert!(reports.len() >= 3);
    let later = &reports[2].flows[0];
    assert_eq!(later.rx.as_ref().unwrap().packets, 0);
    assert!(later.lost.unwrap() > 10);
    assert_eq!(later.loss_pct, Some(100.0));
    drop(sink);
    server.abort();
}

#[tokio::test]
async fn intervals_work_without_a_receiver_session() {
    let sink = UdpSocket::bind((LO, 0)).await.unwrap();
    let spec = FlowSpec {
        target: sink.local_addr().unwrap().to_string(),
        rate_pps: Some(100.0),
        forever: true,
        ..Default::default()
    };
    let (res, reports) = run_forever(spec, None, Duration::from_millis(800)).await;
    assert!(reports.len() >= 2);
    for r in &reports {
        let f = &r.flows[0];
        assert!(f.sent > 10);
        assert!(f.rx.is_none() && f.lost.is_none());
    }
    assert!(res.reports[0].sent.unwrap() > 50);
}
