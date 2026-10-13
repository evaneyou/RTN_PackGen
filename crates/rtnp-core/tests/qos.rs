//! RTCP round-trip measurement and DSCP/TOS marking in both directions.

use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use rtnp_core::client::{SessionOptions, run_session};
use rtnp_core::flow::{Codec, FlowSpec, Wire};
use rtnp_core::log::LogSink;
use rtnp_core::proto::write_rtp;
use rtnp_core::receiver::{Receiver, ReceiverConfig};
use tokio::net::UdpSocket;
use tokio::sync::watch;
use tokio::time::timeout;

const LO: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

fn recv_cfg() -> ReceiverConfig {
    ReceiverConfig {
        bind: LO,
        udp_port: Some(0),
        control_port: Some(0),
        allow_reverse: true,
        ..Default::default()
    }
}

fn voice(target: String) -> FlowSpec {
    FlowSpec {
        target,
        name: Some("voice".into()),
        wire: Some(Wire::Rtp),
        rtp: Some(Codec::G711a),
        ptime_ms: Some(20.0),
        ..Default::default()
    }
}

#[tokio::test]
async fn rtcp_gives_a_round_trip_without_the_control_channel() {
    let log = LogSink::none();
    let rx = Receiver::bind(recv_cfg(), log.handle()).await.unwrap();
    let udp = rx.udp_addr().unwrap();
    let server = tokio::spawn(rx.serve(std::future::pending()));

    let spec = FlowSpec {
        duration_ms: Some(2500),
        rtcp_interval_ms: Some(200),
        ..voice(udp.to_string())
    };
    let opts = SessionOptions::new(log.handle());
    let (_tx, stop) = watch::channel(false);
    let res = run_session(vec![spec.resolve(0).unwrap()], opts, stop)
        .await
        .unwrap();
    let rtt = res.reports[0].rtt.as_ref().expect("RTCP round trips");
    assert!(rtt.count >= 8, "{} samples", rtt.count);
    assert!(rtt.max_ms < 50.0, "loopback rtt {} ms", rtt.max_ms);
    assert!(rtt.min_ms >= 0.0);
    // RTCP must not be mistaken for loss
    assert_eq!(res.reports[0].lost_vs_tx, None);
    server.abort();
}

#[tokio::test]
async fn rtcp_off_means_no_samples_and_zero_is_valid() {
    let log = LogSink::none();
    let rx = Receiver::bind(recv_cfg(), log.handle()).await.unwrap();
    let udp = rx.udp_addr().unwrap();
    let server = tokio::spawn(rx.serve(std::future::pending()));
    let spec = FlowSpec {
        count: Some(50),
        rtcp_interval_ms: Some(0),
        ..voice(udp.to_string())
    };
    let (_tx, stop) = watch::channel(false);
    let res = run_session(
        vec![spec.resolve(0).unwrap()],
        SessionOptions::new(log.handle()),
        stop,
    )
    .await
    .unwrap();
    assert!(res.reports[0].rtt.is_none());
    for bad in [Some(50), None] {
        let s = FlowSpec {
            rtcp_interval_ms: bad,
            wire: None,
            rtp: None,
            ptime_ms: None,
            target: "127.0.0.1:1".into(),
            count: Some(1),
            ..Default::default()
        };
        // rtcp settings need the rtp wire; the default (None) is fine on the rtnp wire
        assert_eq!(s.resolve(0).is_err(), bad.is_some());
    }
    server.abort();
}

#[tokio::test]
async fn receiver_answers_sr_but_ignores_rtcp_for_rtp_stats() {
    let log = LogSink::none();
    let rx = Receiver::bind(recv_cfg(), log.handle()).await.unwrap();
    let (udp, shared) = (rx.udp_addr().unwrap(), rx.shared());
    let server = tokio::spawn(rx.serve(std::future::pending()));

    let s = UdpSocket::bind((LO, 0)).await.unwrap();
    let (msw, lsw) = rtnp_core::rtcp::ntp_now();
    let info = rtnp_core::rtcp::SenderInfo {
        ntp_msw: msw,
        ntp_lsw: lsw,
        ..Default::default()
    };
    s.send_to(&rtnp_core::rtcp::build_sr(0xabcd, &info, "t"), udp)
        .await
        .unwrap();
    let mut buf = [0u8; 256];
    let n = timeout(Duration::from_secs(1), s.recv(&mut buf))
        .await
        .expect("an answer")
        .unwrap();
    let parsed = rtnp_core::rtcp::parse(&buf[..n]);
    let rtnp_core::rtcp::Rtcp::Rr { blocks, .. } = &parsed[0] else {
        panic!("expected RR, got {parsed:?}");
    };
    assert_eq!(blocks[0].ssrc, 0xabcd);
    assert_eq!(blocks[0].lsr, rtnp_core::rtcp::middle32(msw, lsw));
    assert!(shared.snapshot().is_empty(), "RTCP is not an RTP flow");
    server.abort();
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn dscp_is_observed_both_ways() {
    let log = LogSink::none();
    let rx = Receiver::bind(recv_cfg(), log.handle()).await.unwrap();
    let (udp, ctl) = (rx.udp_addr().unwrap(), rx.control_addr().unwrap());
    let server = tokio::spawn(rx.serve(std::future::pending()));

    let spec = FlowSpec {
        count: Some(100),
        tos: Some(184), // EF
        bidirectional: true,
        ..voice(udp.to_string())
    };
    let mut opts = SessionOptions::new(log.handle());
    opts.control = Some(ctl.to_string());
    opts.grace = Duration::from_millis(200);
    let (_tx, stop) = watch::channel(false);
    let res = run_session(vec![spec.resolve(0).unwrap()], opts, stop)
        .await
        .unwrap();
    let r = &res.reports[0];
    assert_eq!(r.rx.as_ref().unwrap().tos, Some(184), "forward marking");
    assert_eq!(r.reverse.as_ref().unwrap().tos, Some(184), "return marking");
    server.abort();
}

#[test]
fn write_rtp_is_still_version_2() {
    let mut b = [0u8; 12];
    write_rtp(&mut b, 8, false, 1, 2, 3);
    assert_eq!(b[0] >> 6, 2);
}
