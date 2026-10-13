//! SIP/SDP call setup against the built-in responder, over loopback.

use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use rtnp_core::client::{SessionOptions, run_session};
use rtnp_core::flow::{FlowSpec, Wire};
use rtnp_core::log::LogSink;
use rtnp_core::receiver::{Receiver, ReceiverConfig};
use rtnp_core::srtp::MasterKey;
use tokio::sync::watch;

const LO: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

fn cfg(key: Option<MasterKey>) -> ReceiverConfig {
    ReceiverConfig {
        bind: LO,
        udp_port: Some(0),
        control_port: Some(0),
        sip_port: Some(0),
        srtp_key: key,
        ..Default::default()
    }
}

fn call(sip: std::net::SocketAddr, srtp: bool, key: Option<MasterKey>) -> FlowSpec {
    FlowSpec {
        // the target is the SIP port: media goes wherever the answer says
        target: sip.to_string(),
        preset: Some("voip-g711".into()),
        wire: Some(Wire::Rtp),
        rtcp_interval_ms: Some(0),
        count: Some(60),
        sip: true,
        srtp,
        srtp_key: key,
        ..Default::default()
    }
}

async fn run(
    spec: FlowSpec,
    ctl: std::net::SocketAddr,
    log: &LogSink,
) -> rtnp_core::error::Result<rtnp_core::client::SessionResult> {
    let mut opts = SessionOptions::new(log.handle());
    opts.control = Some(ctl.to_string());
    opts.grace = Duration::from_millis(300);
    let (_tx, stop) = watch::channel(false);
    run_session(vec![spec.resolve(0)?], opts, stop).await
}

#[tokio::test]
async fn sip_call_sets_up_media_and_hangs_up() {
    let log = LogSink::none();
    let rx = Receiver::bind(cfg(None), log.handle()).await.unwrap();
    let (sip, ctl) = (rx.sip_addr().unwrap(), rx.control_addr().unwrap());
    assert_ne!(sip.port(), rx.udp_addr().unwrap().port());
    let server = tokio::spawn(rx.serve(std::future::pending()));
    let res = run(call(sip, false, None), ctl, &log).await.unwrap();
    let r = res.reports[0]
        .rx
        .as_ref()
        .expect("media reached the receiver's RTP port");
    assert_eq!(r.packets, 60);
    assert_eq!(r.lost, 0);
    server.abort();
}

#[tokio::test]
async fn sdes_srtp_key_travels_in_the_offer_and_is_forgotten_at_bye() {
    let log = LogSink::none();
    let rx = Receiver::bind(cfg(None), log.handle()).await.unwrap();
    let (sip, ctl) = (rx.sip_addr().unwrap(), rx.control_addr().unwrap());
    let keys = rx.call_keys();
    let server = tokio::spawn(rx.serve(std::future::pending()));
    let res = run(call(sip, true, None), ctl, &log).await.unwrap();
    let r = res.reports[0]
        .rx
        .as_ref()
        .expect("encrypted media was decrypted");
    assert_eq!(r.packets, 60);
    assert_eq!(r.bytes, 60 * 172);
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(keys.is_empty(), "BYE removes the call's key");
    server.abort();
}

#[tokio::test]
async fn a_fixed_receiver_key_must_match_the_offer() {
    let log = LogSink::none();
    let fixed = MasterKey::from_bytes([5; 30]);
    let rx = Receiver::bind(cfg(Some(fixed.clone())), log.handle())
        .await
        .unwrap();
    let (sip, ctl) = (rx.sip_addr().unwrap(), rx.control_addr().unwrap());
    let server = tokio::spawn(rx.serve(std::future::pending()));
    // a random SDES key is refused: the receiver only decrypts with its own key
    let res = run(call(sip, true, None), ctl, &log).await.unwrap();
    assert!(
        res.errors.iter().any(|e| e.contains("488")),
        "{:?}",
        res.errors
    );
    // plain RTP is refused as well
    let res = run(call(sip, false, None), ctl, &log).await.unwrap();
    assert!(
        res.errors.iter().any(|e| e.contains("488")),
        "{:?}",
        res.errors
    );
    // the same key is accepted
    let res = run(call(sip, false, Some(fixed)), ctl, &log).await.unwrap();
    assert_eq!(res.reports[0].rx.as_ref().unwrap().packets, 60);
    server.abort();
}

#[tokio::test]
async fn calling_a_closed_sip_port_fails_fast() {
    let log = LogSink::none();
    let rx = Receiver::bind(cfg(None), log.handle()).await.unwrap();
    let ctl = rx.control_addr().unwrap();
    let dead = {
        let s = std::net::UdpSocket::bind((LO, 0)).unwrap();
        s.local_addr().unwrap()
    };
    let server = tokio::spawn(rx.serve(std::future::pending()));
    let t = std::time::Instant::now();
    let res = run(call(dead, false, None), ctl, &log).await.unwrap();
    assert!(
        res.errors.iter().any(|e| e.contains("SIP")),
        "{:?}",
        res.errors
    );
    assert!(t.elapsed() < Duration::from_secs(10));
    server.abort();
}

#[test]
fn sip_flag_validation() {
    let base = FlowSpec {
        target: "127.0.0.1:5060".into(),
        preset: Some("voip-g711".into()),
        wire: Some(Wire::Rtp),
        ..Default::default()
    };
    assert!(
        FlowSpec {
            sip: true,
            ..base.clone()
        }
        .resolve(0)
        .is_ok()
    );
    assert!(
        FlowSpec {
            sip: true,
            wire: None,
            ..base.clone()
        }
        .resolve(0)
        .is_err(),
        "needs rtp wire"
    );
    assert!(
        FlowSpec {
            srtp: true,
            ..base.clone()
        }
        .resolve(0)
        .is_err(),
        "srtp = true needs sip"
    );
    let both = FlowSpec {
        sip: true,
        srtp: true,
        srtp_key: Some(MasterKey::from_bytes([1; 30])),
        ..base.clone()
    };
    assert!(both.resolve(0).is_err());
    let auto = FlowSpec {
        sip: true,
        srtp: true,
        ..base
    };
    assert!(
        auto.resolve(0).unwrap().srtp_key.is_some(),
        "a key is generated per resolve"
    );
}
