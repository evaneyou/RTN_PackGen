//! SRTP end to end: what goes on the wire and how the receiver treats it.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::Ordering;
use std::time::Duration;

use rtnp_core::client::{SessionOptions, run_session};
use rtnp_core::flow::{FlowSpec, Wire};
use rtnp_core::log::LogSink;
use rtnp_core::receiver::{Receiver, ReceiverConfig};
use rtnp_core::sender::run_flow;
use rtnp_core::srtp::{MasterKey, SrtpReceiver, TAG_LEN};
use tokio::net::UdpSocket;
use tokio::sync::watch;
use tokio::time::timeout;

const LO: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

fn key(n: u8) -> MasterKey {
    MasterKey::from_bytes([n; 30])
}

fn call(count: u64, k: Option<MasterKey>) -> FlowSpec {
    FlowSpec {
        preset: Some("voip-g711".into()),
        wire: Some(Wire::Rtp),
        rtcp_interval_ms: Some(0),
        count: Some(count),
        srtp_key: k,
        ..Default::default()
    }
}

#[tokio::test]
async fn packets_are_encrypted_tagged_and_decryptable() {
    let sink = UdpSocket::bind((LO, 0)).await.unwrap();
    let spec = FlowSpec {
        target: sink.local_addr().unwrap().to_string(),
        ..call(30, Some(key(7)))
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
    let mut rx = SrtpReceiver::new(&key(7));
    let mut n = 0;
    let mut buf = vec![0u8; 2048];
    while let Ok(Ok(len)) = timeout(Duration::from_millis(400), sink.recv(&mut buf)).await {
        assert_eq!(len, 172 + TAG_LEN, "RTP packet plus 10-byte tag");
        let wire_payload = buf[12..172].to_vec();
        assert!(
            wire_payload.windows(2).any(|w| w[0] != w[1]),
            "ciphertext must not be a constant fill"
        );
        let plain = rx.unprotect(&mut buf[..len]).expect("authentic packet");
        assert_eq!(plain, 172);
        assert!(
            buf[12..172].iter().all(|b| *b == buf[12]),
            "decrypts back to the constant fill the flow generated"
        );
        n += 1;
    }
    run.await.unwrap().unwrap();
    assert_eq!(n, 30);
}

#[tokio::test]
async fn receiver_with_the_same_key_measures_the_call() {
    let log = LogSink::none();
    let cfg = ReceiverConfig {
        bind: LO,
        udp_port: Some(0),
        control_port: Some(0),
        srtp_key: Some(key(7)),
        ..Default::default()
    };
    let rx = Receiver::bind(cfg, log.handle()).await.unwrap();
    let (udp, ctl) = (rx.udp_addr().unwrap(), rx.control_addr().unwrap());
    let server = tokio::spawn(rx.serve(std::future::pending()));
    let spec = FlowSpec {
        target: udp.to_string(),
        ..call(100, Some(key(7)))
    };
    let mut opts = SessionOptions::new(log.handle());
    opts.control = Some(ctl.to_string());
    opts.grace = Duration::from_millis(200);
    let (_tx, stop) = watch::channel(false);
    let res = run_session(vec![spec.resolve(0).unwrap()], opts, stop)
        .await
        .unwrap();
    let rx = res.reports[0].rx.as_ref().expect("receiver saw the stream");
    assert_eq!(rx.packets, 100);
    assert_eq!(rx.lost, 0);
    assert_eq!(
        rx.bytes,
        100 * 172,
        "counted after decryption, without the tag"
    );
    server.abort();
}

#[tokio::test]
async fn wrong_key_and_plain_rtp_are_dropped_as_malformed() {
    let log = LogSink::none();
    let cfg = ReceiverConfig {
        bind: LO,
        udp_port: Some(0),
        srtp_key: Some(key(7)),
        ..Default::default()
    };
    let rx = Receiver::bind(cfg, log.handle()).await.unwrap();
    let udp = rx.udp_addr().unwrap();
    let shared = rx.shared();
    let server = tokio::spawn(rx.serve(std::future::pending()));
    for k in [Some(key(8)), None] {
        let spec = FlowSpec {
            target: udp.to_string(),
            ..call(10, k)
        };
        let (_tx, stop) = watch::channel(false);
        run_flow(1, 1, spec.resolve(0).unwrap(), log.handle(), false, stop)
            .await
            .unwrap();
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(shared.snapshot().is_empty(), "nothing may be accepted");
    assert_eq!(shared.malformed.load(Ordering::Relaxed), 20);
    server.abort();
}

#[test]
fn srtp_needs_plain_rtp_and_allows_two_way_calls() {
    let base = FlowSpec {
        target: "127.0.0.1:1".into(),
        preset: Some("voip-g711".into()),
        srtp_key: Some(key(1)),
        ..Default::default()
    };
    assert!(base.resolve(0).is_err(), "default wire is rtnp");
    let ok = FlowSpec {
        wire: Some(Wire::Rtp),
        ..base.clone()
    };
    assert!(ok.resolve(0).is_ok());
    let bidir = FlowSpec {
        wire: Some(Wire::Rtp),
        bidirectional: true,
        ptime_ms: Some(20.0),
        ..base
    };
    assert!(bidir.resolve(0).is_ok(), "two-way SRTP calls are supported");
}

#[tokio::test]
async fn tone_payload_is_real_decodable_g711_audio_and_works_with_srtp() {
    use rtnp_core::audio::{alaw_to_linear, ulaw_to_linear};
    for (codec, srtp) in [("g711", false), ("g711a", true)] {
        let sink = UdpSocket::bind((LO, 0)).await.unwrap();
        let spec = FlowSpec {
            target: sink.local_addr().unwrap().to_string(),
            preset: Some(format!("voip-{codec}")),
            payload: Some("tone:1000".parse().unwrap()),
            srtp_key: srtp.then(|| key(3)),
            ..call(10, None)
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
        let mut rx = SrtpReceiver::new(&key(3));
        let mut pcm = Vec::new();
        let mut buf = vec![0u8; 2048];
        while let Ok(Ok(mut n)) = timeout(Duration::from_millis(400), sink.recv(&mut buf)).await {
            if srtp {
                n = rx.unprotect(&mut buf[..n]).unwrap();
            }
            pcm.extend(buf[12..n].iter().map(|b| {
                if codec == "g711" {
                    ulaw_to_linear(*b)
                } else {
                    alaw_to_linear(*b)
                }
            }));
        }
        run.await.unwrap().unwrap();
        assert_eq!(pcm.len(), 1600, "10 packets x 160 samples");
        // 1 kHz at 8 kHz sampling repeats every 8 samples; packets are contiguous slices of it
        for i in 8..pcm.len() {
            assert!(
                (pcm[i] as i32 - pcm[i - 8] as i32).abs() < 700,
                "{codec} sample {i}"
            );
        }
        assert!(pcm.iter().any(|s| s.unsigned_abs() > 8000), "audible level");
    }
}

#[test]
fn audio_payloads_need_plain_rtp_g711() {
    let tone = |wire, preset: &str| FlowSpec {
        target: "127.0.0.1:1".into(),
        preset: Some(preset.into()),
        wire,
        payload: Some("tone".parse().unwrap()),
        ..Default::default()
    };
    assert!(tone(Some(Wire::Rtp), "voip-g711").resolve(0).is_ok());
    assert!(tone(None, "voip-g711").resolve(0).is_err(), "rtnp wire");
    assert!(
        tone(Some(Wire::Rtp), "voip-g729").resolve(0).is_err(),
        "not G.711"
    );
    assert!("tone:0".parse::<rtnp_core::flow::Payload>().is_err());
    let wav = FlowSpec {
        payload: Some("wav:/definitely/missing.wav".parse().unwrap()),
        ..tone(Some(Wire::Rtp), "voip-g711")
    };
    assert!(wav.resolve(0).is_err());
}
