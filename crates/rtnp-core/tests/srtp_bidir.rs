//! Two-way (bidirectional) calls with SRTP: the return stream is protected with the same
//! master key as the forward stream, with its own SSRC and rollover state.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use rtnp_core::client::{SessionOptions, connect_control, run_session};
use rtnp_core::control::{ClientMsg, FlowAnnounce, ReverseSpec, ServerMsg, read_msg, write_msg};
use rtnp_core::flow::{Codec, FlowSpec, Proto, Wire};
use rtnp_core::log::LogSink;
use rtnp_core::proto::{VERSION, write_rtp};
use rtnp_core::receiver::{Receiver, ReceiverConfig};
use rtnp_core::srtp::{MasterKey, SrtpReceiver, TAG_LEN};
use tokio::net::UdpSocket;
use tokio::sync::watch;

const LO: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

fn key(n: u8) -> MasterKey {
    MasterKey::from_bytes([n; 30])
}

fn recv_cfg(srtp_key: Option<MasterKey>, sip: bool) -> ReceiverConfig {
    ReceiverConfig {
        bind: LO,
        udp_port: Some(0),
        control_port: Some(0),
        sip_port: sip.then_some(0),
        allow_reverse: true,
        srtp_key,
        ..Default::default()
    }
}

fn two_way(target: SocketAddr, srtp_key: Option<MasterKey>, sip: bool) -> FlowSpec {
    FlowSpec {
        target: target.to_string(),
        wire: Some(Wire::Rtp),
        rtp: Some(Codec::G711),
        ptime_ms: Some(20.0),
        bidirectional: true,
        count: Some(150), // 3 s
        srtp_key,
        srtp: sip,
        sip,
        ..Default::default()
    }
}

async fn run(spec: FlowSpec, ctl: SocketAddr, log: &LogSink) -> rtnp_core::client::SessionResult {
    let mut opts = SessionOptions::new(log.handle());
    opts.control = Some(ctl.to_string());
    opts.grace = Duration::from_millis(200);
    let (_tx, stop) = watch::channel(false);
    run_session(vec![spec.resolve(0).unwrap()], opts, stop)
        .await
        .unwrap()
}

fn check_both_directions(res: &rtnp_core::client::SessionResult) {
    let r = &res.reports[0];
    let fwd = r.rx.as_ref().expect("forward stream decrypted");
    assert_eq!((fwd.packets, fwd.lost), (150, 0));
    assert_eq!(fwd.bytes, 150 * 172, "counted after decryption");
    let rev = r
        .reverse
        .as_ref()
        .expect("return stream measured at the sender");
    assert!(rev.packets >= 140, "return packets {}", rev.packets);
    assert_eq!(rev.lost, 0);
    assert_eq!(rev.bytes, rev.packets * 172, "counted after decryption");
}

#[tokio::test]
async fn two_way_call_with_a_fixed_key() {
    let log = LogSink::none();
    let rx = Receiver::bind(recv_cfg(Some(key(9)), false), log.handle())
        .await
        .unwrap();
    let (udp, ctl) = (rx.udp_addr().unwrap(), rx.control_addr().unwrap());
    let server = tokio::spawn(rx.serve(std::future::pending()));
    let res = run(two_way(udp, Some(key(9)), false), ctl, &log).await;
    check_both_directions(&res);
    server.abort();
}

#[tokio::test]
async fn two_way_call_with_a_per_call_sdes_key() {
    let log = LogSink::none();
    let rx = Receiver::bind(recv_cfg(None, true), log.handle())
        .await
        .unwrap();
    let (sip, ctl) = (rx.sip_addr().unwrap(), rx.control_addr().unwrap());
    let keys = rx.call_keys();
    let server = tokio::spawn(rx.serve(std::future::pending()));
    let res = run(two_way(sip, None, true), ctl, &log).await;
    check_both_directions(&res);
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(keys.is_empty(), "BYE removes the call's key");
    server.abort();
}

/// What the return stream looks like on the wire: tagged, encrypted, and decryptable with the
/// shared key.
#[tokio::test]
async fn return_stream_is_encrypted_on_the_wire() {
    let log = LogSink::none();
    let rx = Receiver::bind(recv_cfg(Some(key(3)), false), log.handle())
        .await
        .unwrap();
    let (udp, ctl) = (rx.udp_addr().unwrap(), rx.control_addr().unwrap());
    let server = tokio::spawn(rx.serve(std::future::pending()));

    let mut c = connect_control(&ctl.to_string(), None).await.unwrap();
    write_msg(
        &mut c,
        &ClientMsg::Hello {
            version: VERSION,
            session: 7,
            flows: vec![FlowAnnounce {
                flow: 1,
                name: "raw".into(),
                proto: Proto::Udp,
                ssrc: Some(0x1111),
                reverse: Some(ReverseSpec {
                    codec: Codec::G711,
                    idt_ms: 20.0,
                    packet_bytes: 172,
                    ssrc: 0x2222,
                    tos: None,
                }),
            }],
        },
    )
    .await
    .unwrap();
    assert!(matches!(
        read_msg::<_, ServerMsg>(&mut c).await.unwrap(),
        Some(ServerMsg::Ready { reverse: true, .. })
    ));

    // one authentic forward packet latches the destination
    let src = UdpSocket::bind((LO, 0)).await.unwrap();
    let mut b = vec![0u8; 172 + TAG_LEN];
    write_rtp(&mut b[..172], 0, false, 1, 160, 0x1111);
    let len = key(3).session().protect(&mut b, 172, 0);
    src.send_to(&b[..len], udp).await.unwrap();

    let mut dec = SrtpReceiver::new(&key(3));
    let mut buf = vec![0u8; 2048];
    let mut got = 0;
    let end = tokio::time::Instant::now() + Duration::from_millis(600);
    while let Ok(Ok(n)) = tokio::time::timeout_at(end, src.recv(&mut buf)).await {
        assert_eq!(n, 172 + TAG_LEN, "RTP packet plus 10-byte tag");
        assert_eq!(&buf[8..12], &0x2222u32.to_be_bytes());
        assert!(
            buf[12..172].windows(2).any(|w| w[0] != w[1]),
            "ciphertext must not be the constant silence fill"
        );
        let plain = dec
            .unprotect(&mut buf[..n])
            .expect("authentic return packet");
        assert_eq!(plain, 172);
        assert!(buf[12..172].iter().all(|&x| x == 0xff), "µ-law silence");
        got += 1;
    }
    assert!(got >= 20, "got {got} return packets");
    server.abort();
}
