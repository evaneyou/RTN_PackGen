//! TLS on the control and log channels, with throwaway certificates.

use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use rtnp_core::client::{SessionOptions, connect_control_with, run_session};
use rtnp_core::flow::FlowSpec;
use rtnp_core::log::{LogRecord, LogSink, read_records};
use rtnp_core::logd::{LogdConfig, serve as logd_serve};
use rtnp_core::receiver::{Receiver, ReceiverConfig};
use rtnp_core::tls::{TlsClient, TlsServer};
use tokio::net::TcpListener;
use tokio::sync::watch;

const LO: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

/// A self-signed certificate for `names`, written as PEM into a fresh directory.
struct Pki {
    dir: PathBuf,
}

impl Pki {
    fn new(tag: &str, names: &[&str]) -> Pki {
        let dir = std::env::temp_dir().join(format!(
            "rtnp-tls-{tag}-{}-{}",
            std::process::id(),
            rand_suffix()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let ck = rcgen::generate_simple_self_signed(
            names.iter().map(|n| n.to_string()).collect::<Vec<_>>(),
        )
        .unwrap();
        std::fs::write(dir.join("cert.pem"), ck.cert.pem()).unwrap();
        std::fs::write(dir.join("key.pem"), ck.key_pair.serialize_pem()).unwrap();
        Pki { dir }
    }
    fn server(&self) -> TlsServer {
        TlsServer::from_files(&self.dir.join("cert.pem"), &self.dir.join("key.pem")).unwrap()
    }
    fn client(&self) -> TlsClient {
        // a self-signed certificate is its own CA
        TlsClient::from_ca_file(&self.dir.join("cert.pem")).unwrap()
    }
}

impl Drop for Pki {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.dir).ok();
    }
}

fn rand_suffix() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64
}

async fn tls_receiver(pki: &Pki, key: Option<&[u8]>) -> (Receiver, String, String) {
    let cfg = ReceiverConfig {
        bind: LO,
        udp_port: Some(0),
        control_port: Some(0),
        auth_key: key.map(<[u8]>::to_vec),
        tls: Some(pki.server()),
        ..Default::default()
    };
    let rx = Receiver::bind(cfg, LogSink::none().handle()).await.unwrap();
    let udp = rx.udp_addr().unwrap().to_string();
    let ctl = rx.control_addr().unwrap().to_string();
    (rx, udp, ctl)
}

#[tokio::test]
async fn session_runs_over_a_tls_control_channel_with_a_key_inside() {
    let pki = Pki::new("ok", &["127.0.0.1", "localhost"]);
    let (rx, udp, ctl) = tls_receiver(&pki, Some(b"s3cret")).await;
    let server = tokio::spawn(rx.serve(std::future::pending()));
    let spec = FlowSpec {
        target: udp,
        preset: Some("voip-g711".into()),
        count: Some(40),
        ..Default::default()
    };
    let log = LogSink::none();
    let mut opts = SessionOptions::new(log.handle());
    opts.control = Some(ctl);
    opts.key = Some(b"s3cret".to_vec());
    opts.tls = Some(pki.client());
    opts.grace = Duration::from_millis(200);
    let (_tx, stop) = watch::channel(false);
    let res = run_session(vec![spec.resolve(0).unwrap()], opts, stop)
        .await
        .unwrap();
    assert_eq!(res.reports[0].rx.as_ref().unwrap().packets, 40);
    server.abort();
}

#[tokio::test]
async fn untrusted_or_misnamed_servers_and_plain_clients_are_refused() {
    let pki = Pki::new("srv", &["127.0.0.1"]);
    let (rx, _udp, ctl) = tls_receiver(&pki, None).await;
    let server = tokio::spawn(rx.serve(std::future::pending()));

    // a CA that did not sign the server's certificate
    let other = Pki::new("other", &["127.0.0.1"]);
    let e = connect_control_with(&ctl, None, Some(&other.client()))
        .await
        .err()
        .expect("wrong CA must fail");
    assert!(e.to_string().contains("TLS"), "{e}");

    // the right CA, but the certificate names another host
    let named = Pki::new("named", &["receiver.example"]);
    let (rx2, _u2, ctl2) = tls_receiver(&named, None).await;
    let server2 = tokio::spawn(rx2.serve(std::future::pending()));
    assert!(
        connect_control_with(&ctl2, None, Some(&named.client()))
            .await
            .is_err()
    );

    // a plain client gets nothing useful from a TLS port
    let log = LogSink::none();
    let mut opts = SessionOptions::new(log.handle());
    opts.control = Some(ctl.clone());
    opts.grace = Duration::from_millis(100);
    let spec = FlowSpec {
        target: "127.0.0.1:9".into(),
        count: Some(1),
        ..Default::default()
    };
    let (_tx, stop) = watch::channel(false);
    let r = tokio::time::timeout(
        Duration::from_secs(20),
        run_session(vec![spec.resolve(0).unwrap()], opts, stop),
    )
    .await
    .expect("does not hang");
    assert!(r.is_err());

    // and the right CA works
    assert!(
        connect_control_with(&ctl, None, Some(&pki.client()))
            .await
            .is_ok()
    );
    server.abort();
    server2.abort();
}

#[tokio::test]
async fn log_server_accepts_streams_over_tls() {
    let pki = Pki::new("logd", &["127.0.0.1"]);
    let dir = pki.dir.join("out");
    std::fs::create_dir_all(&dir).unwrap();
    let listener = TcpListener::bind((LO, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let server = tokio::spawn(logd_serve(
        listener,
        LogdConfig {
            out_dir: dir.clone(),
            key: Some(b"k3y".to_vec()),
            max_bytes_per_conn: 1 << 20,
            tls: Some(pki.server()),
            on_event: Arc::new(|_| {}),
        },
    ));
    // a plain client cannot even get through the handshake
    assert!(
        LogSink::to_remote(&addr, "plain", Some(b"k3y"))
            .await
            .is_err()
    );
    let sink = LogSink::to_remote_with(&addr, "secure", Some(b"k3y"), Some(&pki.client()))
        .await
        .unwrap();
    let h = sink.handle();
    for seq in 0..5 {
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
    assert_eq!(read_records(&files[0]).unwrap().len(), 5);
}

#[test]
fn bad_files_give_clear_errors() {
    let missing = std::path::Path::new("/definitely/missing.pem");
    assert!(TlsClient::from_ca_file(missing).is_err());
    assert!(TlsServer::from_files(missing, missing).is_err());
    let a = Pki::new("a", &["127.0.0.1"]);
    let b = Pki::new("b", &["127.0.0.1"]);
    let e = TlsServer::from_files(&a.dir.join("cert.pem"), &b.dir.join("key.pem"))
        .expect_err("mismatched key");
    assert!(e.to_string().contains("TLS"), "{e}");
}
