//! Optional TLS (rustls) for the TCP control and log channels.
//!
//! Servers (`rtnp-recv` control port, `rtnp-logd`) load a certificate chain and private key from
//! PEM files. Clients verify the server against a CA file you give them; there is no option to
//! skip verification. Client certificates (mutual TLS) are not used: the shared-key handshake
//! still runs inside the TLS session when a key is configured.
//!
//! Only the control and log connections are covered. The traffic being measured (UDP, TCP data,
//! SCTP) and the Prometheus endpoint stay unencrypted.

use std::io;
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::{TlsAcceptor, TlsConnector};

use crate::error::{Error, Result};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// A control or log connection, plain or inside TLS.
pub enum Stream {
    Plain(TcpStream),
    Client(Box<tokio_rustls::client::TlsStream<TcpStream>>),
    Server(Box<tokio_rustls::server::TlsStream<TcpStream>>),
}

impl From<TcpStream> for Stream {
    fn from(s: TcpStream) -> Self {
        Stream::Plain(s)
    }
}

macro_rules! delegate {
    ($self:ident, $s:ident => $e:expr) => {
        match $self.get_mut() {
            Stream::Plain($s) => $e,
            Stream::Client($s) => $e,
            Stream::Server($s) => $e,
        }
    };
}

impl AsyncRead for Stream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        delegate!(self, s => Pin::new(s).poll_read(cx, buf))
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        delegate!(self, s => Pin::new(s).poll_write(cx, buf))
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        delegate!(self, s => Pin::new(s).poll_flush(cx))
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        delegate!(self, s => Pin::new(s).poll_shutdown(cx))
    }
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

fn cfg_err(what: &str, e: impl std::fmt::Display) -> Error {
    Error::Config(format!("TLS: {what}: {e}"))
}

/// Client side: trusts the CA certificate(s) in one PEM file.
#[derive(Clone)]
pub struct TlsClient {
    connector: TlsConnector,
}

impl std::fmt::Debug for TlsClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TlsClient")
    }
}

impl TlsClient {
    pub fn from_ca_file(path: &Path) -> Result<Self> {
        let mut roots = RootCertStore::empty();
        let mut n = 0;
        for cert in CertificateDer::pem_file_iter(path)
            .map_err(|e| cfg_err(&format!("cannot read CA file {}", path.display()), e))?
        {
            let cert = cert.map_err(|e| cfg_err("bad certificate in CA file", e))?;
            roots
                .add(cert)
                .map_err(|e| cfg_err("unusable CA certificate", e))?;
            n += 1;
        }
        if n == 0 {
            return Err(cfg_err("CA file has no certificates", path.display()));
        }
        let cfg = ClientConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .map_err(|e| cfg_err("protocol setup", e))?
            .with_root_certificates(roots)
            .with_no_client_auth();
        Ok(TlsClient {
            connector: TlsConnector::from(Arc::new(cfg)),
        })
    }

    /// Run the TLS handshake over `tcp`, checking the server certificate against the host in
    /// `addr` (`host:port`, a DNS name or an IP address).
    pub async fn connect(&self, addr: &str, tcp: TcpStream) -> Result<Stream> {
        let host = addr
            .rsplit_once(':')
            .map_or(addr, |(h, _)| h)
            .trim_matches(['[', ']']);
        let name = ServerName::try_from(host.to_string())
            .map_err(|_| Error::Config(format!("TLS: '{host}' is not a valid server name")))?;
        let tls = timeout(HANDSHAKE_TIMEOUT, self.connector.connect(name, tcp))
            .await
            .map_err(|_| Error::Protocol("TLS handshake timed out".into()))?
            .map_err(|e| {
                let hint = if e.to_string().contains("CaUsedAsEndEntity") {
                    " (the server is using a CA certificate as its own; sign a separate server \
                     certificate with it, see scripts/make-test-certs.sh)"
                } else {
                    ""
                };
                Error::Protocol(format!("TLS handshake with {addr} failed: {e}{hint}"))
            })?;
        Ok(Stream::Client(Box::new(tls)))
    }
}

/// Server side: a certificate chain and private key from PEM files.
#[derive(Clone)]
pub struct TlsServer {
    acceptor: TlsAcceptor,
}

impl std::fmt::Debug for TlsServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TlsServer")
    }
}

impl TlsServer {
    pub fn from_files(cert: &Path, key: &Path) -> Result<Self> {
        let certs = CertificateDer::pem_file_iter(cert)
            .map_err(|e| cfg_err(&format!("cannot read certificate {}", cert.display()), e))?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| cfg_err("bad certificate", e))?;
        if certs.is_empty() {
            return Err(cfg_err(
                "certificate file has no certificates",
                cert.display(),
            ));
        }
        let key = PrivateKeyDer::from_pem_file(key)
            .map_err(|e| cfg_err(&format!("cannot read private key {}", key.display()), e))?;
        let cfg = ServerConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .map_err(|e| cfg_err("protocol setup", e))?
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| cfg_err("certificate and key do not match", e))?;
        Ok(TlsServer {
            acceptor: TlsAcceptor::from(Arc::new(cfg)),
        })
    }

    pub async fn accept(&self, tcp: TcpStream) -> Result<Stream> {
        let tls = timeout(HANDSHAKE_TIMEOUT, self.acceptor.accept(tcp))
            .await
            .map_err(|_| Error::Protocol("TLS handshake timed out".into()))?
            .map_err(|e| Error::Protocol(format!("TLS handshake failed: {e}")))?;
        Ok(Stream::Server(Box::new(tls)))
    }
}

/// Wrap an accepted connection: TLS if configured, plain otherwise.
pub async fn accept_optional(tls: Option<&TlsServer>, tcp: TcpStream) -> Result<Stream> {
    match tls {
        Some(t) => t.accept(tcp).await,
        None => Ok(Stream::Plain(tcp)),
    }
}
