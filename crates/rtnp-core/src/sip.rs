//! Minimal SIP call setup over UDP, so a test call looks like a real one: the sender INVITEs the
//! receiver with an SDP offer, the receiver answers with its media port, media flows, and the
//! sender hangs up with BYE.
//!
//! Scope, deliberately small: UDP transport only, one audio stream, no registration, no digest
//! authentication, no re-INVITE, no forking. The responder in `rtnp-recv` is a test endpoint, not
//! a PBX. Key exchange for SRTP is SDES (RFC 4568), `AES_CM_128_HMAC_SHA1_80` only.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;

use crate::error::{Error, Result};
use crate::srtp::{MasterKey, SrtpReceiver};

const MAX_MSG: usize = 8192;
/// Retransmission schedule for the INVITE (RFC 3261 timer A, T1 = 500 ms), then give up.
const RETRANSMITS: [u64; 4] = [500, 1000, 2000, 4000];
/// Calls the responder remembers; the oldest is dropped beyond this.
const MAX_CALLS: usize = 1024;

fn rand_id() -> String {
    format!("{:016x}", rand::random::<u64>())
}

// ---------------------------------------------------------------- messages

/// A parsed SIP request or response.
#[derive(Debug, Clone)]
pub struct Msg {
    start: String,
    headers: Vec<(String, String)>,
    pub body: String,
}

impl Msg {
    pub fn parse(buf: &[u8]) -> Option<Msg> {
        if buf.len() > MAX_MSG {
            return None;
        }
        let text = std::str::from_utf8(buf).ok()?;
        let (head, body) = text.split_once("\r\n\r\n").unwrap_or((text, ""));
        let mut lines = head.split("\r\n");
        let start = lines.next()?.trim().to_string();
        if !start.contains("SIP/2.0") {
            return None;
        }
        let headers = lines
            .filter_map(|l| l.split_once(':'))
            .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string()))
            .collect();
        Some(Msg {
            start,
            headers,
            body: body.to_string(),
        })
    }

    /// Header value by long or compact name.
    pub fn header(&self, name: &str) -> Option<&str> {
        let compact = match name {
            "via" => "v",
            "from" => "f",
            "to" => "t",
            "call-id" => "i",
            "contact" => "m",
            "content-type" => "c",
            _ => name,
        };
        self.headers
            .iter()
            .find(|(k, _)| k == name || k == compact)
            .map(|(_, v)| v.as_str())
    }

    /// Status code if this is a response.
    pub fn status(&self) -> Option<u16> {
        let rest = self.start.strip_prefix("SIP/2.0 ")?;
        rest.split(' ').next()?.parse().ok()
    }

    /// Method if this is a request.
    pub fn method(&self) -> Option<&str> {
        if self.start.starts_with("SIP/2.0") {
            None
        } else {
            self.start.split(' ').next()
        }
    }

    fn call_id(&self) -> Option<&str> {
        self.header("call-id")
    }
}

// ---------------------------------------------------------------- SDP

/// What we read from, or write into, an SDP body: one audio stream.
#[derive(Debug, Clone)]
pub struct Sdp {
    pub ip: IpAddr,
    pub port: u16,
    pub pt: u8,
    /// `RTP/SAVP` (SRTP) rather than `RTP/AVP`.
    pub secure: bool,
    pub key: Option<MasterKey>,
}

fn rtpmap(pt: u8) -> Option<&'static str> {
    Some(match pt {
        0 => "PCMU/8000",
        8 => "PCMA/8000",
        18 => "G729/8000",
        4 => "G723/8000",
        _ => return None,
    })
}

pub fn build_sdp(sdp: &Sdp, ptime_ms: Option<u32>) -> String {
    let fam = if sdp.ip.is_ipv4() { "IP4" } else { "IP6" };
    let proto = if sdp.secure { "RTP/SAVP" } else { "RTP/AVP" };
    let id = rand::random::<u32>();
    let mut s = format!(
        "v=0\r\no=rtnp {id} {id} IN {fam} {ip}\r\ns=rtnp\r\nc=IN {fam} {ip}\r\nt=0 0\r\nm=audio {port} {proto} {pt}\r\n",
        ip = sdp.ip,
        port = sdp.port,
        pt = sdp.pt,
    );
    if let Some(m) = rtpmap(sdp.pt) {
        s += &format!("a=rtpmap:{} {m}\r\n", sdp.pt);
    }
    if let Some(p) = ptime_ms {
        s += &format!("a=ptime:{p}\r\n");
    }
    if let Some(k) = &sdp.key {
        s += &format!(
            "a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:{}\r\n",
            k.to_base64()
        );
    }
    s
}

pub fn parse_sdp(text: &str) -> Result<Sdp> {
    let bad = |m: &str| Error::Protocol(format!("SDP: {m}"));
    let mut ip: Option<IpAddr> = None;
    let mut media: Option<(u16, bool, u8)> = None;
    let mut key = None;
    for line in text.lines().map(str::trim) {
        if let Some(c) = line.strip_prefix("c=") {
            // c=IN IP4 192.0.2.1[/ttl]; the media-level line (after m=) wins
            let addr = c
                .split_whitespace()
                .nth(2)
                .and_then(|a| a.split('/').next());
            if let Some(a) = addr.and_then(|a| a.parse().ok()) {
                if media.is_none() {
                    ip.get_or_insert(a);
                } else {
                    ip = Some(a);
                }
            }
        } else if let Some(m) = line.strip_prefix("m=audio ") {
            if media.is_some() {
                continue; // only the first audio stream
            }
            let mut f = m.split_whitespace();
            let port: u16 = f
                .next()
                .and_then(|p| p.split('/').next()?.parse().ok())
                .ok_or_else(|| bad("bad media port"))?;
            let proto = f.next().ok_or_else(|| bad("no transport"))?;
            let secure = match proto {
                "RTP/AVP" => false,
                "RTP/SAVP" => true,
                other => return Err(bad(&format!("unsupported transport {other}"))),
            };
            let pt = f
                .filter_map(|p| p.parse::<u8>().ok())
                .find(|p| rtpmap(*p).is_some())
                .ok_or_else(|| bad("no supported codec (PCMU, PCMA, G729, G723)"))?;
            media = Some((port, secure, pt));
        } else if let Some(c) = line.strip_prefix("a=crypto:")
            && media.is_some()
            && key.is_none()
        {
            let mut f = c.split_whitespace();
            let (_tag, suite, params) = (f.next(), f.next(), f.next());
            if suite == Some("AES_CM_128_HMAC_SHA1_80")
                && let Some(inline) = params.and_then(|p| p.strip_prefix("inline:"))
            {
                key = MasterKey::parse(inline.split('|').next().unwrap_or(inline)).ok();
            }
        }
    }
    let (port, secure, pt) = media.ok_or_else(|| bad("no audio stream"))?;
    if secure && key.is_none() {
        return Err(bad(
            "SRTP offered without a usable AES_CM_128_HMAC_SHA1_80 key",
        ));
    }
    Ok(Sdp {
        ip: ip.ok_or_else(|| bad("no connection address"))?,
        port,
        pt,
        secure,
        key,
    })
}

/// Local address the OS would use to reach `peer` (nothing is sent).
pub fn local_ip_for(peer: SocketAddr) -> Result<IpAddr> {
    let bind = if peer.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let s = std::net::UdpSocket::bind(bind)?;
    s.connect(peer)?;
    Ok(s.local_addr()?.ip())
}

// ---------------------------------------------------------------- caller

/// What the caller offers.
pub struct Offer<'a> {
    /// Where the callee's SIP port is.
    pub sip_target: SocketAddr,
    /// The caller's RTP source port (its media socket).
    pub media_port: u16,
    pub pt: u8,
    pub ptime_ms: Option<u32>,
    /// SRTP key to offer with SDES; `None` offers plain RTP.
    pub key: Option<&'a MasterKey>,
}

/// An established call (INVITE answered with 2xx and acknowledged).
pub struct Call {
    sock: UdpSocket,
    peer: SocketAddr,
    call_id: String,
    local_ip: IpAddr,
    from: String,
    to: String,
    /// Where to send media, from the answer.
    pub media: SocketAddr,
    pub pt: u8,
}

#[allow(clippy::too_many_arguments)]
fn request(
    method: &str,
    uri: &str,
    via: &str,
    from: &str,
    to: &str,
    call_id: &str,
    cseq: u32,
    extra: &str,
    body: &str,
) -> String {
    let ctype = if body.is_empty() {
        String::new()
    } else {
        "Content-Type: application/sdp\r\n".to_string()
    };
    format!(
        "{method} {uri} SIP/2.0\r\nVia: {via}\r\nMax-Forwards: 70\r\nFrom: {from}\r\nTo: {to}\r\nCall-ID: {call_id}\r\nCSeq: {cseq} {method}\r\n{extra}{ctype}Content-Length: {}\r\n\r\n{body}",
        body.len()
    )
}

/// Place a call: send the INVITE (retransmitting as RFC 3261 does over UDP), wait for the
/// answer, acknowledge it.
pub async fn invite(o: Offer<'_>) -> Result<Call> {
    let bind = if o.sip_target.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let sock = UdpSocket::bind(bind).await?;
    sock.connect(o.sip_target).await?;
    let local = sock.local_addr()?;
    let ip = local.ip();
    let host = |a: IpAddr| {
        if a.is_ipv6() {
            format!("[{a}]")
        } else {
            a.to_string()
        }
    };
    let call_id = format!("{}@{}", rand_id(), host(ip));
    let from = format!("<sip:rtnp@{}>;tag={}", host(ip), rand_id());
    let to = format!("<sip:rtnp@{}>", host(o.sip_target.ip()));
    let branch = format!("z9hG4bK{}", rand_id());
    let via = format!(
        "SIP/2.0/UDP {}:{};branch={branch};rport",
        host(ip),
        local.port()
    );
    let uri = format!(
        "sip:rtnp@{}:{}",
        host(o.sip_target.ip()),
        o.sip_target.port()
    );
    let contact = format!("Contact: <sip:rtnp@{}:{}>\r\n", host(ip), local.port());

    let offer = Sdp {
        ip,
        port: o.media_port,
        pt: o.pt,
        secure: o.key.is_some(),
        key: o.key.cloned(),
    };
    let body = build_sdp(&offer, o.ptime_ms);
    let msg = request(
        "INVITE", &uri, &via, &from, &to, &call_id, 1, &contact, &body,
    );

    let mut buf = vec![0u8; MAX_MSG];
    let mut waits = RETRANSMITS.iter();
    let mut deadline = Instant::now();
    let ok = 'attempts: loop {
        if sock.send(msg.as_bytes()).await.is_err() {
            return Err(Error::Protocol("SIP: cannot reach the callee".into()));
        }
        let Some(ms) = waits.next() else {
            return Err(Error::Protocol("SIP: no answer to INVITE".into()));
        };
        deadline = deadline.max(Instant::now()) + Duration::from_millis(*ms);
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            match tokio::time::timeout(left, sock.recv(&mut buf)).await {
                Err(_) => continue 'attempts, // retransmit
                Ok(Err(e)) => {
                    return Err(Error::Protocol(format!("SIP: callee unreachable ({e})")));
                }
                Ok(Ok(n)) => {
                    let Some(m) = Msg::parse(&buf[..n]) else {
                        continue;
                    };
                    if m.call_id() != Some(call_id.as_str()) {
                        continue;
                    }
                    match m.status() {
                        Some(100..=199) => deadline = Instant::now() + Duration::from_secs(30),
                        Some(200..=299) => break 'attempts m,
                        Some(code) => {
                            // non-2xx final answers are acknowledged too
                            let to_hdr = m.header("to").unwrap_or(&to).to_string();
                            let ack =
                                request("ACK", &uri, &via, &from, &to_hdr, &call_id, 1, "", "");
                            let _ = sock.send(ack.as_bytes()).await;
                            let why = match code {
                                401 | 407 => " (digest authentication is not supported)",
                                488 => " (the callee refused the offered media or SRTP key)",
                                _ => "",
                            };
                            return Err(Error::Protocol(format!(
                                "SIP: call rejected with {code}{why}"
                            )));
                        }
                        None => {}
                    }
                }
            }
        }
    };
    let to_hdr = ok.header("to").unwrap_or(&to).to_string();
    let ans = parse_sdp(&ok.body)?;
    if ans.secure != o.key.is_some() {
        return Err(Error::Protocol(
            "SIP: the answer's media security does not match the offer".into(),
        ));
    }
    // the answer's media address must be the same family we can send to
    if ans.ip.is_ipv4() != o.sip_target.is_ipv4() {
        return Err(Error::Protocol("SIP: answer uses another IP family".into()));
    }
    let ack = request("ACK", &uri, &via, &from, &to_hdr, &call_id, 1, "", "");
    let _ = sock.send(ack.as_bytes()).await;
    Ok(Call {
        sock,
        peer: o.sip_target,
        call_id,
        local_ip: ip,
        from,
        to: to_hdr,
        media: SocketAddr::new(ans.ip, ans.port),
        pt: ans.pt,
    })
}

impl Call {
    /// The local address used for SIP (and the media source address).
    pub fn local_ip(&self) -> IpAddr {
        self.local_ip
    }

    /// Hang up. Best effort: waits up to a second for the 200 OK.
    pub async fn bye(self) {
        let host = |a: IpAddr| {
            if a.is_ipv6() {
                format!("[{a}]")
            } else {
                a.to_string()
            }
        };
        let port = self.sock.local_addr().map(|a| a.port()).unwrap_or(0);
        let via = format!(
            "SIP/2.0/UDP {}:{port};branch=z9hG4bK{};rport",
            host(self.local_ip),
            rand_id()
        );
        let uri = format!("sip:rtnp@{}:{}", host(self.peer.ip()), self.peer.port());
        let msg = request(
            "BYE",
            &uri,
            &via,
            &self.from,
            &self.to,
            &self.call_id,
            2,
            "",
            "",
        );
        let mut buf = vec![0u8; MAX_MSG];
        for _ in 0..2 {
            if self.sock.send(msg.as_bytes()).await.is_err() {
                return;
            }
            if let Ok(Ok(n)) =
                tokio::time::timeout(Duration::from_millis(500), self.sock.recv(&mut buf)).await
                && Msg::parse(&buf[..n]).is_some_and(|m| m.status().is_some_and(|s| s >= 200))
            {
                return;
            }
        }
    }
}

// ---------------------------------------------------------------- callee

struct Dialog {
    /// Media source the caller announced (keys SRTP lookups).
    media_src: SocketAddr,
    reply: String,
    started: Instant,
}

/// SRTP receivers for calls whose key arrived in SDP, keyed by the caller's announced media
/// address.
#[derive(Default)]
pub struct CallKeys {
    inner: Mutex<HashMap<SocketAddr, SrtpReceiver>>,
}

impl CallKeys {
    /// `None` if `src` has no SDES call; `Some(None)` if it has one and the packet failed
    /// authentication; `Some(Some(len))` with the plaintext length otherwise.
    pub fn unprotect(&self, src: SocketAddr, buf: &mut [u8]) -> Option<Option<usize>> {
        let mut m = self.inner.lock().ok()?;
        m.get_mut(&src).map(|rx| rx.unprotect(buf))
    }

    pub fn is_empty(&self) -> bool {
        self.inner.lock().map(|m| m.is_empty()).unwrap_or(true)
    }

    pub fn len(&self) -> usize {
        self.inner.lock().map(|m| m.len()).unwrap_or(0)
    }
}

/// How the responder treats SRTP offers.
#[derive(Clone)]
pub struct Policy {
    /// The receiver's RTP port, announced in answers.
    pub media_port: u16,
    /// Static SRTP key the data port already uses: SAVP offers must carry exactly this key.
    /// `None`: SAVP offers are accepted with whatever key they bring (SDES).
    pub static_key: Option<MasterKey>,
}

/// Answer SIP requests on `sock` until the task is dropped.
pub async fn serve(sock: UdpSocket, policy: Policy, keys: std::sync::Arc<CallKeys>) -> Result<()> {
    let mut dialogs: HashMap<String, Dialog> = HashMap::new();
    let mut buf = vec![0u8; MAX_MSG + 1];
    loop {
        let (n, peer) = match sock.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => continue,
            Err(e) => return Err(e.into()),
        };
        let Some(m) = Msg::parse(&buf[..n]) else {
            continue;
        };
        let Some(method) = m.method().map(str::to_string) else {
            continue;
        };
        let Some(call_id) = m.call_id().map(str::to_string) else {
            continue;
        };
        let reply = |code: u16, reason: &str, to_tag: Option<&str>, body: &str| {
            let to = match (m.header("to"), to_tag) {
                (Some(t), Some(tag)) if !t.contains(";tag=") => format!("{t};tag={tag}"),
                (Some(t), _) => t.to_string(),
                _ => String::new(),
            };
            let ctype = if body.is_empty() {
                ""
            } else {
                "Content-Type: application/sdp\r\n"
            };
            format!(
                "SIP/2.0 {code} {reason}\r\nVia: {}\r\nFrom: {}\r\nTo: {to}\r\nCall-ID: {call_id}\r\nCSeq: {}\r\n{ctype}Content-Length: {}\r\n\r\n{body}",
                m.header("via").unwrap_or(""),
                m.header("from").unwrap_or(""),
                m.header("cseq").unwrap_or(""),
                body.len()
            )
        };
        match method.as_str() {
            "INVITE" => {
                if let Some(d) = dialogs.get(&call_id) {
                    let _ = sock.send_to(d.reply.as_bytes(), peer).await; // retransmitted INVITE
                    continue;
                }
                let refuse = |code, reason| reply(code, reason, Some(&rand_id()), "");
                let offer = match parse_sdp(&m.body) {
                    Ok(o) => o,
                    Err(_) => {
                        let _ = sock
                            .send_to(refuse(488, "Not Acceptable Here").as_bytes(), peer)
                            .await;
                        continue;
                    }
                };
                // media-security policy
                let ok = match (&policy.static_key, offer.secure, &offer.key) {
                    (Some(k), true, Some(o)) => k == o,
                    (Some(_), _, _) => false,
                    (None, _, _) => true,
                };
                if !ok {
                    let _ = sock
                        .send_to(refuse(488, "Not Acceptable Here").as_bytes(), peer)
                        .await;
                    continue;
                }
                let media_src = SocketAddr::new(offer.ip, offer.port);
                if offer.secure && policy.static_key.is_none() {
                    let stored = match (&offer.key, keys.inner.lock()) {
                        (Some(k), Ok(mut map)) if map.len() < MAX_CALLS => {
                            map.insert(media_src, SrtpReceiver::new(k));
                            true
                        }
                        _ => false,
                    };
                    if !stored {
                        let _ = sock
                            .send_to(refuse(503, "Service Unavailable").as_bytes(), peer)
                            .await;
                        continue;
                    }
                }
                if dialogs.len() >= MAX_CALLS
                    && let Some(oldest) = dialogs
                        .iter()
                        .min_by_key(|(_, d)| d.started)
                        .map(|(k, _)| k.clone())
                    && let Some(d) = dialogs.remove(&oldest)
                    && let Ok(mut map) = keys.inner.lock()
                {
                    map.remove(&d.media_src);
                }
                let my_ip = local_ip_for(peer).unwrap_or(peer.ip());
                let answer = Sdp {
                    ip: my_ip,
                    port: policy.media_port,
                    pt: offer.pt,
                    secure: offer.secure,
                    key: offer.key.clone(),
                };
                let tag = rand_id();
                let host = if my_ip.is_ipv6() {
                    format!("[{my_ip}]")
                } else {
                    my_ip.to_string()
                };
                let mut ok = reply(200, "OK", Some(&tag), &build_sdp(&answer, None));
                ok = ok.replacen(
                    "Content-Type:",
                    &format!("Contact: <sip:rtnp@{host}>\r\nContent-Type:"),
                    1,
                );
                let _ = sock.send_to(ok.as_bytes(), peer).await;
                dialogs.insert(
                    call_id,
                    Dialog {
                        media_src,
                        reply: ok,
                        started: Instant::now(),
                    },
                );
            }
            "ACK" => {}
            "BYE" => {
                let resp = match dialogs.remove(&call_id) {
                    Some(d) => {
                        if let Ok(mut map) = keys.inner.lock() {
                            map.remove(&d.media_src);
                        }
                        reply(200, "OK", None, "")
                    }
                    None => reply(481, "Call/Transaction Does Not Exist", None, ""),
                };
                let _ = sock.send_to(resp.as_bytes(), peer).await;
            }
            "OPTIONS" => {
                let _ = sock
                    .send_to(reply(200, "OK", None, "").as_bytes(), peer)
                    .await;
            }
            _ => {
                let _ = sock
                    .send_to(reply(501, "Not Implemented", None, "").as_bytes(), peer)
                    .await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sdp_round_trips_with_a_key() {
        let key = MasterKey::from_bytes([9; 30]);
        let a = Sdp {
            ip: "192.0.2.7".parse().unwrap(),
            port: 40000,
            pt: 8,
            secure: true,
            key: Some(key.clone()),
        };
        let text = build_sdp(&a, Some(20));
        assert!(text.contains("m=audio 40000 RTP/SAVP 8\r\n"));
        assert!(text.contains("a=rtpmap:8 PCMA/8000"));
        assert!(text.contains("a=ptime:20"));
        let b = parse_sdp(&text).unwrap();
        assert_eq!((b.ip, b.port, b.pt, b.secure), (a.ip, 40000, 8, true));
        assert_eq!(b.key, Some(key));
    }

    #[test]
    fn sdp_rejects_what_it_cannot_do() {
        assert!(parse_sdp("v=0\r\nc=IN IP4 1.2.3.4\r\nm=video 5000 RTP/AVP 96\r\n").is_err());
        assert!(
            parse_sdp("v=0\r\nc=IN IP4 1.2.3.4\r\nm=audio 5000 UDP/TLS/RTP/SAVPF 0\r\n").is_err()
        );
        assert!(
            parse_sdp("v=0\r\nc=IN IP4 1.2.3.4\r\nm=audio 5000 RTP/SAVP 0\r\n").is_err(),
            "SAVP without a key"
        );
        assert!(
            parse_sdp("v=0\r\nc=IN IP4 1.2.3.4\r\nm=audio 5000 RTP/AVP 111\r\n").is_err(),
            "unknown codec"
        );
        // picks the first codec we know from a list; media-level c= wins
        let s = parse_sdp(
            "v=0\r\nc=IN IP4 1.2.3.4\r\nm=audio 5000 RTP/AVP 101 8 0\r\nc=IN IP4 5.6.7.8\r\n",
        )
        .unwrap();
        assert_eq!((s.ip.to_string(), s.pt), ("5.6.7.8".into(), 8));
    }

    #[test]
    fn messages_parse_requests_and_responses() {
        let r = Msg::parse(b"SIP/2.0 180 Ringing\r\nv: x\r\ni: abc\r\n\r\n").unwrap();
        assert_eq!(r.status(), Some(180));
        assert_eq!(r.header("call-id"), Some("abc"));
        assert_eq!(r.header("via"), Some("x"), "compact header names work");
        let q = Msg::parse(b"BYE sip:a@b SIP/2.0\r\nCall-ID: z\r\n\r\n").unwrap();
        assert_eq!(q.method(), Some("BYE"));
        assert!(Msg::parse(b"GET / HTTP/1.1\r\n\r\n").is_none());
    }
}
