//! High-level sender API: run a set of flows as one session, optionally coordinated with a
//! receiver over the control channel, or ask a remote agent to run them.
//!
//! ```no_run
//! # async fn demo() -> rtnp_core::Result<()> {
//! use rtnp_core::client::{SessionOptions, run_session};
//! use rtnp_core::flow::Script;
//! use rtnp_core::log::LogSink;
//!
//! let script = Script::from_toml("[[flow]]\ntarget = \"10.0.0.2:8998\"\npreset = \"voip-g711\"")?;
//! let flows = script.flow.iter().enumerate().map(|(i, f)| f.resolve(i)).collect::<Result<Vec<_>, _>>()?;
//! let (_stop_tx, stop_rx) = tokio::sync::watch::channel(false);
//! let result = run_session(flows, SessionOptions::new(LogSink::none().handle()), stop_rx).await?;
//! for r in &result.reports {
//!     println!("{} sent {:?}", r.name, r.sent);
//! }
//! # Ok(()) }
//! ```

use std::sync::Arc;
use std::time::Duration;

use serde::Serialize;
use tokio::net::TcpStream;
use tokio::sync::watch;
use tokio::task::JoinSet;
use tokio::time::{Instant, MissedTickBehavior, interval_at, timeout};

use crate::auth;
use crate::control::{ClientMsg, FlowAnnounce, ReverseSpec, ServerMsg, read_msg, write_msg};
use crate::dist::Dist;
use crate::error::{Error, Result};
use crate::flow::{FlowSpec, Proto, ResolvedFlow, Wire};
use crate::log::LogHandle;
use crate::proto::{VERSION, reverse_ssrc, ssrc_for};
use crate::report::{FlowReport, RttSummary, rtt_summary};
use crate::sender::{FlowOutcome, FlowProgress, run_flow_with_progress};
use crate::stats::Summary;
use crate::time::now_ns;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const POLL_TIMEOUT: Duration = Duration::from_secs(3);
/// Round-trip samples kept per flow for the final report (8 MB); later ones only feed the
/// interval reports. Keeps an endless run bounded.
const MAX_KEPT_RTTS: usize = 1_000_000;

/// One flow's numbers for a single reporting interval.
#[derive(Debug, Clone, Serialize)]
pub struct IntervalFlow {
    pub flow: u32,
    pub name: String,
    pub proto: String,
    /// Packets (probes) sent during the interval.
    pub sent: u64,
    pub tx_kbps: f64,
    /// The receiver's view of the interval (needs `control`). Bitrate and rate are averaged
    /// over the whole interval; delay and jitter cover the packets that arrived in it.
    pub rx: Option<Summary>,
    /// Round-trip times of the replies that arrived during the interval.
    pub rtt: Option<RttSummary>,
    /// Packets lost, when it can be known: ICMP probes that timed out, or sequence gaps seen
    /// by the receiver. A gap is reported in the first interval that sees a later packet; an
    /// interval in which nothing arrived is charged with what the previous interval sent.
    pub lost: Option<u64>,
    pub loss_pct: Option<f64>,
    /// Two-way calls: the return stream (receiver to sender) during the interval, measured
    /// here, with the same loss rules as the forward direction.
    pub reverse: Option<Summary>,
    pub reverse_lost: Option<u64>,
    pub reverse_loss_pct: Option<f64>,
    /// Present when quality limits were given.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verdict: Option<crate::verdict::Verdict>,
}

/// Rolling summary passed to [`SessionOptions::on_interval`].
#[derive(Debug, Clone, Serialize)]
pub struct IntervalReport {
    pub session: u32,
    /// 1, 2, 3, ...
    pub index: u64,
    /// Wall-clock time of the report, milliseconds since the Unix epoch.
    pub unix_ms: u64,
    pub elapsed_s: f64,
    /// Actual length of this interval.
    pub interval_s: f64,
    pub flows: Vec<IntervalFlow>,
    pub warnings: Vec<String>,
}

pub type IntervalCallback = Box<dyn FnMut(&IntervalReport) + Send>;

pub struct SessionOptions {
    /// Receiver control address (`host:port`). Enables the end-of-run report from the receiver.
    pub control: Option<String>,
    /// Shared key for the control channel.
    pub key: Option<Vec<u8>>,
    pub log: LogHandle,
    pub log_packets: bool,
    /// How long the receiver waits for in-flight packets before reporting.
    pub grace: Duration,
    /// Emit a rolling [`IntervalReport`] this often while the flows run (to `on_interval`).
    pub interval: Option<Duration>,
    pub on_interval: Option<IntervalCallback>,
    /// Judge every interval and the final report against these limits.
    pub limits: Option<crate::verdict::QualityLimits>,
}

impl SessionOptions {
    pub fn new(log: LogHandle) -> Self {
        SessionOptions {
            control: None,
            key: None,
            log,
            log_packets: false,
            grace: Duration::from_millis(500),
            interval: None,
            on_interval: None,
            limits: None,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct SessionResult {
    pub session: u32,
    pub reports: Vec<FlowReport>,
    /// Flows that failed to run.
    pub errors: Vec<String>,
    /// Non-fatal observations (UDP send errors, missing receiver report, ...).
    pub warnings: Vec<String>,
}

fn timed_out(what: &str) -> Error {
    Error::Protocol(format!("timed out {what}"))
}

/// Connect to a control channel and authenticate if a key is given.
pub async fn connect_control(addr: &str, key: Option<&[u8]>) -> Result<TcpStream> {
    let mut s = timeout(CONNECT_TIMEOUT, TcpStream::connect(addr))
        .await
        .map_err(|_| timed_out(&format!("connecting to {addr}")))?
        .map_err(|e| Error::Protocol(format!("cannot connect to {addr}: {e}")))?;
    if let Some(k) = key {
        timeout(CONNECT_TIMEOUT, auth::client_handshake(&mut s, k))
            .await
            .map_err(|_| {
                timed_out("during authentication (is a key configured on the receiver?)")
            })??;
    }
    Ok(s)
}

/// Turn a malformed first reply into a hint about missing authentication.
fn friendly_reply_error(e: Error) -> Error {
    match e {
        Error::Json(_) => Error::Protocol(
            "unexpected reply from receiver (does it require a key? pass --key)".into(),
        ),
        other => other,
    }
}

#[derive(Default)]
struct FlowTrack {
    prev_sent: u64,
    prev_bytes: u64,
    prev_replies: u64,
    prev_failed: u64,
    /// Sent / received in the previous interval, to charge an empty interval with loss.
    last_sent: u64,
    last_rx: u64,
    /// Loss already reported for packets that a later gap will include again.
    carried_lost: u64,
    rev_last_rx: u64,
    rev_carried_lost: u64,
    kept_rtts: Vec<f64>,
}

/// Loss in one interval from the receiver's window (`s`), given what was sent in the interval
/// before (`last_sent`, of which `last_rx` arrived) and the loss already charged to silent
/// intervals (`carried`).
fn window_loss(
    s: &Summary,
    last_sent: u64,
    last_rx: u64,
    carried: &mut u64,
) -> (Option<u64>, Option<f64>) {
    if s.packets > 0 {
        let lost = s.lost.saturating_sub(*carried);
        *carried = 0;
        (
            Some(lost),
            Some(lost as f64 * 100.0 / (s.packets + lost) as f64),
        )
    } else {
        let lost = last_sent.saturating_sub(last_rx);
        *carried += lost;
        (Some(lost), (lost > 0).then_some(100.0))
    }
}

struct IntervalClock {
    started: Instant,
    last: Instant,
    index: u64,
    poll_ok: bool,
}

async fn poll_window(
    ctl: &mut TcpStream,
    session: u32,
) -> std::result::Result<Vec<crate::control::RemoteFlowSummary>, String> {
    write_msg(ctl, &ClientMsg::Poll { session })
        .await
        .map_err(|e| e.to_string())?;
    match timeout(POLL_TIMEOUT, read_msg::<_, ServerMsg>(ctl)).await {
        Ok(Ok(Some(ServerMsg::Window { flows, .. }))) => Ok(flows),
        Ok(Ok(Some(ServerMsg::Error { message }))) => Err(message),
        Ok(Ok(other)) => Err(format!("unexpected reply to poll: {other:?}")),
        Ok(Err(e)) => Err(e.to_string()),
        Err(_) => Err("timed out waiting for the receiver".into()),
    }
}

async fn interval_tick(
    session: u32,
    clock: &mut IntervalClock,
    flows: &[ResolvedFlow],
    progress: &[Arc<FlowProgress>],
    tracks: &mut [FlowTrack],
    ctl: Option<&mut TcpStream>,
    limits: Option<&crate::verdict::QualityLimits>,
) -> IntervalReport {
    clock.index += 1;
    let mut warnings = Vec::new();

    // Ask the receiver first: the sender's counters read afterwards can only be newer.
    let mut remote = None;
    if let Some(s) = ctl
        && clock.poll_ok
    {
        match poll_window(s, session).await {
            Ok(w) => remote = Some(w),
            Err(e) => {
                // a half-read reply would desynchronise the channel, so stop polling
                warnings.push(format!("receiver polling stopped: {e}"));
                clock.poll_ok = false;
            }
        }
    }

    let now = Instant::now();
    let interval_s = (now - clock.last).as_secs_f64().max(1e-9);
    clock.last = now;

    let mut out = Vec::with_capacity(flows.len());
    for (i, f) in flows.iter().enumerate() {
        let flow_id = i as u32 + 1;
        let (p, t) = (&progress[i], &mut tracks[i]);
        let (sent, bytes, replies, failed) = (p.sent(), p.bytes(), p.replies(), p.failed());
        let d_sent = sent.saturating_sub(t.prev_sent);
        let d_bytes = bytes.saturating_sub(t.prev_bytes);
        let d_replies = replies.saturating_sub(t.prev_replies);
        let d_failed = failed.saturating_sub(t.prev_failed);
        t.prev_sent = sent;
        t.prev_bytes = bytes;
        t.prev_replies = replies;
        t.prev_failed = failed;

        let rtts = p.take_rtts();
        let room = MAX_KEPT_RTTS.saturating_sub(t.kept_rtts.len());
        t.kept_rtts.extend(rtts.iter().copied().take(room));
        let rtt = rtt_summary(&rtts);

        let mut rx = remote
            .as_ref()
            .and_then(|w| w.iter().find(|r| r.flow == flow_id))
            .map(|r| r.summary.clone());
        if let Some(r) = rx.as_mut() {
            r.duration_s = interval_s;
            r.bitrate_kbps = r.bytes as f64 * 8.0 / 1000.0 / interval_s;
            r.pps = r.packets as f64 / interval_s;
        }

        let (lost, loss_pct) = if f.proto == Proto::Icmp {
            let done = d_replies + d_failed;
            (
                Some(d_failed),
                (done > 0).then(|| d_failed as f64 * 100.0 / done as f64),
            )
        } else if let Some(r) = &rx {
            window_loss(r, t.last_sent, t.last_rx, &mut t.carried_lost)
        } else {
            (None, None)
        };
        let mut reverse = p.take_reverse_window();
        let (reverse_lost, reverse_loss_pct) = match reverse.as_mut() {
            Some(r) => {
                r.duration_s = interval_s;
                r.bitrate_kbps = r.bytes as f64 * 8.0 / 1000.0 / interval_s;
                r.pps = r.packets as f64 / interval_s;
                // the far end sends at the same cadence, so what we sent last interval is
                // what we expect to have received
                let res = window_loss(r, t.last_sent, t.rev_last_rx, &mut t.rev_carried_lost);
                t.rev_last_rx = r.packets;
                res
            }
            None => (None, None),
        };
        t.last_sent = d_sent;
        t.last_rx = rx.as_ref().map_or(0, |r| r.packets);

        let verdict = limits.map(|l| {
            l.judge(
                rx.as_ref(),
                reverse.as_ref(),
                rtt.as_ref(),
                loss_pct.filter(|_| f.proto != Proto::Icmp),
            )
        });
        out.push(IntervalFlow {
            flow: flow_id,
            name: f.name.clone(),
            proto: f.proto.as_str().into(),
            sent: d_sent,
            tx_kbps: d_bytes as f64 * 8.0 / 1000.0 / interval_s,
            rx,
            rtt,
            lost,
            loss_pct,
            reverse,
            reverse_lost,
            reverse_loss_pct,
            verdict,
        });
    }

    IntervalReport {
        session,
        index: clock.index,
        unix_ms: now_ns() / 1_000_000,
        elapsed_s: (now - clock.started).as_secs_f64(),
        interval_s,
        flows: out,
        warnings,
    }
}

/// The return stream a two-way call asks the receiver for: same codec and cadence as the
/// forward stream. (`resolve` guarantees constant interval and size.)
fn reverse_spec(f: &ResolvedFlow, session: u32, flow: u32) -> Option<ReverseSpec> {
    if !f.bidirectional {
        return None;
    }
    let (Dist::Constant { value: idt_ms }, Dist::Constant { value: size }) = (&f.idt_ms, &f.size)
    else {
        return None;
    };
    Some(ReverseSpec {
        codec: f.rtp?,
        idt_ms: *idt_ms,
        packet_bytes: *size as usize,
        ssrc: reverse_ssrc(session, flow),
        tos: f.tos,
    })
}

/// Run all flows concurrently as one session.
pub async fn run_session(
    flows: Vec<ResolvedFlow>,
    mut opts: SessionOptions,
    stop: watch::Receiver<bool>,
) -> Result<SessionResult> {
    let session: u32 = rand::random();
    if opts.control.is_none() && flows.iter().any(|f| f.bidirectional) {
        return Err(Error::Config(
            "a bidirectional call needs the control channel (--control) to set up the return stream"
                .into(),
        ));
    }

    // Control channel handshake.
    let mut ctl = match &opts.control {
        Some(addr) => {
            let mut s = connect_control(addr, opts.key.as_deref()).await?;
            let announce = flows
                .iter()
                .enumerate()
                .map(|(i, f)| FlowAnnounce {
                    flow: i as u32 + 1,
                    name: f.name.clone(),
                    proto: f.proto,
                    ssrc: (f.wire == Wire::Rtp).then(|| ssrc_for(session, i as u32 + 1)),
                    reverse: reverse_spec(f, session, i as u32 + 1),
                })
                .collect();
            write_msg(
                &mut s,
                &ClientMsg::Hello {
                    version: VERSION,
                    session,
                    flows: announce,
                },
            )
            .await?;
            match timeout(CONNECT_TIMEOUT, read_msg::<_, ServerMsg>(&mut s)).await {
                Ok(Ok(Some(ServerMsg::Ready { .. }))) => {}
                Ok(Ok(Some(ServerMsg::Error { message }))) => {
                    return Err(Error::Protocol(format!(
                        "receiver refused session: {message}"
                    )));
                }
                Ok(Ok(_)) => return Err(Error::Protocol("unexpected reply from receiver".into())),
                Ok(Err(e)) => return Err(friendly_reply_error(e)),
                Err(_) => return Err(timed_out("waiting for the control handshake")),
            }
            Some(s)
        }
        None => None,
    };

    let progress: Vec<Arc<FlowProgress>> = flows.iter().map(|_| Arc::default()).collect();
    let mut set: JoinSet<(usize, Result<FlowOutcome>)> = JoinSet::new();
    for (i, f) in flows.iter().cloned().enumerate() {
        let log = opts.log.clone();
        let stop = stop.clone();
        let log_packets = opts.log_packets;
        let prog = progress[i].clone();
        set.spawn(async move {
            (
                i,
                run_flow_with_progress(session, i as u32 + 1, f, log, log_packets, stop, prog)
                    .await,
            )
        });
    }
    let mut results: Vec<Option<Result<FlowOutcome>>> = (0..flows.len()).map(|_| None).collect();

    let mut tracks: Vec<FlowTrack> = flows.iter().map(|_| FlowTrack::default()).collect();
    let interval = opts.interval;
    let mut on_interval = opts.on_interval.take();
    let started = Instant::now();
    let mut clock = IntervalClock {
        started,
        last: started,
        index: 0,
        poll_ok: true,
    };
    let period = interval.unwrap_or(Duration::from_secs(365 * 24 * 3600));
    let mut ticker = interval_at(started + period, period);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            r = set.join_next() => {
                let Some(r) = r else { break };
                let (i, res) = r.map_err(|e| Error::Protocol(format!("flow task failed: {e}")))?;
                results[i] = Some(res);
            }
            _ = ticker.tick(), if interval.is_some() => {
                let rep = interval_tick(session, &mut clock, &flows, &progress, &mut tracks, ctl.as_mut(), opts.limits.as_ref()).await;
                if let Some(cb) = on_interval.as_mut() {
                    cb(&rep);
                }
            }
        }
    }

    let mut out = SessionResult {
        session,
        ..Default::default()
    };

    // Ask the receiver for its view.
    let mut remote = Vec::new();
    if let Some(s) = ctl.as_mut() {
        write_msg(
            s,
            &ClientMsg::Done {
                session,
                grace_ms: opts.grace.as_millis() as u64,
            },
        )
        .await?;
        let reply = timeout(opts.grace + Duration::from_secs(10), async {
            loop {
                match read_msg::<_, ServerMsg>(s).await {
                    // a poll answer that arrived late
                    Ok(Some(ServerMsg::Window { .. })) => continue,
                    other => return other,
                }
            }
        })
        .await;
        match reply {
            Ok(Ok(Some(ServerMsg::Report { flows, .. }))) => remote = flows,
            Ok(Ok(other)) => out
                .warnings
                .push(format!("unexpected control reply: {other:?}")),
            Ok(Err(e)) => out.warnings.push(format!("control channel error: {e}")),
            Err(_) => out
                .warnings
                .push("timed out waiting for receiver report".into()),
        }
    }

    for (i, res) in results.into_iter().enumerate() {
        let flow_id = i as u32 + 1;
        match res.expect("every flow reports a result") {
            Ok(o) => {
                if o.send_errors > 0 {
                    out.warnings.push(format!(
                        "flow {flow_id} ({}): {} UDP send errors (is anything listening?)",
                        o.name, o.send_errors
                    ));
                }
                let rx = remote
                    .iter()
                    .find(|r| r.flow == flow_id)
                    .map(|r| r.summary.clone())
                    .filter(|s| s.packets > 0);
                let mut all_rtts = std::mem::take(&mut tracks[i].kept_rtts);
                all_rtts.extend_from_slice(&o.rtts_ms);
                let rtt = rtt_summary(&all_rtts);
                let lost_vs_tx = match (&rx, o.proto) {
                    (Some(s), _) => Some(o.sent.saturating_sub(s.packets)),
                    (None, Proto::Icmp) => None,
                    (None, _) if opts.control.is_some() => Some(o.sent),
                    // round-trip flows: loss is unanswered probes
                    (None, _) if rtt.is_some() && flows[i].wire != crate::flow::Wire::Rtp => {
                        Some(o.sent.saturating_sub(all_rtts.len() as u64))
                    }
                    _ => None,
                };
                let mut report = FlowReport {
                    session,
                    flow: flow_id,
                    name: o.name.clone(),
                    proto: o.proto.as_str().into(),
                    sent: Some(o.sent),
                    sent_bytes: Some(o.bytes),
                    late: Some(o.late),
                    rx,
                    rtt,
                    lost_vs_tx,
                    reverse: o.reverse.clone(),
                    verdict: None,
                };
                report.verdict = opts.limits.as_ref().map(|l| l.judge_report(&report));
                out.reports.push(report);
            }
            Err(e) => out
                .errors
                .push(format!("flow {flow_id} ({}) failed: {e}", flows[i].name)),
        }
    }
    Ok(out)
}

/// Ask a remote agent (a receiver started with `--allow-launch`) to generate `flows` from its
/// own host. Dropping `stop`'s sender side or flipping it to `true` aborts the remote run.
pub async fn remote_launch(
    agent: &str,
    key: Option<&[u8]>,
    flows: Vec<FlowSpec>,
    far_control: Option<String>,
    mut stop: watch::Receiver<bool>,
) -> Result<SessionResult> {
    let mut s = connect_control(agent, key).await?;
    write_msg(
        &mut s,
        &ClientMsg::Launch {
            flows,
            control: far_control,
        },
    )
    .await?;
    let reply = tokio::select! {
        r = read_msg::<_, ServerMsg>(&mut s) => r.map_err(friendly_reply_error)?,
        _ = stop.changed() => {
            // closing the connection tells the agent to abort
            return Err(Error::Protocol("interrupted; remote run aborted".into()));
        }
    };
    match reply {
        Some(ServerMsg::LaunchReport { reports, errors }) => Ok(SessionResult {
            session: reports.first().map(|r| r.session).unwrap_or(0),
            reports,
            errors,
            warnings: Vec::new(),
        }),
        Some(ServerMsg::Error { message }) => {
            Err(Error::Protocol(format!("agent refused launch: {message}")))
        }
        _ => Err(Error::Protocol("unexpected reply from agent".into())),
    }
}
