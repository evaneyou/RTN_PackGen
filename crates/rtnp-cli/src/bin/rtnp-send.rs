use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand};
use rtnp_cli::{fmt_interval, fmt_report, load_key, parse_duration};
use rtnp_core::client::{SessionOptions, remote_launch, run_session};
use rtnp_core::dist::Dist;
use rtnp_core::flow::{
    Codec, FlowSpec, Meter, Payload, Proto, ResolvedFlow, Script, VideoSpec, Wire,
};
use rtnp_core::log::LogSink;
use rtnp_core::preset;
use rtnp_core::verdict::{CallMetrics, Outcome, QualityLimits, compare as compare_calls};
use tokio::sync::watch;

/// Generate traffic towards a rtnp-recv instance (or any UDP/TCP sink).
#[derive(Parser)]
#[command(version, about)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
#[allow(clippy::large_enum_variant)] // one-shot CLI parse, size is irrelevant
enum Cmd {
    /// Run every [[flow]] in a TOML script concurrently
    Run {
        script: PathBuf,
        #[command(flatten)]
        common: Common,
    },
    /// Run a single flow described on the command line
    Flow(FlowArgs),
    /// List built-in traffic presets
    Presets,
    /// Print a fresh random SRTP master key (60 hex characters)
    SrtpKey,
    /// Test whether a priority queue protects voice: run the same call marked (EF) and unmarked
    /// under identical background load and compare them
    Compare(CompareArgs),
}

#[derive(Args)]
struct CompareArgs {
    /// Receiver UDP address (host:port)
    #[arg(long, short = 't')]
    target: String,
    /// Receiver control channel (host:port); needed for receiver-side jitter, loss and DSCP
    #[arg(long, short = 'c')]
    control: String,
    #[arg(long, env = "RTNP_KEY", hide_env_values = true)]
    key: Option<String>,
    #[arg(long)]
    key_file: Option<PathBuf>,
    /// Length of each phase
    #[arg(long, short = 'd', default_value = "20s", value_parser = parse_duration)]
    duration: Duration,
    /// Background load in kbit/s (UDP, unmarked), sent alongside the call in both phases.
    /// It has to be enough to congest the bottleneck link, or the result is inconclusive
    #[arg(long, default_value_t = 10_000.0)]
    background_kbps: f64,
    /// Background packet size in bytes (keep below the path MTU; WireGuard is ~1420)
    #[arg(long, default_value_t = 1200)]
    background_size: u32,
    /// DSCP to mark the call with in the protected phase (46 = EF)
    #[arg(long, default_value_t = 46)]
    dscp: u8,
    /// Codec: g711, g711a, g729 or g723
    #[arg(long, default_value = "g711a")]
    codec: Codec,
    /// Packetisation time in ms
    #[arg(long, default_value_t = 20.0)]
    ptime: f64,
    /// Make it a two-way call (receiver needs --allow-reverse); also checks the return marking
    #[arg(long)]
    bidir: bool,
    /// Also measure the call with no background load first
    #[arg(long)]
    baseline: bool,
    /// Pause between phases so queues drain
    #[arg(long, default_value = "3s", value_parser = parse_duration)]
    pause: Duration,
    /// How long the receiver waits for in-flight packets before reporting
    #[arg(long, default_value = "500ms", value_parser = parse_duration)]
    grace: Duration,
    /// Print JSON instead of a table
    #[arg(long)]
    json: bool,
}

#[derive(Args, Clone)]
struct Common {
    /// Receiver control channel (host:port); enables the end-of-run report from the receiver
    #[arg(long, short = 'c')]
    control: Option<String>,
    /// Shared key for the control channel and log server (prefer RTNP_KEY or --key-file)
    #[arg(long, env = "RTNP_KEY", hide_env_values = true)]
    key: Option<String>,
    /// Read the shared key from a file
    #[arg(long)]
    key_file: Option<PathBuf>,
    /// Write JSONL records to this file
    #[arg(long, short = 'l')]
    log: Option<PathBuf>,
    /// Stream JSONL records to a rtnp-logd server (host:port)
    #[arg(long, conflicts_with = "log")]
    log_server: Option<String>,
    /// Name for this stream on the log server
    #[arg(long, default_value = "sender")]
    log_tag: String,
    /// Also log every transmitted packet (larger logs)
    #[arg(long)]
    log_packets: bool,
    /// Run the flows from a remote agent (a rtnp-recv started with --allow-launch) instead of
    /// from this host. --control then names the far end's control channel, as seen from the agent
    #[arg(long)]
    agent: Option<String>,
    /// Print results as JSON (with --interval: one JSON object per line, ending with a
    /// {"type":"final"} line)
    #[arg(long)]
    json: bool,
    /// Print a rolling summary this often while the flows run, e.g. 10s (default 10s with
    /// --forever). Needs --control for receiver-side numbers (delay, jitter, loss)
    #[arg(long, short = 'i', value_parser = parse_duration)]
    interval: Option<Duration>,
    /// How long the receiver waits for in-flight packets before reporting
    #[arg(long, default_value = "500ms", value_parser = parse_duration)]
    grace: Duration,
    /// Fail (exit status 3) if the mean round trip exceeds this many ms. Voice needs about
    /// 300 ms round trip for ITU-T G.114's 150 ms one-way budget
    #[arg(long)]
    max_rtt: Option<f64>,
    /// Fail if RFC 3550 jitter (worst direction) exceeds this many ms (voice: 30)
    #[arg(long)]
    max_jitter: Option<f64>,
    /// Fail if packet loss (worst direction) exceeds this percentage
    #[arg(long)]
    max_loss: Option<f64>,
    /// Fail if the DSCP seen by the receiver differs (EF is 46); catches marking being
    /// rewritten on the path
    #[arg(long)]
    expect_dscp: Option<u8>,
}

impl Common {
    fn limits(&self) -> Result<Option<QualityLimits>> {
        let l = QualityLimits {
            max_rtt_ms: self.max_rtt,
            max_jitter_ms: self.max_jitter,
            max_loss_pct: self.max_loss,
            expect_dscp: self.expect_dscp,
        };
        l.validate().map_err(|e| anyhow::anyhow!(e))?;
        Ok((!l.is_empty()).then_some(l))
    }
}

#[derive(Args)]
struct FlowArgs {
    /// host:port (host for ICMP)
    #[arg(long, short = 't')]
    target: String,
    #[arg(long)]
    name: Option<String>,
    /// udp, tcp, icmp or sctp
    #[arg(long, short = 'p')]
    proto: Option<Proto>,
    /// Built-in preset, see `rtnp-send presets`
    #[arg(long)]
    preset: Option<String>,
    /// Inter-departure time in ms: 20, const:20, exp:50, normal:50,5, pareto:30,1.5
    #[arg(long)]
    idt: Option<Dist>,
    /// Packet size in bytes (same syntax as --idt)
    #[arg(long)]
    size: Option<Dist>,
    /// Constant packets per second (alternative to --idt)
    #[arg(long)]
    rate_pps: Option<f64>,
    /// Flow duration, e.g. 10s, 500ms, 2m (default 10s if no other limit is given)
    #[arg(long, short = 'd', value_parser = parse_duration)]
    duration: Option<Duration>,
    /// Stop after this many packets
    #[arg(long)]
    count: Option<u64>,
    /// Stop after this many bytes
    #[arg(long)]
    max_bytes: Option<u64>,
    /// Keep going until interrupted (Ctrl-C); incompatible with -d/--count/--max-bytes
    #[arg(long)]
    forever: bool,
    #[arg(long)]
    ttl: Option<u32>,
    #[arg(long)]
    tos: Option<u8>,
    /// Seed for reproducible traffic patterns
    #[arg(long)]
    seed: Option<u64>,
    /// owd (one-way delay, default) or rtt (the receiver reflects packets)
    #[arg(long)]
    meter: Option<Meter>,
    /// Packet body: zero (default), random, pattern:<hex> or file:<path>
    #[arg(long)]
    payload: Option<Payload>,
    /// Write an RTP header for this codec: g711 (µ-law), g711a (A-law), g729, g723 (UDP only)
    #[arg(long)]
    rtp: Option<Codec>,
    /// Packetisation time in ms for --rtp voice, e.g. 20 or 30 (sets interval and size)
    #[arg(long)]
    ptime: Option<f64>,
    /// Two-way call: the receiver (started with --allow-reverse) sends its own constant stream
    /// back, and the report covers both directions. Needs --wire rtp, --rtp and --control
    #[arg(long)]
    bidir: bool,
    /// Voice-activity detection: alternate talkspurts and silences
    #[arg(long)]
    vad: bool,
    /// Talkspurt length in ms (distribution syntax, default exp:1004)
    #[arg(long)]
    vad_talk: Option<Dist>,
    /// Silence length in ms (distribution syntax, default exp:1587)
    #[arg(long)]
    vad_silence: Option<Dist>,
    /// Wire format: rtnp (our measurement header, default) or rtp (plain RTP, UDP only; needs
    /// --rtp or --video)
    #[arg(long)]
    wire: Option<Wire>,
    /// Synthetic video stream over plain RTP (see --video-*)
    #[arg(long)]
    video: bool,
    /// Video frames per second (default 30)
    #[arg(long, requires = "video")]
    video_fps: Option<f64>,
    /// Frames per group of pictures: one I-frame, the rest P-frames (default 30)
    #[arg(long, requires = "video")]
    video_gop: Option<u32>,
    /// I-frame size in bytes (distribution syntax, default normal:30000,3000)
    #[arg(long, requires = "video")]
    video_i_size: Option<Dist>,
    /// P-frame size in bytes (distribution syntax, default normal:4000,1200)
    #[arg(long, requires = "video")]
    video_p_size: Option<Dist>,
    /// Maximum RTP payload per packet in bytes (default 1200)
    #[arg(long, requires = "video")]
    video_payload: Option<usize>,
    /// RTCP sender-report period for --wire rtp, e.g. 1s (default 5s) or 0 to turn RTCP off. The
    /// receiver's answers give a standard round-trip time
    #[arg(long, value_parser = parse_duration)]
    rtcp_interval: Option<Duration>,
    /// Set the RTP marker bit on the first packet (plain-RTP voice), as most phones do
    #[arg(long)]
    first_marker: bool,
    /// Encrypt the RTP stream with SRTP (AES_CM_128_HMAC_SHA1_80). The 30-byte master key and
    /// salt as 60 hex or 40 base64 characters; make one with `rtnp-send srtp-key`. Prefer
    /// RTNP_SRTP_KEY or --srtp-key-file over this flag, which shows in the process list.
    /// Needs --wire rtp; the receiver must use the same key.
    #[arg(long, env = "RTNP_SRTP_KEY", hide_env_values = true)]
    srtp_key: Option<String>,
    /// Read the SRTP master key from a file
    #[arg(long)]
    srtp_key_file: Option<PathBuf>,
    /// Set the call up with SIP first (INVITE, ACK, BYE) with an SDP offer. The target is then the
    /// receiver's SIP port (rtnp-recv --sip-port) and media goes to the port in its answer.
    /// Plain-RTP voice only
    #[arg(long)]
    sip: bool,
    /// With --sip: encrypt with SRTP using a fresh random key sent in the SDP (SDES)
    #[arg(long, requires = "sip", conflicts_with_all = ["srtp_key", "srtp_key_file"])]
    srtp: bool,
    #[command(flatten)]
    common: Common,
}

#[tokio::main]
async fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::Presets => {
            for p in preset::all() {
                println!("{:<16} {:<4} {}", p.name, p.proto.as_str(), p.description);
            }
            Ok(())
        }
        Cmd::SrtpKey => {
            println!("{}", rtnp_core::srtp::MasterKey::random().to_hex());
            Ok(())
        }
        Cmd::Compare(a) => compare(a).await,
        Cmd::Run { script, common } => {
            let text = std::fs::read_to_string(&script)
                .with_context(|| format!("cannot read {}", script.display()))?;
            let script = Script::from_toml(&text)?;
            execute(script.flow, common).await
        }
        Cmd::Flow(a) => {
            let video = a.video.then(|| {
                let d = VideoSpec::default();
                VideoSpec {
                    fps: a.video_fps.unwrap_or(d.fps),
                    gop: a.video_gop.unwrap_or(d.gop),
                    i_bytes: a.video_i_size.unwrap_or(d.i_bytes),
                    p_bytes: a.video_p_size.unwrap_or(d.p_bytes),
                    payload_bytes: a.video_payload.unwrap_or(d.payload_bytes),
                    payload_type: d.payload_type,
                }
            });
            let spec = FlowSpec {
                wire: a.wire,
                video,
                ptime_ms: a.ptime,
                bidirectional: a.bidir,
                name: a.name,
                proto: a.proto,
                target: a.target,
                preset: a.preset,
                idt_ms: a.idt,
                size: a.size,
                rate_pps: a.rate_pps,
                duration_ms: a.duration.map(|d| d.as_millis() as u64),
                count: a.count,
                max_bytes: a.max_bytes,
                forever: a.forever,
                start_delay_ms: 0,
                ttl: a.ttl,
                tos: a.tos,
                seed: a.seed,
                meter: a.meter,
                payload: a.payload,
                rtp: a.rtp,
                vad: a.vad,
                vad_talk_ms: a.vad_talk,
                vad_silence_ms: a.vad_silence,
                rtcp_interval_ms: a.rtcp_interval.map(|d| d.as_millis() as u64),
                first_marker: a.first_marker,
                sip: a.sip,
                srtp: a.srtp,
                srtp_key: rtnp_core::srtp::load_key(
                    a.srtp_key.as_deref(),
                    a.srtp_key_file.as_deref(),
                )?,
            };
            execute(vec![spec], a.common).await
        }
    }
}

/// Write to stdout; if the reader has gone away (closed pipe), stop instead of running unobserved.
fn emit(text: String) {
    use std::io::Write;
    let mut out = std::io::stdout().lock();
    if out
        .write_all(text.as_bytes())
        .and_then(|_| out.flush())
        .is_err()
    {
        eprintln!("stdout closed: exiting");
        std::process::exit(1);
    }
}

async fn execute(specs: Vec<FlowSpec>, mut c: Common) -> Result<()> {
    let key = load_key(&c.key, &c.key_file)?;
    let limits = c.limits()?;
    if limits.is_some() && c.agent.is_some() {
        bail!("--max-rtt/--max-jitter/--max-loss/--expect-dscp are not supported with --agent");
    }
    if c.agent.is_some() && specs.iter().any(|s| s.srtp_key.is_some()) {
        bail!("SRTP keys are not sent to remote agents: run SRTP flows from this host");
    }
    let forever = specs.iter().any(|s| s.forever);
    if forever && c.interval.is_none() {
        c.interval = Some(Duration::from_secs(10));
    }
    if let Some(i) = c.interval
        && i < Duration::from_millis(100)
    {
        bail!("--interval must be at least 100ms");
    }
    if c.agent.is_some() && (forever || c.interval.is_some()) {
        bail!("--forever and --interval are not supported with --agent");
    }

    // Ctrl-C asks flows (local or remote) to stop early.
    let (stop_tx, stop_rx) = watch::channel(false);
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        eprintln!("interrupted: stopping flows");
        let _ = stop_tx.send(true);
        std::future::pending::<()>().await; // keep the sender alive
    });

    let result = if let Some(agent) = &c.agent {
        if c.log.is_some() || c.log_server.is_some() {
            bail!(
                "--log / --log-server cannot be combined with --agent (the agent runs the flows)"
            );
        }
        // validate locally first for a quicker error message
        for (i, s) in specs.iter().enumerate() {
            s.resolve(i)
                .map_err(|e| anyhow::anyhow!("invalid flow {}: {e}", i + 1))?;
        }
        remote_launch(agent, key.as_deref(), specs, c.control.clone(), stop_rx).await?
    } else {
        let flows: Vec<ResolvedFlow> = specs
            .iter()
            .enumerate()
            .map(|(i, s)| s.resolve(i))
            .collect::<Result<_, _>>()
            .context("invalid flow")?;
        let sink = match (&c.log, &c.log_server) {
            (Some(p), _) => LogSink::to_file(p)
                .await
                .with_context(|| format!("cannot open log {}", p.display()))?,
            (None, Some(addr)) => LogSink::to_remote(addr, &c.log_tag, key.as_deref())
                .await
                .with_context(|| format!("cannot reach log server {addr}"))?,
            (None, None) => LogSink::none(),
        };
        let mut opts = SessionOptions::new(sink.handle());
        opts.control = c.control.clone();
        opts.key = key.clone();
        opts.log_packets = c.log_packets;
        opts.grace = c.grace;
        opts.limits = limits;
        if let Some(every) = c.interval {
            opts.interval = Some(every);
            let json = c.json;
            opts.on_interval = Some(Box::new(move |r| {
                if json {
                    match serde_json::to_value(r) {
                        Ok(mut v) => {
                            v["type"] = "interval".into();
                            emit(format!("{v}\n"));
                        }
                        Err(e) => eprintln!("warning: cannot encode interval report: {e}"),
                    }
                } else {
                    emit(fmt_interval(r));
                }
                for w in &r.warnings {
                    eprintln!("warning: {w}");
                }
            }));
        }
        let run = run_session(flows, opts, stop_rx).await;
        let closed = sink.close().await;
        let res = run?;
        match closed {
            Ok(0) => {}
            Ok(dropped) => {
                eprintln!("warning: {dropped} log records dropped (disk or network too slow)")
            }
            Err(e) => eprintln!("warning: log delivery failed: {e}"),
        }
        res
    };

    for w in &result.warnings {
        eprintln!("warning: {w}");
    }
    for e in &result.errors {
        eprintln!("{e}");
    }
    if c.json && c.interval.is_some() {
        println!(
            "{}",
            serde_json::json!({
                "type": "final",
                "session": result.session,
                "flows": result.reports,
            })
        );
    } else if c.json {
        println!("{}", serde_json::to_string_pretty(&result.reports)?);
    } else {
        println!("session {:08x}", result.session);
        for r in &result.reports {
            print!("{}", fmt_report(r));
        }
    }
    if !result.errors.is_empty() {
        bail!("one or more flows failed");
    }
    if result
        .reports
        .iter()
        .any(|r| r.verdict.as_ref().is_some_and(|v| !v.pass))
    {
        eprintln!("quality limits exceeded");
        std::process::exit(3);
    }
    Ok(())
}

/// One measured phase of `compare`.
struct Phase {
    label: String,
    metrics: CallMetrics,
    report: rtnp_core::report::FlowReport,
}

async fn compare(a: CompareArgs) -> Result<()> {
    if a.dscp > 63 {
        bail!("--dscp must be 0-63");
    }
    if a.duration < Duration::from_secs(5) {
        bail!("--duration must be at least 5s for a meaningful comparison");
    }
    if !(a.background_kbps.is_finite() && a.background_kbps > 0.0 && a.background_size >= 100) {
        bail!("--background-kbps must be positive and --background-size at least 100");
    }
    let key = load_key(&a.key, &a.key_file)?;
    let (stop_tx, stop_rx) = watch::channel(false);
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        eprintln!("interrupted: stopping");
        let _ = stop_tx.send(true);
        std::future::pending::<()>().await;
    });

    let marked = a.dscp << 2;
    let plan: Vec<(String, bool, u8)> = a
        .baseline
        .then(|| ("baseline (no load)".to_string(), false, marked))
        .into_iter()
        .chain([
            (format!("marked DSCP {}", a.dscp), true, marked),
            ("unmarked".to_string(), true, 0),
        ])
        .collect();

    let mut phases: Vec<Phase> = Vec::new();
    for (i, (label, load, tos)) in plan.into_iter().enumerate() {
        if i > 0 {
            if *stop_rx.borrow() {
                bail!("interrupted");
            }
            tokio::time::sleep(a.pause).await;
        }
        eprintln!("phase: {label}");
        let ms = a.duration.as_millis() as u64;
        let mut specs = vec![FlowSpec {
            name: Some("voice".into()),
            target: a.target.clone(),
            wire: Some(rtnp_core::flow::Wire::Rtp),
            rtp: Some(a.codec),
            ptime_ms: Some(a.ptime),
            bidirectional: a.bidir,
            tos: Some(tos),
            duration_ms: Some(ms),
            ..Default::default()
        }];
        if load {
            specs.push(FlowSpec {
                name: Some("background".into()),
                proto: Some(Proto::Udp),
                target: a.target.clone(),
                size: Some(Dist::Constant {
                    value: a.background_size as f64,
                }),
                rate_pps: Some(a.background_kbps * 1000.0 / 8.0 / a.background_size as f64),
                tos: Some(0),
                duration_ms: Some(ms),
                ..Default::default()
            });
        }
        let flows: Vec<ResolvedFlow> = specs
            .iter()
            .enumerate()
            .map(|(i, s)| s.resolve(i))
            .collect::<Result<_, _>>()
            .context("invalid flow")?;
        let mut opts = SessionOptions::new(LogSink::none().handle());
        opts.control = Some(a.control.clone());
        opts.key = key.clone();
        opts.grace = a.grace;
        let res = run_session(flows, opts, stop_rx.clone()).await?;
        for e in &res.errors {
            eprintln!("{e}");
        }
        for w in &res.warnings {
            eprintln!("warning: {w}");
        }
        let report = res
            .reports
            .into_iter()
            .find(|r| r.name == "voice")
            .with_context(|| format!("no result for the call in phase '{label}'"))?;
        if report.rx.is_none() {
            bail!(
                "phase '{label}': the receiver reported nothing (is --control right and the receiver up?)"
            );
        }
        phases.push(Phase {
            label,
            metrics: CallMetrics::from_report(&report),
            report,
        });
    }

    let (baseline, ef, be) = match phases.as_slice() {
        [b, e, u] => (Some(b), e, u),
        [e, u] => (None, e, u),
        _ => unreachable!("two or three phases"),
    };
    let cmp = compare_calls(
        &ef.metrics,
        &be.metrics,
        baseline.map(|b| &b.metrics),
        a.dscp,
    );

    if a.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "phases": phases.iter().map(|p| serde_json::json!({
                    "label": p.label, "metrics": p.metrics, "report": p.report,
                })).collect::<Vec<_>>(),
                "comparison": cmp,
            }))?
        );
    } else {
        println!(
            "{:<20} {:>10} {:>10} {:>9} {:>8} {:>6}",
            "phase", "rtt avg ms", "rtt max ms", "jitter ms", "loss %", "dscp"
        );
        let f = |v: Option<f64>| v.map_or("-".to_string(), |v| format!("{v:.2}"));
        for p in &phases {
            let m = &p.metrics;
            println!(
                "{:<20} {:>10} {:>10} {:>9} {:>8} {:>6}",
                p.label,
                f(m.rtt_avg_ms),
                f(m.rtt_max_ms),
                f(m.jitter_ms),
                f(m.loss_pct),
                m.dscp_seen.map_or("-".to_string(), |d| d.to_string()),
            );
        }
        println!();
        let head = match cmp.outcome {
            Outcome::Protected => "PROTECTED: marked voice fared clearly better under load",
            Outcome::NotProtected => "NOT PROTECTED: marking did not shield voice from the load",
            Outcome::MarkingLost => "MARKING LOST: the DSCP did not survive the path",
            Outcome::Inconclusive => "INCONCLUSIVE: the load did not stress the path",
        };
        println!("{head}");
        for r in &cmp.reasons {
            println!("  - {r}");
        }
        if be.metrics.rtt_avg_ms.is_none() {
            println!("  (no round trip measured: RTCP answers did not arrive)");
        }
    }
    match cmp.outcome {
        Outcome::Protected => Ok(()),
        Outcome::Inconclusive => std::process::exit(4),
        _ => std::process::exit(3),
    }
}
