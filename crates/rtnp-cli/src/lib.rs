//! Shared helpers for the rtnp command line tools.

use std::fmt::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

use rtnp_core::client::IntervalReport;
use rtnp_core::report::FlowReport;
use rtnp_core::stats::Summary;

pub fn parse_duration(s: &str) -> Result<Duration, String> {
    humantime::parse_duration(s).map_err(|e| e.to_string())
}

pub fn fmt_summary(out: &mut String, s: &Summary, indent: &str) {
    fmt_summary_as(out, s, indent, "rx");
}

/// Like [`fmt_summary`] with a custom label (e.g. `reverse rx` for the return stream).
pub fn fmt_summary_as(out: &mut String, s: &Summary, indent: &str, label: &str) {
    let _ = writeln!(
        out,
        "{indent}{label}: packets={} bytes={} duration={:.3}s bitrate={:.1} kbit/s rate={:.1} pps",
        s.packets, s.bytes, s.duration_s, s.bitrate_kbps, s.pps
    );
    let _ = writeln!(
        out,
        "{indent}    delay{} min/avg/max/sd = {:.3}/{:.3}/{:.3}/{:.3} ms",
        if s.delay_relative {
            " (relative to first packet)"
        } else {
            ""
        },
        s.delay_min_ms,
        s.delay_avg_ms,
        s.delay_max_ms,
        s.delay_stddev_ms
    );
    let _ = writeln!(
        out,
        "{indent}    jitter mean|D|={:.3} ms rfc3550={:.3} ms",
        s.jitter_ms, s.jitter_rfc3550_ms
    );
    let _ = writeln!(
        out,
        "{indent}    seq-gap loss={} ({:.2}%) reordered={}",
        s.lost, s.loss_pct, s.reordered
    );
    if let Some(t) = s.tos {
        let _ = writeln!(
            out,
            "{indent}    marking seen: tos=0x{t:02x} dscp={}",
            t >> 2
        );
    }
}

/// One block per interval report: a header line and one line per flow.
pub fn fmt_interval(r: &IntervalReport) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "[{:>8.1}s] interval {} ({:.2}s)",
        r.elapsed_s, r.index, r.interval_s
    );
    for f in &r.flows {
        let name = if f.name.is_empty() { "-" } else { &f.name };
        let _ = write!(
            out,
            "  {} {} tx={} pkts {:.1} kbit/s",
            name, f.proto, f.sent, f.tx_kbps
        );
        if let Some(rx) = &f.rx {
            let _ = write!(
                out,
                " | rx={} pkts {:.1} kbit/s delay avg/max={:.3}/{:.3} ms jitter={:.3} ms",
                rx.packets, rx.bitrate_kbps, rx.delay_avg_ms, rx.delay_max_ms, rx.jitter_ms
            );
        }
        if let Some(rtt) = &f.rtt {
            let _ = write!(
                out,
                " | rtt n={} min/avg/max={:.3}/{:.3}/{:.3} ms",
                rtt.count, rtt.min_ms, rtt.avg_ms, rtt.max_ms
            );
        }
        if let (Some(lost), Some(pct)) = (f.lost, f.loss_pct) {
            let _ = write!(out, " | lost={lost} ({pct:.2}%)");
        }
        if let Some(rev) = &f.reverse {
            let _ = write!(
                out,
                " | reverse rx={} pkts {:.1} kbit/s jitter={:.3} ms",
                rev.packets, rev.bitrate_kbps, rev.jitter_rfc3550_ms
            );
            if let (Some(lost), Some(pct)) = (f.reverse_lost, f.reverse_loss_pct) {
                let _ = write!(out, " lost={lost} ({pct:.2}%)");
            }
        }
        if let Some(v) = &f.verdict {
            let _ = write!(out, " | {}", v.label());
            for m in &v.failures {
                let _ = write!(out, " ({m})");
            }
        }
        out.push('\n');
    }
    out
}

pub fn fmt_report(r: &FlowReport) -> String {
    let mut out = String::new();
    let name = if r.name.is_empty() { "-" } else { &r.name };
    let proto = if r.proto.is_empty() { "-" } else { &r.proto };
    let _ = writeln!(
        out,
        "Flow {} (session {:08x}) name={} proto={}",
        r.flow, r.session, name, proto
    );
    if let Some(sent) = r.sent {
        let _ = writeln!(
            out,
            "  tx: packets={} bytes={} late={}",
            sent,
            r.sent_bytes.unwrap_or(0),
            r.late.map(|l| l.to_string()).unwrap_or_else(|| "?".into())
        );
    }
    if let Some(rx) = &r.rx {
        fmt_summary(&mut out, rx, "  ");
    }
    if let Some(rev) = &r.reverse {
        fmt_summary_as(&mut out, rev, "  ", "reverse (receiver to sender)");
    }
    if let Some(rtt) = &r.rtt {
        let _ = writeln!(
            out,
            "  rtt: probes={} min/avg/max = {:.3}/{:.3}/{:.3} ms jitter={:.3} ms",
            rtt.count, rtt.min_ms, rtt.avg_ms, rtt.max_ms, rtt.jitter_ms
        );
    }
    if let Some(lost) = r.lost_vs_tx {
        let pct = match r.sent {
            Some(s) if s > 0 => lost as f64 * 100.0 / s as f64,
            _ => 0.0,
        };
        let _ = writeln!(out, "  loss vs tx: {} ({:.2}%)", lost, pct);
    }
    if let Some(v) = &r.verdict {
        let _ = writeln!(out, "  verdict: {}", v.label());
        for m in &v.failures {
            let _ = writeln!(out, "    - {m}");
        }
        for m in &v.notes {
            let _ = writeln!(out, "    (not checked: {m})");
        }
    }
    out
}

/// Resolve the shared key from `--key` / `RTNP_KEY` or `--key-file`. Prefer the environment
/// variable or a file over `--key`, which is visible in the process list.
pub fn load_key(key: &Option<String>, file: &Option<PathBuf>) -> anyhow::Result<Option<Vec<u8>>> {
    let raw = match (key, file) {
        (Some(_), Some(_)) => anyhow::bail!("use either --key or --key-file, not both"),
        (Some(k), None) => k.clone().into_bytes(),
        (None, Some(f)) => read_key_file(f)?,
        (None, None) => return Ok(None),
    };
    if raw.len() < 8 {
        anyhow::bail!("the shared key must be at least 8 bytes long");
    }
    Ok(Some(raw))
}

fn read_key_file(path: &Path) -> anyhow::Result<Vec<u8>> {
    let mut data = std::fs::read(path)
        .map_err(|e| anyhow::anyhow!("cannot read key file {}: {e}", path.display()))?;
    while data.last().is_some_and(|b| *b == b'\n' || *b == b'\r') {
        data.pop();
    }
    Ok(data)
}
