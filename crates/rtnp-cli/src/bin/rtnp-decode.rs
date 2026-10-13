use std::path::PathBuf;

use anyhow::{Result, bail};
use clap::{Parser, ValueEnum};
use rtnp_cli::fmt_report;
use rtnp_core::log::read_records;
use rtnp_core::report::{aggregate, interval_series};

#[derive(Clone, Copy, ValueEnum)]
enum Format {
    Text,
    Json,
    Csv,
}

/// Decode rtnp JSONL logs into per-flow statistics.
///
/// Pass sender and receiver logs together to get loss measured against what was actually
/// sent. One-way delay is only meaningful when both hosts' clocks are synchronised.
#[derive(Parser)]
#[command(version, about)]
struct Args {
    /// One or more JSONL log files
    #[arg(required = true)]
    logs: Vec<PathBuf>,
    #[arg(long, short = 'f', value_enum, default_value = "text")]
    format: Format,
    /// Emit a time series with this bucket size in milliseconds instead of totals
    #[arg(long, short = 'i')]
    interval: Option<u64>,
    /// Only this flow id
    #[arg(long)]
    flow: Option<u32>,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let mut records = Vec::new();
    for p in &args.logs {
        records.extend(read_records(p)?);
    }
    if records.is_empty() {
        bail!("no records found");
    }

    if let Some(ms) = args.interval {
        if ms == 0 {
            bail!("--interval must be at least 1 ms");
        }
        let rows = interval_series(&records, ms, args.flow);
        match args.format {
            Format::Json => println!("{}", serde_json::to_string_pretty(&rows)?),
            Format::Csv => {
                println!("session,flow,t_ms,packets,bitrate_kbps,pps,delay_avg_ms,jitter_ms");
                for r in rows {
                    println!(
                        "{:08x},{},{:.1},{},{:.3},{:.3},{:.6},{:.6}",
                        r.session,
                        r.flow,
                        r.t_ms,
                        r.packets,
                        r.bitrate_kbps,
                        r.pps,
                        r.delay_avg_ms,
                        r.jitter_ms
                    );
                }
            }
            Format::Text => {
                println!(
                    "{:<9} {:>4} {:>10} {:>8} {:>12} {:>9} {:>10} {:>10}",
                    "session", "flow", "t_ms", "packets", "kbit/s", "pps", "delay_ms", "jitter_ms"
                );
                for r in rows {
                    println!(
                        "{:<9x} {:>4} {:>10.1} {:>8} {:>12.1} {:>9.1} {:>10.3} {:>10.3}",
                        r.session,
                        r.flow,
                        r.t_ms,
                        r.packets,
                        r.bitrate_kbps,
                        r.pps,
                        r.delay_avg_ms,
                        r.jitter_ms
                    );
                }
            }
        }
        return Ok(());
    }

    let reports = aggregate(&records, args.flow);
    match args.format {
        Format::Json => println!("{}", serde_json::to_string_pretty(&reports)?),
        Format::Csv => {
            println!(
                "session,flow,name,proto,sent,rx_packets,rx_bytes,lost,loss_pct,bitrate_kbps,pps,delay_avg_ms,delay_max_ms,jitter_ms"
            );
            for r in &reports {
                let (rp, rb, bl, pps, da, dm, j) = match &r.rx {
                    Some(s) => (
                        s.packets,
                        s.bytes,
                        s.bitrate_kbps,
                        s.pps,
                        s.delay_avg_ms,
                        s.delay_max_ms,
                        s.jitter_ms,
                    ),
                    None => (0, 0, 0.0, 0.0, 0.0, 0.0, 0.0),
                };
                let lost = r.lost_vs_tx.or(r.rx.as_ref().map(|s| s.lost)).unwrap_or(0);
                let loss_pct = match r.sent {
                    Some(s) if s > 0 => lost as f64 * 100.0 / s as f64,
                    _ => r.rx.as_ref().map(|s| s.loss_pct).unwrap_or(0.0),
                };
                println!(
                    "{:08x},{},{},{},{},{},{},{},{:.3},{:.3},{:.3},{:.6},{:.6},{:.6}",
                    r.session,
                    r.flow,
                    r.name,
                    r.proto,
                    r.sent.map(|s| s.to_string()).unwrap_or_default(),
                    rp,
                    rb,
                    lost,
                    loss_pct,
                    bl,
                    pps,
                    da,
                    dm,
                    j
                );
            }
        }
        Format::Text => {
            for r in &reports {
                print!("{}", fmt_report(r));
            }
        }
    }
    Ok(())
}
