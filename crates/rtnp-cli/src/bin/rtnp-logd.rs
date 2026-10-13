use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Parser;
use rtnp_cli::load_key;
use rtnp_core::logd::{LogdConfig, serve};
use tokio::net::TcpListener;

/// Central log server: collects JSONL streams from rtnp-send / rtnp-recv (--log-server).
/// One file per connection is written to the output directory; decode them with rtnp-decode.
#[derive(Parser)]
#[command(version, about)]
struct Args {
    #[arg(long, default_value = "0.0.0.0:9000")]
    listen: String,
    #[arg(long, default_value = "rtnp-logs")]
    out_dir: PathBuf,
    /// Require clients to authenticate with this key (prefer RTNP_KEY or --key-file)
    #[arg(long, env = "RTNP_KEY", hide_env_values = true)]
    key: Option<String>,
    #[arg(long)]
    key_file: Option<PathBuf>,
    /// Cut each connection off after this many bytes
    #[arg(long, default_value_t = 1024 * 1024 * 1024)]
    max_bytes_per_conn: u64,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let key = load_key(&args.key, &args.key_file)?;
    std::fs::create_dir_all(&args.out_dir)
        .with_context(|| format!("cannot create {}", args.out_dir.display()))?;
    let listener = TcpListener::bind(&args.listen)
        .await
        .with_context(|| format!("cannot listen on {}", args.listen))?;
    eprintln!(
        "log server on {} writing to {} ({})",
        listener.local_addr()?,
        args.out_dir.display(),
        if key.is_some() {
            "authenticated"
        } else {
            "WARNING: unauthenticated, set --key"
        }
    );
    let cfg = LogdConfig {
        out_dir: args.out_dir,
        key,
        max_bytes_per_conn: args.max_bytes_per_conn,
        on_event: Arc::new(|m| eprintln!("{m}")),
    };
    tokio::select! {
        r = serve(listener, cfg) => r.context("log server failed"),
        _ = tokio::signal::ctrl_c() => Ok(()),
    }
}
