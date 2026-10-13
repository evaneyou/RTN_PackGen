//! ICMP echo flows. Reports round-trip time per probe (`rtt` log records).
//! Requires privileges for ICMP sockets (root/CAP_NET_RAW, or on Linux a suitable
//! `net.ipv4.ping_group_range`).

use std::sync::Arc;

use surge_ping::{Client, Config, ICMP, PingIdentifier, PingSequence};
use tokio::sync::{Semaphore, watch};

use crate::error::{Error, Result};
use crate::flow::{Proto, ResolvedFlow};
use crate::log::{LogHandle, LogRecord};
use crate::pacer::Pacer;
use crate::proto::HEADER_LEN;
use crate::sender::{FlowOutcome, FlowProgress, resolve_target};
use crate::time::now_ns;

const MAX_ICMP_PAYLOAD: usize = 1400;
const MAX_IN_FLIGHT: usize = 1024;

pub(crate) async fn run(
    session: u32,
    flow: u32,
    cfg: ResolvedFlow,
    log: LogHandle,
    mut stop: watch::Receiver<bool>,
    progress: Arc<FlowProgress>,
) -> Result<FlowOutcome> {
    // Accept "host", "host:port" or a bare IPv6 address; the port is ignored for ICMP.
    let addr = match resolve_target(&cfg.target).await {
        Ok(a) => a,
        Err(_) => resolve_target(&format!("{}:0", cfg.target)).await?,
    };
    let ip = addr.ip();

    let icmp_cfg = if ip.is_ipv6() {
        Config::builder().kind(ICMP::V6).build()
    } else {
        Config::default()
    };
    let client = Client::new(&icmp_cfg)
        .map_err(|e| Error::Config(format!("cannot open ICMP socket: {e}")))?;

    let mut pacer = Pacer::new(&cfg, HEADER_LEN, MAX_ICMP_PAYLOAD)?;
    let ident = rand::random::<u16>();
    let permits = Arc::new(Semaphore::new(MAX_IN_FLIGHT));
    let mut tasks: tokio::task::JoinSet<()> = tokio::task::JoinSet::new();

    log.send(LogRecord::FlowStart {
        session,
        flow,
        role: "tx".into(),
        name: cfg.name.clone(),
        proto: Proto::Icmp.as_str().into(),
        peer: ip.to_string(),
        t_ns: now_ns(),
    });

    pacer.restart();
    while let Some(size) = pacer.wait(&mut stop).await {
        let seq = pacer.seq;
        let payload = vec![0u8; size.saturating_sub(HEADER_LEN).max(8)];
        let permit = match permits.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                pacer.advance(size);
                progress.update(pacer.seq, pacer.bytes, pacer.late);
                continue; // too many probes outstanding; skip rather than stall pacing
            }
        };
        // Create the pinger here: dropping a cloned `Client` inside a task would shut the
        // shared receiver down for every other probe.
        let mut pinger = client
            .pinger(ip, PingIdentifier(ident.wrapping_add(seq as u16)))
            .await;
        pinger.timeout(std::time::Duration::from_secs(2));
        let log = log.clone();
        let progress_task = progress.clone();
        tasks.spawn(async move {
            let res = pinger.ping(PingSequence(seq as u16), &payload).await;
            if let Ok((_pkt, rtt)) = res {
                log.send(LogRecord::Rtt {
                    session,
                    flow,
                    seq,
                    size: (payload.len() + 8) as u32,
                    t_ns: now_ns(),
                    rtt_ns: rtt.as_nanos() as u64,
                });
                progress_task.push_rtt(seq, rtt.as_secs_f64() * 1000.0);
            } else {
                progress_task.mark_failed();
            }
            drop(permit);
        });
        pacer.advance(size);
        progress.update(pacer.seq, pacer.bytes, pacer.late);
        // reap finished probes so an endless run does not accumulate join results
        while tasks.try_join_next().is_some() {}
    }

    while tasks.join_next().await.is_some() {}

    log.send(LogRecord::FlowEnd {
        session,
        flow,
        t_ns: now_ns(),
        sent: pacer.seq,
        bytes: pacer.bytes,
        late: pacer.late,
    });
    Ok(FlowOutcome {
        session,
        flow,
        name: cfg.name,
        proto: Proto::Icmp,
        sent: pacer.seq,
        bytes: pacer.bytes,
        late: pacer.late,
        send_errors: 0,
        elapsed: pacer.elapsed(),
        rtts_ms: progress.take_rtts(),
        reverse: None,
    })
}
