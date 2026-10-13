//! Departure scheduling shared by all transports. Uses an absolute schedule so that
//! timer jitter does not accumulate into rate drift.

use std::time::Duration;

use rand::{SeedableRng, rngs::StdRng};
use tokio::sync::watch;
use tokio::time::{Instant, sleep_until};

use crate::dist::Sampler;
use crate::error::Result;
use crate::flow::ResolvedFlow;

const LATE_THRESHOLD: Duration = Duration::from_millis(1);
const RESYNC_THRESHOLD: Duration = Duration::from_secs(1);

struct Vad {
    talk: Sampler,
    silence: Sampler,
    talk_end: Instant,
}

pub(crate) struct Pacer {
    start: Instant,
    next: Instant,
    idt: Sampler,
    size: Sampler,
    rng: StdRng,
    vad: Option<Vad>,
    duration: Option<Duration>,
    count: Option<u64>,
    bytes_limit: Option<u64>,
    min_size: usize,
    max_size: usize,
    pub seq: u64,
    pub bytes: u64,
    pub late: u64,
    /// True for the first packet of each talkspurt (RTP marker bit). The caller clears it.
    pub new_talkspurt: bool,
}

fn ms(v: f64) -> Duration {
    if v.is_finite() && v > 0.0 {
        Duration::from_secs_f64(v / 1000.0)
    } else {
        Duration::ZERO
    }
}

impl Pacer {
    pub fn new(cfg: &ResolvedFlow, min_size: usize, max_size: usize) -> Result<Self> {
        let seed = cfg.seed.unwrap_or_else(rand::random::<u64>);
        let now = Instant::now();
        let vad = match &cfg.vad {
            Some((talk, silence)) => Some(Vad {
                talk: talk.build()?,
                silence: silence.build()?,
                talk_end: now,
            }),
            None => None,
        };
        Ok(Pacer {
            start: now,
            next: now,
            idt: cfg.idt_ms.build()?,
            size: cfg.size.build()?,
            rng: StdRng::seed_from_u64(seed),
            vad,
            duration: cfg.stop.duration,
            count: cfg.stop.count,
            bytes_limit: cfg.stop.bytes,
            min_size,
            max_size,
            seq: 0,
            bytes: 0,
            late: 0,
            new_talkspurt: true,
        })
    }

    /// Reset the schedule origin (call right before the first departure).
    pub fn restart(&mut self) {
        let now = Instant::now();
        self.start = now;
        self.next = now;
        self.new_talkspurt = true;
        if let Some(v) = &mut self.vad {
            v.talk_end = now + ms(v.talk.sample(&mut self.rng));
        }
    }

    pub fn elapsed(&self) -> Duration {
        self.start.elapsed()
    }

    /// Scheduled departure time of the current packet, relative to flow start.
    pub fn scheduled_offset(&self) -> Duration {
        self.next.saturating_duration_since(self.start)
    }

    /// Waits until the next packet is due. Returns its size, or `None` when the flow
    /// is complete or a stop was requested.
    pub async fn wait(&mut self, stop: &mut watch::Receiver<bool>) -> Option<usize> {
        if *stop.borrow() {
            return None;
        }
        if self.count.is_some_and(|c| self.seq >= c) {
            return None;
        }
        if self.bytes_limit.is_some_and(|b| self.bytes >= b) {
            return None;
        }
        if self.duration.is_some_and(|d| self.scheduled_offset() >= d) {
            return None;
        }

        let now = Instant::now();
        if self.next > now {
            tokio::select! {
                _ = sleep_until(self.next) => {}
                _ = stop.changed() => return None,
            }
        } else {
            let lag = now - self.next;
            if lag > LATE_THRESHOLD {
                self.late += 1;
            }
            if lag > RESYNC_THRESHOLD {
                self.next = now; // avoid an unbounded catch-up burst
            }
        }
        Some(
            self.size
                .sample_clamped(&mut self.rng, self.min_size, self.max_size),
        )
    }

    /// Record a departure and schedule the next one.
    pub fn advance(&mut self, size: usize) {
        self.seq += 1;
        self.bytes += size as u64;
        self.next += ms(self.idt.sample(&mut self.rng));
        if let Some(v) = &mut self.vad
            && self.next >= v.talk_end
        {
            // talkspurt over: stay silent, then start the next one
            self.next = v.talk_end + ms(v.silence.sample(&mut self.rng));
            v.talk_end = self.next + ms(v.talk.sample(&mut self.rng));
            self.new_talkspurt = true;
        }
    }
}
