use std::time::{SystemTime, UNIX_EPOCH};

/// Wall-clock time as nanoseconds since the Unix epoch.
///
/// One-way delay between two hosts is only meaningful when their clocks are
/// synchronised (NTP/PTP). Loopback measurements are always consistent.
pub fn now_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}
