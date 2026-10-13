//! Pass/fail judgement of a measurement against quality limits, e.g. for voice: round trip
//! (about twice the one-way delay of ITU-T G.114's 150 ms budget), jitter, loss, and whether the
//! DSCP marking survived the path.

use serde::{Deserialize, Serialize};

use crate::report::{FlowReport, RttSummary};
use crate::stats::Summary;

/// Limits to judge against. Anything left unset is not checked.
#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize, Deserialize)]
pub struct QualityLimits {
    /// Mean round-trip time (ms), from RTCP or an rtt meter.
    pub max_rtt_ms: Option<f64>,
    /// RFC 3550 interarrival jitter (ms), worst direction.
    pub max_jitter_ms: Option<f64>,
    /// Packet loss in percent, worst direction.
    pub max_loss_pct: Option<f64>,
    /// DSCP (0-63) the receiver must see. Use 46 for EF.
    pub expect_dscp: Option<u8>,
}

impl QualityLimits {
    pub fn is_empty(&self) -> bool {
        *self == QualityLimits::default()
    }

    /// Check the limits; `Err` names the first invalid one.
    pub fn validate(&self) -> Result<(), String> {
        for (n, v) in [
            ("max_rtt_ms", self.max_rtt_ms),
            ("max_jitter_ms", self.max_jitter_ms),
            ("max_loss_pct", self.max_loss_pct),
        ] {
            if v.is_some_and(|x| !x.is_finite() || x < 0.0) {
                return Err(format!("{n} must be a non-negative number"));
            }
        }
        if self.expect_dscp.is_some_and(|d| d > 63) {
            return Err("expect_dscp must be 0-63".into());
        }
        Ok(())
    }

    /// Judge one flow. `fwd` and `rev` are the receiver's and the sender's views of the two
    /// directions; `sent_loss_pct` is end-to-end loss when it is known more precisely than the
    /// sequence-gap figure inside `fwd`.
    pub fn judge(
        &self,
        fwd: Option<&Summary>,
        rev: Option<&Summary>,
        rtt: Option<&RttSummary>,
        loss_pct: Option<f64>,
    ) -> Verdict {
        let mut v = Verdict {
            pass: true,
            failures: Vec::new(),
            notes: Vec::new(),
        };
        if let Some(max) = self.max_rtt_ms {
            match rtt {
                Some(r) if r.avg_ms > max => {
                    v.fail(format!("round trip {:.1} ms exceeds {max} ms", r.avg_ms))
                }
                Some(_) => {}
                None => v.notes.push("round trip not measured".into()),
            }
        }
        if let Some(max) = self.max_jitter_ms {
            let worst = [fwd, rev]
                .into_iter()
                .flatten()
                .filter(|s| s.packets > 1)
                .map(|s| s.jitter_rfc3550_ms)
                .fold(None, |a: Option<f64>, x| Some(a.map_or(x, |a| a.max(x))));
            match worst {
                Some(j) if j > max => v.fail(format!("jitter {j:.1} ms exceeds {max} ms")),
                Some(_) => {}
                None => v.notes.push("jitter not measured".into()),
            }
        }
        if let Some(max) = self.max_loss_pct {
            let worst = [loss_pct, fwd.map(|s| s.loss_pct), rev.map(|s| s.loss_pct)]
                .into_iter()
                .flatten()
                .fold(None, |a: Option<f64>, x| Some(a.map_or(x, |a| a.max(x))));
            match worst {
                Some(l) if l > max => v.fail(format!("loss {l:.2}% exceeds {max}%")),
                Some(_) => {}
                None => v.notes.push("loss not measured".into()),
            }
        }
        if let Some(want) = self.expect_dscp {
            for (dir, s) in [("forward", fwd), ("return", rev)] {
                let Some(s) = s.filter(|s| s.packets > 0) else {
                    continue;
                };
                match s.tos {
                    Some(t) if t >> 2 != want => v.fail(format!(
                        "{dir} marking not preserved: DSCP {} arrived, {want} expected",
                        t >> 2
                    )),
                    Some(_) => {}
                    None => v
                        .notes
                        .push(format!("{dir} DSCP not observable on this platform")),
                }
            }
        }
        v
    }

    pub fn judge_report(&self, r: &FlowReport) -> Verdict {
        let loss = match (r.sent, r.lost_vs_tx) {
            (Some(s), Some(l)) if s > 0 => Some(l as f64 * 100.0 / s as f64),
            _ => None,
        };
        self.judge(r.rx.as_ref(), r.reverse.as_ref(), r.rtt.as_ref(), loss)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Verdict {
    pub pass: bool,
    pub failures: Vec<String>,
    /// Limits that could not be checked.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
}

impl Verdict {
    fn fail(&mut self, msg: String) {
        self.pass = false;
        self.failures.push(msg);
    }

    pub fn label(&self) -> &'static str {
        if self.pass { "PASS" } else { "FAIL" }
    }
}

/// The numbers a priority-queue comparison is made from.
#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize, Deserialize)]
pub struct CallMetrics {
    pub rtt_avg_ms: Option<f64>,
    pub rtt_max_ms: Option<f64>,
    /// RFC 3550 jitter, worst direction.
    pub jitter_ms: Option<f64>,
    /// Packet loss, worst direction.
    pub loss_pct: Option<f64>,
    /// DSCP the receiver saw on the forward stream.
    pub dscp_seen: Option<u8>,
}

fn worst(vals: impl IntoIterator<Item = Option<f64>>) -> Option<f64> {
    vals.into_iter()
        .flatten()
        .fold(None, |a: Option<f64>, x| Some(a.map_or(x, |a| a.max(x))))
}

impl CallMetrics {
    pub fn from_report(r: &FlowReport) -> Self {
        let e2e = match (r.sent, r.lost_vs_tx) {
            (Some(s), Some(l)) if s > 0 => Some(l as f64 * 100.0 / s as f64),
            _ => None,
        };
        let dirs = [r.rx.as_ref(), r.reverse.as_ref()];
        CallMetrics {
            rtt_avg_ms: r.rtt.as_ref().map(|t| t.avg_ms),
            rtt_max_ms: r.rtt.as_ref().map(|t| t.max_ms),
            jitter_ms: worst(
                dirs.iter()
                    .flatten()
                    .filter(|s| s.packets > 1)
                    .map(|s| Some(s.jitter_rfc3550_ms)),
            ),
            loss_pct: worst(
                std::iter::once(e2e).chain(dirs.iter().flatten().map(|s| Some(s.loss_pct))),
            ),
            dscp_seen: r.rx.as_ref().and_then(|s| s.tos).map(|t| t >> 2),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// Marked traffic did clearly better than unmarked traffic under the same load.
    Protected,
    /// The load hurt, and marking did not help (or made it worse).
    NotProtected,
    /// The marking never reached the receiver, so the queue could not have honoured it.
    MarkingLost,
    /// The load did not hurt unmarked traffic: nothing was tested.
    Inconclusive,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Comparison {
    pub outcome: Outcome,
    pub reasons: Vec<String>,
}

/// How much worse `a` must be than `b` to count: the larger of an absolute floor and a fraction.
fn clearly_worse(a: f64, b: f64, floor: f64) -> bool {
    a - b >= floor.max(0.5 * b)
}

/// Decide whether `ef` (marked) was protected from the load that `be` (unmarked) suffered.
/// `baseline` is the same call without any load, when measured.
pub fn compare(
    ef: &CallMetrics,
    be: &CallMetrics,
    baseline: Option<&CallMetrics>,
    ef_dscp: u8,
) -> Comparison {
    let mut reasons = Vec::new();
    if let Some(d) = ef.dscp_seen
        && d != ef_dscp
    {
        reasons.push(format!(
            "marked traffic arrived as DSCP {d}, not {ef_dscp}: something on the path rewrote it"
        ));
        return Comparison {
            outcome: Outcome::MarkingLost,
            reasons,
        };
    }
    // (name, floor, accessor)
    type Metric = (&'static str, f64, fn(&CallMetrics) -> Option<f64>);
    let metrics: [Metric; 3] = [
        ("jitter ms", 2.0, |m| m.jitter_ms),
        ("round trip ms", 5.0, |m| m.rtt_avg_ms),
        ("loss %", 0.5, |m| m.loss_pct),
    ];
    let (mut better, mut worse) = (0, 0);
    let mut stressed = false;
    for (name, floor, get) in metrics {
        let (Some(e), Some(b)) = (get(ef), get(be)) else {
            continue;
        };
        if clearly_worse(b, e, floor) {
            better += 1;
            reasons.push(format!("{name}: marked {e:.2} vs unmarked {b:.2}"));
        } else if clearly_worse(e, b, floor) {
            worse += 1;
            reasons.push(format!(
                "{name}: marked {e:.2} is worse than unmarked {b:.2}"
            ));
        } else {
            reasons.push(format!(
                "{name}: marked {e:.2} vs unmarked {b:.2} (similar)"
            ));
        }
        if let Some(base) = baseline.and_then(get)
            && clearly_worse(b, base, floor)
        {
            stressed = true;
        }
    }
    // absolute signs that the unmarked call was hurt even with nothing to compare against
    stressed |= be.loss_pct.is_some_and(|l| l >= 0.5)
        || be.jitter_ms.is_some_and(|j| j >= 10.0)
        || be.rtt_avg_ms.is_some_and(|r| r >= 100.0);
    let outcome = if better > 0 && worse == 0 {
        Outcome::Protected
    } else if worse > 0 || stressed {
        Outcome::NotProtected
    } else {
        reasons.push("the load did not hurt unmarked traffic: raise the background rate".into());
        Outcome::Inconclusive
    };
    Comparison { outcome, reasons }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(jitter: f64, loss: f64, tos: Option<u8>) -> Summary {
        Summary {
            packets: 100,
            jitter_rfc3550_ms: jitter,
            loss_pct: loss,
            tos,
            ..Default::default()
        }
    }

    fn rtt(avg: f64) -> RttSummary {
        RttSummary {
            count: 5,
            avg_ms: avg,
            ..Default::default()
        }
    }

    #[test]
    fn passes_within_limits() {
        let l = QualityLimits {
            max_rtt_ms: Some(300.0),
            max_jitter_ms: Some(30.0),
            max_loss_pct: Some(1.0),
            expect_dscp: Some(46),
        };
        let v = l.judge(
            Some(&s(5.0, 0.0, Some(184))),
            Some(&s(8.0, 0.2, Some(184))),
            Some(&rtt(40.0)),
            None,
        );
        assert!(v.pass, "{v:?}");
    }

    #[test]
    fn reports_each_violation_and_worst_direction() {
        let l = QualityLimits {
            max_rtt_ms: Some(100.0),
            max_jitter_ms: Some(30.0),
            max_loss_pct: Some(1.0),
            expect_dscp: Some(46),
        };
        let v = l.judge(
            Some(&s(5.0, 0.0, Some(184))),
            Some(&s(45.0, 3.0, Some(0))),
            Some(&rtt(180.0)),
            None,
        );
        assert!(!v.pass);
        assert_eq!(v.failures.len(), 4, "{v:?}");
        assert!(v.failures.iter().any(|f| f.contains("return marking")));
    }

    #[test]
    fn unmeasured_limits_are_notes_not_failures() {
        let l = QualityLimits {
            max_rtt_ms: Some(100.0),
            expect_dscp: Some(46),
            ..Default::default()
        };
        let v = l.judge(Some(&s(1.0, 0.0, None)), None, None, None);
        assert!(v.pass);
        assert_eq!(v.notes.len(), 2);
    }

    fn m(jitter: f64, rtt: f64, loss: f64, dscp: Option<u8>) -> CallMetrics {
        CallMetrics {
            rtt_avg_ms: Some(rtt),
            rtt_max_ms: Some(rtt),
            jitter_ms: Some(jitter),
            loss_pct: Some(loss),
            dscp_seen: dscp,
        }
    }

    #[test]
    fn compare_protected_not_protected_inconclusive_and_marking() {
        let c = compare(
            &m(1.0, 5.0, 0.0, Some(46)),
            &m(25.0, 60.0, 4.0, Some(0)),
            None,
            46,
        );
        assert_eq!(c.outcome, Outcome::Protected, "{c:?}");
        let c = compare(
            &m(24.0, 58.0, 4.0, Some(46)),
            &m(25.0, 60.0, 4.0, Some(0)),
            None,
            46,
        );
        assert_eq!(c.outcome, Outcome::NotProtected, "{c:?}");
        let c = compare(
            &m(1.0, 5.0, 0.0, Some(46)),
            &m(1.2, 5.5, 0.0, Some(0)),
            None,
            46,
        );
        assert_eq!(c.outcome, Outcome::Inconclusive, "{c:?}");
        let c = compare(
            &m(25.0, 60.0, 4.0, Some(0)),
            &m(25.0, 60.0, 4.0, Some(0)),
            None,
            46,
        );
        assert_eq!(c.outcome, Outcome::MarkingLost, "{c:?}");
        // load hurt relative to the quiet baseline even though absolute numbers are modest
        let base = m(0.5, 2.0, 0.0, Some(46));
        let c = compare(
            &m(4.0, 9.0, 0.0, Some(46)),
            &m(4.5, 9.5, 0.0, Some(0)),
            Some(&base),
            46,
        );
        assert_eq!(c.outcome, Outcome::NotProtected, "{c:?}");
    }

    #[test]
    fn rejects_bad_limits() {
        assert!(
            QualityLimits {
                expect_dscp: Some(64),
                ..Default::default()
            }
            .validate()
            .is_err()
        );
        assert!(
            QualityLimits {
                max_loss_pct: Some(-1.0),
                ..Default::default()
            }
            .validate()
            .is_err()
        );
    }
}
