//! Statistical distributions for inter-departure times (ms) and packet sizes (bytes).

use std::str::FromStr;

use rand::Rng;
use rand_distr::{Cauchy, Distribution, Exp, Gamma, Normal, Pareto, Poisson, Weibull};
use serde::{Deserialize, Deserializer, Serialize};

use crate::error::{Error, Result};

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Dist {
    Constant { value: f64 },
    Uniform { min: f64, max: f64 },
    Exponential { mean: f64 },
    Normal { mean: f64, std_dev: f64 },
    Pareto { scale: f64, shape: f64 },
    Cauchy { median: f64, scale: f64 },
    Gamma { shape: f64, scale: f64 },
    Weibull { scale: f64, shape: f64 },
    Poisson { mean: f64 },
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum Tagged {
    Constant { value: f64 },
    Uniform { min: f64, max: f64 },
    Exponential { mean: f64 },
    Normal { mean: f64, std_dev: f64 },
    Pareto { scale: f64, shape: f64 },
    Cauchy { median: f64, scale: f64 },
    Gamma { shape: f64, scale: f64 },
    Weibull { scale: f64, shape: f64 },
    Poisson { mean: f64 },
}

impl From<Tagged> for Dist {
    fn from(t: Tagged) -> Self {
        match t {
            Tagged::Constant { value } => Dist::Constant { value },
            Tagged::Uniform { min, max } => Dist::Uniform { min, max },
            Tagged::Exponential { mean } => Dist::Exponential { mean },
            Tagged::Normal { mean, std_dev } => Dist::Normal { mean, std_dev },
            Tagged::Pareto { scale, shape } => Dist::Pareto { scale, shape },
            Tagged::Cauchy { median, scale } => Dist::Cauchy { median, scale },
            Tagged::Gamma { shape, scale } => Dist::Gamma { shape, scale },
            Tagged::Weibull { scale, shape } => Dist::Weibull { scale, shape },
            Tagged::Poisson { mean } => Dist::Poisson { mean },
        }
    }
}

#[derive(Deserialize)]
#[serde(untagged)]
enum Repr {
    Number(f64),
    Text(String),
    Tagged(Tagged),
}

/// Accepts a bare number (`20`), a compact string (`"exp:50"`) or a table
/// (`{ kind = "exponential", mean = 50 }`).
impl<'de> Deserialize<'de> for Dist {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        match Repr::deserialize(d)? {
            Repr::Number(value) => Ok(Dist::Constant { value }),
            Repr::Text(s) => s.parse().map_err(serde::de::Error::custom),
            Repr::Tagged(t) => Ok(t.into()),
        }
    }
}

fn params(s: &str, n: usize, usage: &str) -> Result<Vec<f64>> {
    let v: std::result::Result<Vec<f64>, _> =
        s.split(',').map(|p| p.trim().parse::<f64>()).collect();
    match v {
        Ok(v) if v.len() == n => Ok(v),
        _ => Err(Error::Config(format!("expected {usage}"))),
    }
}

impl FromStr for Dist {
    type Err = Error;

    /// Compact syntax: `const:20`, `uniform:10,50`, `exp:100`, `normal:100,10`,
    /// `pareto:30,1.5`, `cauchy:50,5`, `gamma:2,10`, `weibull:30,1.5`, `poisson:5`,
    /// or a bare number meaning constant.
    fn from_str(s: &str) -> Result<Self> {
        let s = s.trim();
        if let Ok(value) = s.parse::<f64>() {
            return Ok(Dist::Constant { value });
        }
        let (name, rest) = s.split_once(':').ok_or_else(|| {
            Error::Config(format!(
                "invalid distribution '{s}' (try 'const:20' or 'exp:50')"
            ))
        })?;
        let d = match name.trim().to_ascii_lowercase().as_str() {
            "const" | "constant" => {
                let p = params(rest, 1, "const:<value>")?;
                Dist::Constant { value: p[0] }
            }
            "uniform" => {
                let p = params(rest, 2, "uniform:<min>,<max>")?;
                Dist::Uniform {
                    min: p[0],
                    max: p[1],
                }
            }
            "exp" | "exponential" => {
                let p = params(rest, 1, "exp:<mean>")?;
                Dist::Exponential { mean: p[0] }
            }
            "normal" => {
                let p = params(rest, 2, "normal:<mean>,<std_dev>")?;
                Dist::Normal {
                    mean: p[0],
                    std_dev: p[1],
                }
            }
            "pareto" => {
                let p = params(rest, 2, "pareto:<scale>,<shape>")?;
                Dist::Pareto {
                    scale: p[0],
                    shape: p[1],
                }
            }
            "cauchy" => {
                let p = params(rest, 2, "cauchy:<median>,<scale>")?;
                Dist::Cauchy {
                    median: p[0],
                    scale: p[1],
                }
            }
            "gamma" => {
                let p = params(rest, 2, "gamma:<shape>,<scale>")?;
                Dist::Gamma {
                    shape: p[0],
                    scale: p[1],
                }
            }
            "weibull" => {
                let p = params(rest, 2, "weibull:<scale>,<shape>")?;
                Dist::Weibull {
                    scale: p[0],
                    shape: p[1],
                }
            }
            "poisson" => {
                let p = params(rest, 1, "poisson:<mean>")?;
                Dist::Poisson { mean: p[0] }
            }
            other => return Err(Error::Config(format!("unknown distribution '{other}'"))),
        };
        d.build()?; // validate parameters eagerly
        Ok(d)
    }
}

/// A validated, ready-to-sample distribution.
#[derive(Debug, Clone)]
pub enum Sampler {
    Constant(f64),
    Uniform(f64, f64),
    Exp(Exp<f64>),
    Normal(Normal<f64>),
    Pareto(Pareto<f64>),
    Cauchy(Cauchy<f64>),
    Gamma(Gamma<f64>),
    Weibull(Weibull<f64>),
    Poisson(Poisson<f64>),
}

impl Dist {
    pub fn build(&self) -> Result<Sampler> {
        let bad = |what: &str, e: &dyn std::fmt::Display| {
            Error::Config(format!("invalid {what} parameters: {e}"))
        };
        let finite = |vals: &[f64]| -> Result<()> {
            if vals.iter().all(|v| v.is_finite()) {
                Ok(())
            } else {
                Err(Error::Config(
                    "distribution parameters must be finite".into(),
                ))
            }
        };
        Ok(match *self {
            Dist::Constant { value } => {
                finite(&[value])?;
                Sampler::Constant(value)
            }
            Dist::Uniform { min, max } => {
                finite(&[min, max])?;
                if min > max {
                    return Err(Error::Config("uniform requires min <= max".into()));
                }
                Sampler::Uniform(min, max)
            }
            Dist::Exponential { mean } => {
                finite(&[mean])?;
                if mean <= 0.0 {
                    return Err(Error::Config("exponential requires mean > 0".into()));
                }
                Sampler::Exp(Exp::new(1.0 / mean).map_err(|e| bad("exponential", &e))?)
            }
            Dist::Normal { mean, std_dev } => {
                finite(&[mean, std_dev])?;
                Sampler::Normal(Normal::new(mean, std_dev).map_err(|e| bad("normal", &e))?)
            }
            Dist::Pareto { scale, shape } => {
                finite(&[scale, shape])?;
                Sampler::Pareto(Pareto::new(scale, shape).map_err(|e| bad("pareto", &e))?)
            }
            Dist::Cauchy { median, scale } => {
                finite(&[median, scale])?;
                Sampler::Cauchy(Cauchy::new(median, scale).map_err(|e| bad("cauchy", &e))?)
            }
            Dist::Gamma { shape, scale } => {
                finite(&[shape, scale])?;
                Sampler::Gamma(Gamma::new(shape, scale).map_err(|e| bad("gamma", &e))?)
            }
            Dist::Weibull { scale, shape } => {
                finite(&[scale, shape])?;
                Sampler::Weibull(Weibull::new(scale, shape).map_err(|e| bad("weibull", &e))?)
            }
            Dist::Poisson { mean } => {
                finite(&[mean])?;
                Sampler::Poisson(Poisson::new(mean).map_err(|e| bad("poisson", &e))?)
            }
        })
    }
}

impl Sampler {
    pub fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> f64 {
        match self {
            Sampler::Constant(v) => *v,
            Sampler::Uniform(a, b) => {
                if a == b {
                    *a
                } else {
                    rng.random_range(*a..*b)
                }
            }
            Sampler::Exp(d) => d.sample(rng),
            Sampler::Normal(d) => d.sample(rng),
            Sampler::Pareto(d) => d.sample(rng),
            Sampler::Cauchy(d) => d.sample(rng),
            Sampler::Gamma(d) => d.sample(rng),
            Sampler::Weibull(d) => d.sample(rng),
            Sampler::Poisson(d) => d.sample(rng),
        }
    }

    /// Sample, round to an integer and clamp into `[lo, hi]` (used for packet sizes).
    pub fn sample_clamped<R: Rng + ?Sized>(&self, rng: &mut R, lo: usize, hi: usize) -> usize {
        let v = self.sample(rng);
        if !v.is_finite() {
            return lo;
        }
        (v.round().max(lo as f64).min(hi as f64)) as usize
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{SeedableRng, rngs::StdRng};

    #[test]
    fn parses_compact_forms() {
        assert_eq!(
            "20".parse::<Dist>().unwrap(),
            Dist::Constant { value: 20.0 }
        );
        assert_eq!(
            "exp:50".parse::<Dist>().unwrap(),
            Dist::Exponential { mean: 50.0 }
        );
        assert_eq!(
            "uniform:10,50".parse::<Dist>().unwrap(),
            Dist::Uniform {
                min: 10.0,
                max: 50.0
            }
        );
        assert!("pareto:1".parse::<Dist>().is_err());
        assert!("exp:-3".parse::<Dist>().is_err());
        assert!("bogus:1".parse::<Dist>().is_err());
    }

    #[test]
    fn deserializes_all_representations() {
        #[derive(Deserialize)]
        struct W {
            a: Dist,
            b: Dist,
            c: Dist,
        }
        let w: W = toml::from_str(
            r#"
            a = 12
            b = "exp:30"
            c = { kind = "pareto", scale = 5.0, shape = 1.5 }
            "#,
        )
        .unwrap();
        assert_eq!(w.a, Dist::Constant { value: 12.0 });
        assert_eq!(w.b, Dist::Exponential { mean: 30.0 });
        assert_eq!(
            w.c,
            Dist::Pareto {
                scale: 5.0,
                shape: 1.5
            }
        );
    }

    #[test]
    fn exponential_mean_is_close() {
        let s = Dist::Exponential { mean: 40.0 }.build().unwrap();
        let mut rng = StdRng::seed_from_u64(7);
        let n = 100_000;
        let mean: f64 = (0..n).map(|_| s.sample(&mut rng)).sum::<f64>() / n as f64;
        assert!((mean - 40.0).abs() < 1.0, "mean was {mean}");
    }

    #[test]
    fn clamped_sizes_stay_in_range() {
        let s = Dist::Normal {
            mean: 500.0,
            std_dev: 400.0,
        }
        .build()
        .unwrap();
        let mut rng = StdRng::seed_from_u64(1);
        for _ in 0..10_000 {
            let v = s.sample_clamped(&mut rng, 32, 1400);
            assert!((32..=1400).contains(&v));
        }
    }
}
