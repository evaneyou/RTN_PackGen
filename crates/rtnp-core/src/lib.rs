//! Core library for a Rust distributed Internet traffic generator.
//!
//! * [`flow`] / [`preset`] / [`dist`] describe traffic.
//! * [`sender`] generates it, [`receiver`] measures it, [`control`] links the two.
//! * [`log`] and [`report`] record and analyse results.

pub mod auth;
pub mod client;
pub mod control;
pub mod dist;
pub mod error;
pub mod flow;
pub mod log;
pub mod logd;
pub mod metrics;
pub mod preset;
pub mod proto;
pub mod receiver;
pub mod report;
pub mod rtcp;
mod rtpsend;
pub mod sender;
pub mod srtp;
pub mod stats;
pub mod time;
mod tos;
mod track;
pub mod util;
pub mod verdict;

#[cfg(feature = "icmp")]
mod icmp;
mod pacer;

pub use error::{Error, Result};
