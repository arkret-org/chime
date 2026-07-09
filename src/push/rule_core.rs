//! Shared client-side push rule evaluator.
//!
//! Chime exposes the protocol-level watch-state decision for client and NSE
//! callers, while the implementation lives in the Arkret SDK so servers and
//! clients cannot drift.

pub use arkret::push_rule_core::{
    EventContext, ShouldNotify, WatchLevel, evaluate_watch_level, reason_code,
};
