//! Local push registration state helpers.
//!
//! This module is split into:
//! - [`model`]: persisted state types + hash helper
//! - [`bridge_cache`]: cached bridge-describe digest for drift detection

mod bridge_cache;
mod model;

#[cfg(test)]
pub(crate) mod test_fixtures;

/// Schema version recorded with each persisted [`PushRegistrationState`].
pub const PUSH_REGISTRATION_STATE_SCHEMA_VERSION: u16 = 1;

pub use bridge_cache::{BridgeContractCache, BridgeContractCacheError, BridgeContractDriftVerdict};
pub use model::{
    PushRegistrationLastError, PushRegistrationState, build_registration_state, hash_push_key,
};
