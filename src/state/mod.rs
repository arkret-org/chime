//! Local push registration state helpers.
//!
//! This module contains:
//! - [`model`]: persisted state types + hash helper

mod model;

#[cfg(test)]
pub(crate) mod test_fixtures;

/// Schema version recorded with each persisted [`PushRegistrationState`].
pub const PUSH_REGISTRATION_STATE_SCHEMA_VERSION: u16 = 1;

pub use model::{
    PushRegistrationLastError, PushRegistrationState, build_registration_state, hash_push_key,
};
