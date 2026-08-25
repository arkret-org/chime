//! Local push registration state helpers.
//!
//! This module contains:
//! - [`model`]: persisted state types + hash helper

mod model;

#[cfg(test)]
pub(crate) mod test_fixtures;

pub use model::{PushRegistrationState, build_registration_state, hash_push_key};
