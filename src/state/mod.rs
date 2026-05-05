//! Local push registration state helpers.
//!
//! This module is split into:
//! - [`model`]: persisted state types, store trait, hash + finder helpers
//! - [`rotation`]: token rotation plans
//! - [`repair`]: stale-state repair plans

mod model;
mod repair;
mod rotation;

#[cfg(test)]
pub(crate) mod test_fixtures;

/// Schema version recorded with each persisted [`PushRegistrationState`].
pub const PUSH_REGISTRATION_STATE_SCHEMA_VERSION: u16 = 1;

pub use model::{
    PushRegistrationLastError, PushRegistrationState, PushRegistrationStore,
    build_registration_state, find_registration_by_token, find_registration_for_device,
    hash_push_key, merge_registration_state, token_moved_to_different_device,
    token_rotation_required,
};
pub use repair::{PushRegistrationRepairPlan, plan_registration_repair};
pub use rotation::{
    PushTokenRotationPlan, PushTokenRotationStrategy, plan_token_rotation,
    plan_token_rotation_with_strategy,
};
