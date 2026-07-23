//! Bridge describe + integration describe response DTOs.
//!
//! The wire structs live in `arkret-models-integration` and are re-exported
//! here for chime's existing public API. Keeping one owner for the
//! producer/consumer contract prevents
//! floria and chime from carrying divergent copies.

pub use arkret_models_integration::push::{
    EXPECTED_SPEC_VERSION, IntegrationView, PushBridgeDescribeGatewayDescriptor,
    PushBridgeDescribeNotifyDescriptor, PushBridgeDescribeOutcome,
    PushBridgeDescribePrivacyDescriptor,
};
pub use arkret_models_integration::{IntegrationDependencyDescriptor, IntegrationDescribeOutcome};
