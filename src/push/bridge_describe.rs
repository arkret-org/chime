//! Bridge describe + integration describe response DTOs.
//!
//! The wire structs live in `arkret-core` (surfaced via the SDK's
//! canonical modules) and are re-exported here for chime's existing
//! public API. Keeping the producer/consumer contract in the SDK prevents
//! floria and chime from carrying divergent copies.

pub use arkret_wire_edge::push::{
    EXPECTED_SPEC_VERSION, IntegrationView, PushBridgeDescribeGatewayDescriptor,
    PushBridgeDescribeNotifyDescriptor, PushBridgeDescribeOutcome,
    PushBridgeDescribePrivacyDescriptor,
};
pub use arkret_wire_edge::{IntegrationDependencyDescriptor, IntegrationDescribeOutcome};
