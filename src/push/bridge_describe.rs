//! Bridge describe + integration describe response DTOs.
//!
//! The wire structs live in `arkret-core` (surfaced via the SDK's
//! `push_gateway_api` alias) and are re-exported here for chime's existing
//! public API. Keeping the producer/consumer contract in the SDK prevents
//! floria and chime from carrying divergent copies.

pub use arkret::push_gateway_api::{
    EXPECTED_SPEC_VERSION, IntegrationView, PushBridgeDescribeGatewayDescriptor,
    PushBridgeDescribeNotifyDescriptor, PushBridgeDescribeOutcome,
    PushBridgeDescribePrivacyDescriptor, PushGatewayIntegrationDependency,
    PushGatewayIntegrationDescribeOutcome,
};
