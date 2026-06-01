//! Bridge describe + integration describe response DTOs.
//!
//! The wire structs live in `contrix-contracts` and are re-exported here for
//! chime's existing public API. Keeping the producer/consumer contract in
//! the SDK prevents floria and chime from carrying divergent copies.

pub use contrix::push_gateway_api::{
    EXPECTED_SPEC_VERSION, IntegrationView, PushBridgeDescribeGatewayDescriptor,
    PushBridgeDescribeNotifyDescriptor, PushBridgeDescribePrivacyDescriptor,
    PushBridgeDescribeResponse, PushGatewayIntegrationDependency,
    PushGatewayIntegrationDescribeResponse, PushGatewayIntegrationSurface,
};
