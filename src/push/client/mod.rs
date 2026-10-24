//! Async HTTP client for the Arkret push register/unregister/describe endpoints.
//!
//! Available only when the `http` feature is enabled.
//!
//! This module is split into:
//! - [`secret`]: `SecretString` zeroize-on-drop credential wrapper
//! - [`retry`]: `PushRetryPolicy` + retry/backoff/idempotency primitives
//! - [`transport`]: `ArkretHttpResponse` + low-level JSON request plumbing
//! - [`core`]: the `ArkretPushClient` builder + high-level register/describe API

mod core;
mod retry;
mod secret;
mod transport;

#[cfg(test)]
mod tests;

pub use core::ArkretPushClient;

pub use retry::PushRetryPolicy;
pub use transport::ArkretHttpResponse;
