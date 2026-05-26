//! Async HTTP client for the Contrix push register/unregister/describe endpoints.
//!
//! Available only when the `http` feature is enabled.

use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::{GatewayBinding, PushPreferences};

/// A.5 #2 — minimal `SecretString` wrapper for credential material the
/// HTTP client must hold in memory (bearer tokens today; the surface is
/// designed so we can extend it to other secrets later).
///
/// Semantics:
/// - `Clone` is intentionally supported so the surrounding
///   `ContrixPushClient` can remain `Clone`. Each clone owns its own
///   zeroed-on-drop allocation.
/// - `Debug` returns the literal string `"<redacted>"`; the inner
///   `String` is never formatted.
/// - `Drop` zeroes the underlying allocation via the `zeroize` crate so
///   a `ContrixPushClient` going out of scope does not leave the token
///   sitting in the freed heap region.
///
/// We do NOT implement `Display`, `PartialEq`, or `Serialize` on this
/// type — callers explicitly call [`Self::expose`] only at the very
/// moment they hand the secret to a reqwest header.
struct SecretString(String);

impl SecretString {
    fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Borrow the underlying secret. Callers MUST NOT clone the returned
    /// `&str` into a long-lived owned `String` outside of the request
    /// builder, and MUST NOT format it through `Debug`/`Display`.
    fn expose(&self) -> &str {
        self.0.as_str()
    }
}

impl Clone for SecretString {
    fn clone(&self) -> Self {
        // Allocate a fresh String so each `ContrixPushClient` clone gets
        // its own zeroed-on-drop buffer.
        Self(self.0.clone())
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

impl Drop for SecretString {
    fn drop(&mut self) {
        // `String::zeroize` wipes the allocation before it is freed.
        self.0.zeroize();
    }
}

use super::bridge_describe::{
    IntegrationView, PushBridgeDescribeResponse, PushGatewayIntegrationDescribeResponse,
};
use super::errors::{PushErrorKind, PushRegistrationError, classify_http_error};
use super::registration::{build_register_device_request, build_unregister_device_request};
use super::urls::{redact_url, try_contrix_api_url};
use super::wire::{
    ContrixErrorEnvelope, PushDeviceConfig, RegisterDeviceRequest, RegisterDeviceResponse,
    UnregisterDeviceRequest, UnregisterDeviceResponse,
};
use super::{
    CONTRIX_REQUEST_ID_HEADER, CONTRIX_SESSION_GRANT_HEADER, PUSH_BRIDGE_DESCRIBE_PATH,
    PUSH_INTEGRATION_DESCRIBE_PATH, PUSH_UNSUBSCRIBE_PATH, REGISTER_DEVICE_PATH,
    RETRY_AFTER_HEADER, SDK_USER_AGENT, UNREGISTER_DEVICE_PATH,
};
use super::wire::{PushUnsubscribeRequest, PushUnsubscribeResponse};
use super::registration::build_unsubscribe_request;

/// HTTP response body plus Contrix response metadata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContrixResponse<T> {
    pub body: T,
    pub request_id: Option<String>,
    pub retry_after: Option<String>,
}

impl<T> ContrixResponse<T> {
    pub fn map_body<U>(self, f: impl FnOnce(T) -> U) -> ContrixResponse<U> {
        ContrixResponse {
            body: f(self.body),
            request_id: self.request_id,
            retry_after: self.retry_after,
        }
    }
}

/// Retry configuration for `ContrixPushClient`.
///
/// Stability: `1.0`-stable. Stays `Copy` + `const`-constructible so
/// callers can stash it in static config. The `disabled_kinds_mask`
/// is a bitmask indexed by [`PushErrorKind`] discriminant ordinal —
/// see [`PushRetryPolicy::with_disabled_kinds`] for ergonomic builder
/// access.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PushRetryPolicy {
    pub max_retries: u32,
    pub initial_backoff: Duration,
    pub max_backoff: Duration,
    pub jitter: Duration,
    /// Bitmask of `PushErrorKind` ordinals that should *not* be
    /// retried even when `is_retryable()` would say yes. Useful when
    /// the host application wants to bypass retries for `RateLimited`
    /// to surface 429 immediately, etc.
    pub disabled_kinds_mask: u32,
}

impl PushRetryPolicy {
    pub const fn disabled() -> Self {
        Self {
            max_retries: 0,
            initial_backoff: Duration::from_millis(0),
            max_backoff: Duration::from_millis(0),
            jitter: Duration::from_millis(0),
            disabled_kinds_mask: 0,
        }
    }

    pub const fn conservative() -> Self {
        Self {
            max_retries: 2,
            initial_backoff: Duration::from_millis(200),
            max_backoff: Duration::from_secs(3),
            jitter: Duration::from_millis(100),
            disabled_kinds_mask: 0,
        }
    }

    /// Disable retries for the listed error kinds. Returns a new
    /// policy; the input slice is OR-folded into the existing mask so
    /// callers can layer this on top of `conservative()`.
    pub const fn with_disabled_kinds(mut self, kinds: &[super::PushErrorKind]) -> Self {
        let mut i = 0;
        while i < kinds.len() {
            self.disabled_kinds_mask |= 1u32 << kinds[i].ordinal();
            i += 1;
        }
        self
    }

    /// Whether retries are explicitly disabled for `kind`.
    pub const fn retries_disabled_for(&self, kind: super::PushErrorKind) -> bool {
        self.disabled_kinds_mask & (1u32 << kind.ordinal()) != 0
    }
}

impl Default for PushRetryPolicy {
    fn default() -> Self {
        Self::disabled()
    }
}

#[derive(Clone)]
pub struct ContrixPushClient {
    http: reqwest::Client,
    service_base_url: String,
    // A.5 #2 — bearer token is held in a zeroize-on-drop wrapper so
    // it does not linger in freed heap allocations after the client is
    // dropped. The Debug impl below redacts it.
    bearer_token: Option<SecretString>,
    timeout: Option<Duration>,
    retry_policy: PushRetryPolicy,
    retry_jitter_seed: u64,
    user_agent: String,
    headers: Vec<(reqwest::header::HeaderName, reqwest::header::HeaderValue)>,
    default_idempotency_key: Option<String>,
    default_request_id: Option<String>,
    require_session_grant: bool,
    // Bridge-discovered path overrides. When the gateway advertises a
    // non-default register/unregister path through `bridge/describe`,
    // hosts (e.g. yougen) need to route through it instead of the
    // baked-in `REGISTER_DEVICE_PATH` constant.
    register_device_path: Option<String>,
    unregister_device_path: Option<String>,
}

impl fmt::Debug for ContrixPushClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // A.5 #2 — `SecretString::Debug` already prints `<redacted>`,
        // so handing the `Option<SecretString>` straight to
        // `debug_struct` cannot leak the token. The explicit cast to
        // `Option<&SecretString>` makes that contract grep-able.
        let bearer: Option<&SecretString> = self.bearer_token.as_ref();
        f.debug_struct("ContrixPushClient")
            .field("service_base_url", &redact_url(&self.service_base_url))
            .field("bearer_token", &bearer)
            .field("timeout", &self.timeout)
            .field("retry_policy", &self.retry_policy)
            .field("user_agent", &self.user_agent)
            .field("header_count", &self.headers.len())
            .field("default_idempotency_key", &self.default_idempotency_key)
            .field("default_request_id", &self.default_request_id)
            .field("require_session_grant", &self.require_session_grant)
            .finish()
    }
}

impl ContrixPushClient {
    pub fn new(service_base_url: impl Into<String>) -> Self {
        Self {
            http: reqwest::Client::new(),
            service_base_url: service_base_url.into(),
            bearer_token: None,
            timeout: None,
            retry_policy: PushRetryPolicy::disabled(),
            retry_jitter_seed: retry_jitter_seed(),
            user_agent: SDK_USER_AGENT.to_owned(),
            headers: Vec::new(),
            default_idempotency_key: None,
            default_request_id: None,
            // Default: register/unregister fail-closed unless the caller
            // attaches a session grant. Tests / dev sandboxes that want to
            // opt out can call `.with_required_session_grant(false)`.
            require_session_grant: true,
            register_device_path: None,
            unregister_device_path: None,
        }
    }

    pub fn with_http_client(mut self, http: reqwest::Client) -> Self {
        self.http = http;
        self
    }

    pub fn with_bearer_token(mut self, token: impl Into<String>) -> Self {
        self.bearer_token = Some(SecretString::new(token));
        self
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    pub fn with_retry_policy(mut self, retry_policy: PushRetryPolicy) -> Self {
        self.retry_policy = retry_policy;
        self
    }

    pub fn without_retries(mut self) -> Self {
        self.retry_policy = PushRetryPolicy::disabled();
        self
    }

    pub fn with_user_agent(mut self, user_agent: impl Into<String>) -> Self {
        self.user_agent = user_agent.into();
        self
    }

    pub fn with_default_idempotency_key(mut self, idempotency_key: impl Into<String>) -> Self {
        self.default_idempotency_key = Some(idempotency_key.into());
        self
    }

    pub fn with_default_request_id(mut self, request_id: impl Into<String>) -> Self {
        self.default_request_id = Some(request_id.into());
        self
    }

    pub fn with_session_grant(
        self,
        session_grant: impl AsRef<str>,
    ) -> Result<Self, PushRegistrationError> {
        self.with_header(CONTRIX_SESSION_GRANT_HEADER, session_grant)
    }

    /// Override the `register-device` path. Use this when the active
    /// push gateway advertises a non-default endpoint via
    /// `bridge/describe.push.register_device_path`. When unset, the
    /// SDK posts to the baked-in [`REGISTER_DEVICE_PATH`] constant.
    pub fn with_register_device_path(mut self, path: impl Into<String>) -> Self {
        self.register_device_path = Some(path.into());
        self
    }

    /// Override the `unregister-device` path. Symmetric counterpart of
    /// [`with_register_device_path`](Self::with_register_device_path).
    pub fn with_unregister_device_path(mut self, path: impl Into<String>) -> Self {
        self.unregister_device_path = Some(path.into());
        self
    }

    fn effective_register_device_path(&self) -> &str {
        self.register_device_path
            .as_deref()
            .unwrap_or(REGISTER_DEVICE_PATH)
    }

    fn effective_unregister_device_path(&self) -> &str {
        self.unregister_device_path
            .as_deref()
            .unwrap_or(UNREGISTER_DEVICE_PATH)
    }

    /// Toggle the session-grant requirement for register/unregister calls.
    ///
    /// **Default is `true`.** When required, the client fail-closes with
    /// [`PushRegistrationError::MissingField`] (with field
    /// `"session_grant"`) before sending any request unless an
    /// `X-Contrix-Session-Grant` header has been attached via
    /// [`with_session_grant`](Self::with_session_grant) or
    /// [`with_header`](Self::with_header).
    ///
    /// Pass `false` for development sandboxes or test fixtures that
    /// intentionally skip soland session binding.
    pub fn with_required_session_grant(mut self, required: bool) -> Self {
        self.require_session_grant = required;
        self
    }

    /// Add a caller-supplied header, for example HTTP Message Signature fields.
    pub fn with_header(
        mut self,
        name: impl AsRef<str>,
        value: impl AsRef<str>,
    ) -> Result<Self, PushRegistrationError> {
        let name_raw = name.as_ref();
        let header_name =
            reqwest::header::HeaderName::from_bytes(name_raw.as_bytes()).map_err(|_| {
                PushRegistrationError::InvalidHeader {
                    name: name_raw.to_owned(),
                }
            })?;
        let header_value =
            reqwest::header::HeaderValue::from_str(value.as_ref()).map_err(|_| {
                PushRegistrationError::InvalidHeader {
                    name: name_raw.to_owned(),
                }
            })?;
        self.headers.push((header_name, header_value));
        Ok(self)
    }

    /// Discover the active push gateway bridge contract.
    pub async fn bridge_describe(
        &self,
    ) -> Result<PushBridgeDescribeResponse, PushRegistrationError> {
        Ok(self.bridge_describe_with_context().await?.body)
    }

    /// Discover the active push gateway bridge contract and return response metadata.
    pub async fn bridge_describe_with_context(
        &self,
    ) -> Result<ContrixResponse<PushBridgeDescribeResponse>, PushRegistrationError> {
        self.get_json(PUSH_BRIDGE_DESCRIBE_PATH).await
    }

    /// Discover the service-level push gateway integration manifest.
    pub async fn integration_describe(
        &self,
    ) -> Result<PushGatewayIntegrationDescribeResponse, PushRegistrationError> {
        Ok(self.integration_describe_with_context().await?.body)
    }

    /// Discover the service-level push gateway integration manifest and return response metadata.
    pub async fn integration_describe_with_context(
        &self,
    ) -> Result<ContrixResponse<PushGatewayIntegrationDescribeResponse>, PushRegistrationError>
    {
        self.get_json(PUSH_INTEGRATION_DESCRIBE_PATH).await
    }

    /// Fetch both the service-level integration manifest and the active bridge
    /// contract and return them as a single [`IntegrationView`].
    ///
    /// The two requests run sequentially. Either failure short-circuits.
    pub async fn integration_view(&self) -> Result<IntegrationView, PushRegistrationError> {
        let manifest = self.integration_describe().await?;
        let bridge = self.bridge_describe().await?;
        Ok(IntegrationView::new(manifest, bridge))
    }

    /// Register a push-capable device with a Contrix service against
    /// a specific gateway binding.
    ///
    /// When `prefs.enabled` is false, this method performs an idempotent
    /// unregister call and returns an `ok` register-shaped response.
    ///
    /// ```rust,no_run
    /// # async fn doc_run() -> Result<(), chime::PushRegistrationError> {
    /// # use chime::{GatewayBinding, PushDeviceConfig, PushGatewayType, PushPreferences};
    /// # let config = PushDeviceConfig {
    /// #     principal_did: None,
    /// #     device_id: "did:web:alice.example#device-phone",
    /// #     push_key: Some("fcm-or-apns-device-token"),
    /// #     platform: None, app_id: None, domestic_app_id: None,
    /// #     registration_id: None, display_name: None,
    /// #     idempotency_key: None, request_id: None, proof: None,
    /// # };
    /// # let binding = GatewayBinding::new(
    /// #     PushGatewayType::Standard,
    /// #     "https://push.example.com/api/v1/push/notify",
    /// # );
    /// # let prefs = PushPreferences {
    /// #     enabled: true,
    /// #     ..Default::default()
    /// # };
    /// use std::time::Duration;
    /// use chime::{ContrixPushClient, PushRetryPolicy};
    ///
    /// let client = ContrixPushClient::new("https://principal.example")
    ///     .with_bearer_token("session-token")
    ///     .with_timeout(Duration::from_secs(10))
    ///     .with_retry_policy(PushRetryPolicy::conservative());
    /// let response = client.register_device(&config, &binding, &prefs).await?;
    /// assert!(response.ok);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// Live coverage of this flow lives in `tests/live_floria_integration.rs`,
    /// which spawns a real `floria` push gateway on a loopback port.
    pub async fn register_device(
        &self,
        config: &PushDeviceConfig<'_>,
        binding: &GatewayBinding,
        prefs: &PushPreferences,
    ) -> Result<RegisterDeviceResponse, PushRegistrationError> {
        Ok(self
            .register_device_with_context(config, binding, prefs)
            .await?
            .body)
    }

    /// Register a push-capable device and return response metadata.
    pub async fn register_device_with_context(
        &self,
        config: &PushDeviceConfig<'_>,
        binding: &GatewayBinding,
        prefs: &PushPreferences,
    ) -> Result<ContrixResponse<RegisterDeviceResponse>, PushRegistrationError> {
        self.assert_session_grant_if_required()?;
        if !prefs.enabled {
            let response = self
                .unregister_device_with_context(config, binding, prefs)
                .await?;
            return Ok(response.map_body(|body| RegisterDeviceResponse {
                ok: body.ok,
                registration_id: None,
                accepted_gateway: None,
                push_key_hash: None,
                push_key_preview: None,
                expires_at: None,
                refresh_hint: None,
                warnings: Vec::new(),
                request_id: body.request_id,
            }));
        }

        let body = build_register_device_request(config, binding, prefs)?;
        let response = self
            .post_json(
                self.effective_register_device_path(),
                &body,
                config.idempotency_key,
                config.request_id,
            )
            .await?;

        tracing::info!(
            platform = body.platform.as_deref().unwrap_or("unspecified"),
            gateway = binding.gateway_type.display_name(),
            operation_id = crate::OPERATION_PUSH_REGISTER_DEVICE,
            request_id = response.request_id.as_deref(),
            "Contrix push device registered"
        );

        Ok(response)
    }

    /// Post a pre-built [`RegisterDeviceRequest`] through the
    /// configured client (session-grant header, retry policy,
    /// caller-supplied headers, register-device path override all
    /// honored). Use this when callers already constructed the wire
    /// body — typically because they cached it for retry or built it
    /// in one place and post in another (yougen's bridge-discovered
    /// register flow does this) — and would otherwise have to rebuild
    /// it via `build_register_device_request`.
    pub async fn register_device_with_request(
        &self,
        body: &RegisterDeviceRequest,
        idempotency_key: Option<&str>,
        request_id: Option<&str>,
    ) -> Result<ContrixResponse<RegisterDeviceResponse>, PushRegistrationError> {
        self.assert_session_grant_if_required()?;
        let response = self
            .post_json(
                self.effective_register_device_path(),
                body,
                idempotency_key.or(body.idempotency_key.as_deref()),
                request_id,
            )
            .await?;

        tracing::info!(
            platform = body.platform.as_deref().unwrap_or("unspecified"),
            operation_id = crate::OPERATION_PUSH_REGISTER_DEVICE,
            request_id = response.request_id.as_deref(),
            "Contrix push device registered (prebuilt body)"
        );

        Ok(response)
    }

    /// Symmetric counterpart of
    /// [`register_device_with_request`](Self::register_device_with_request)
    /// for unregister flows.
    pub async fn unregister_device_with_request(
        &self,
        body: &UnregisterDeviceRequest,
        idempotency_key: Option<&str>,
        request_id: Option<&str>,
    ) -> Result<ContrixResponse<UnregisterDeviceResponse>, PushRegistrationError> {
        self.assert_session_grant_if_required()?;
        let response = match self
            .post_json(
                self.effective_unregister_device_path(),
                body,
                idempotency_key.or(body.idempotency_key.as_deref()),
                request_id,
            )
            .await
        {
            Ok(response) => response,
            Err(error) if error.kind() == PushErrorKind::NotFound => ContrixResponse {
                body: UnregisterDeviceResponse {
                    ok: true,
                    already_removed: true,
                    removed_registration_id: None,
                    request_id: error.request_id().map(str::to_owned),
                },
                request_id: error.request_id().map(str::to_owned),
                retry_after: error.retry_after().map(str::to_owned),
            },
            Err(error) => return Err(error),
        };

        Ok(response)
    }

    /// B.5 #8 — unsubscribe a device from a specific Circle / Realm /
    /// Flow at the gateway.
    ///
    /// Differs from [`Self::unregister_device`] in scope: unregister
    /// removes the device's push registration entirely (no more
    /// wakeups from any scope), whereas `unsubscribe` removes a single
    /// scope while keeping the registration alive for other scopes.
    /// Use this when the user mutes a single Circle but expects other
    /// Circles and Realms to keep waking the device.
    ///
    /// The `target_id` query parameter is added to the URL in
    /// addition to the wire body, mirroring the floria contract that
    /// accepts both forms for the same operation.
    pub async fn unsubscribe(
        &self,
        config: &PushDeviceConfig<'_>,
        target_id: &str,
    ) -> Result<PushUnsubscribeResponse, PushRegistrationError> {
        Ok(self.unsubscribe_with_context(config, target_id).await?.body)
    }

    /// Unsubscribe a device from a scope and return response metadata.
    pub async fn unsubscribe_with_context(
        &self,
        config: &PushDeviceConfig<'_>,
        target_id: &str,
    ) -> Result<ContrixResponse<PushUnsubscribeResponse>, PushRegistrationError> {
        self.assert_session_grant_if_required()?;
        let body = build_unsubscribe_request(config, target_id)?;
        let path = format!(
            "{PUSH_UNSUBSCRIBE_PATH}?target_id={}",
            urlencode_for_query(target_id),
        );
        let response = self
            .post_json(&path, &body, config.idempotency_key, config.request_id)
            .await?;

        tracing::info!(
            target_id = target_id,
            operation_id = crate::OPERATION_PUSH_UNSUBSCRIBE,
            request_id = response.request_id.as_deref(),
            "Contrix push device unsubscribed from scope",
        );

        Ok(response)
    }

    /// Variant of [`Self::unsubscribe`] that posts a pre-built body
    /// (caller-supplied [`PushUnsubscribeRequest`]).
    pub async fn unsubscribe_with_request(
        &self,
        body: &PushUnsubscribeRequest,
    ) -> Result<ContrixResponse<PushUnsubscribeResponse>, PushRegistrationError> {
        self.assert_session_grant_if_required()?;
        let path = format!(
            "{PUSH_UNSUBSCRIBE_PATH}?target_id={}",
            urlencode_for_query(&body.target_id),
        );
        self.post_json(
            &path,
            body,
            body.idempotency_key.as_deref(),
            body.request_id.as_deref(),
        )
        .await
    }

    /// Unregister a push-capable device from a Contrix service against
    /// a specific gateway binding.
    pub async fn unregister_device(
        &self,
        config: &PushDeviceConfig<'_>,
        binding: &GatewayBinding,
        prefs: &PushPreferences,
    ) -> Result<UnregisterDeviceResponse, PushRegistrationError> {
        Ok(self
            .unregister_device_with_context(config, binding, prefs)
            .await?
            .body)
    }

    /// Unregister a push-capable device and return response metadata.
    pub async fn unregister_device_with_context(
        &self,
        config: &PushDeviceConfig<'_>,
        binding: &GatewayBinding,
        prefs: &PushPreferences,
    ) -> Result<ContrixResponse<UnregisterDeviceResponse>, PushRegistrationError> {
        self.assert_session_grant_if_required()?;
        let body = build_unregister_device_request(config, binding, prefs)?;
        let response = match self
            .post_json(
                self.effective_unregister_device_path(),
                &body,
                config.idempotency_key,
                config.request_id,
            )
            .await
        {
            Ok(response) => response,
            Err(error) if error.kind() == PushErrorKind::NotFound => ContrixResponse {
                body: UnregisterDeviceResponse {
                    ok: true,
                    already_removed: true,
                    removed_registration_id: None,
                    request_id: error.request_id().map(str::to_owned),
                },
                request_id: error.request_id().map(str::to_owned),
                retry_after: error.retry_after().map(str::to_owned),
            },
            Err(error) => return Err(error),
        };

        tracing::info!(
            platform = config.platform.unwrap_or("unspecified"),
            operation_id = crate::OPERATION_PUSH_UNREGISTER_DEVICE,
            request_id = response.request_id.as_deref(),
            "Contrix push device unregistered"
        );

        Ok(response)
    }

    /// Register the device against every binding in
    /// [`PushPreferences::gateways`](crate::PushPreferences::gateways).
    ///
    /// Each binding is exercised independently — a failure on one
    /// binding does not abort the others. Returns one
    /// `Result<RegisterDeviceResponse, _>` per binding, in the same
    /// order as `prefs.gateways`. When `prefs.gateways` is empty the
    /// returned `Vec` is empty.
    ///
    /// Per-binding `push_key` and `app_id` overrides on the binding
    /// take priority over the values in `config`. The base
    /// `device_id`, `principal_did`, `platform`, `idempotency_key`,
    /// `request_id`, and `proof` are shared across bindings.
    pub async fn register_device_all(
        &self,
        config: &PushDeviceConfig<'_>,
        prefs: &PushPreferences,
    ) -> Vec<Result<RegisterDeviceResponse, PushRegistrationError>> {
        let mut out = Vec::with_capacity(prefs.gateways.len());
        for binding in &prefs.gateways {
            out.push(self.register_device(config, binding, prefs).await);
        }
        out
    }

    /// Rotate a push token for a specific gateway binding: unregister
    /// the prior registration (if any) and register the new token in
    /// one call. Wraps [`plan_token_rotation_with_strategy`] +
    /// [`register_device`](Self::register_device) /
    /// [`unregister_device`](Self::unregister_device) so callers do not
    /// have to thread the request bodies themselves.
    ///
    /// Returns `Ok(None)` when the token has not changed (no work to
    /// do); returns `Ok(Some(response))` with the fresh registration
    /// response on success. Errors from either leg short-circuit.
    ///
    /// `existing` should be the locally stored
    /// [`PushRegistrationState`](crate::PushRegistrationState) for this
    /// device — typically loaded from `PushRegistrationStore::load_push_registration`.
    /// `config.push_key` (or `binding.push_key`) MUST be set to the new
    /// platform token.
    ///
    /// [`plan_token_rotation_with_strategy`]:
    /// crate::plan_token_rotation_with_strategy
    pub async fn rotate_token(
        &self,
        existing: Option<&crate::PushRegistrationState>,
        config: &PushDeviceConfig<'_>,
        binding: &GatewayBinding,
        prefs: &PushPreferences,
        strategy: crate::PushTokenRotationStrategy,
    ) -> Result<Option<RegisterDeviceResponse>, PushRegistrationError> {
        let plan =
            crate::plan_token_rotation_with_strategy(existing, config, binding, prefs, strategy)?;

        if !plan.token_changed {
            return Ok(None);
        }

        let response = match strategy {
            crate::PushTokenRotationStrategy::UnregisterOldFirst => {
                if plan.unregister_old.is_some() {
                    self.unregister_device(config, binding, prefs).await.ok();
                }
                self.register_device(config, binding, prefs).await?
            }
            crate::PushTokenRotationStrategy::RegisterNewFirst => {
                let response = self.register_device(config, binding, prefs).await?;
                if plan.unregister_old.is_some() {
                    self.unregister_device(config, binding, prefs).await.ok();
                }
                response
            }
        };

        Ok(Some(response))
    }

    async fn post_json<T, R>(
        &self,
        path: &str,
        body: &T,
        idempotency_key: Option<&str>,
        request_id: Option<&str>,
    ) -> Result<ContrixResponse<R>, PushRegistrationError>
    where
        T: Serialize + ?Sized,
        R: for<'de> Deserialize<'de>,
    {
        let mut retry_count = 0;
        let idempotency_key = idempotency_key
            .map(str::to_owned)
            .or_else(|| self.default_idempotency_key.clone())
            .unwrap_or_else(generate_idempotency_key);
        let request_id = request_id.or(self.default_request_id.as_deref());

        loop {
            let result = self
                .post_json_once(path, body, Some(idempotency_key.as_str()), request_id)
                .await;

            match result {
                Ok(response) => return Ok(response),
                Err(error)
                    if retry_count < self.retry_policy.max_retries
                        && error.is_retryable()
                        && !self.retry_policy.retries_disabled_for(error.kind()) =>
                {
                    let delay = error
                        .retry_after_duration()
                        .unwrap_or_else(|| self.backoff_delay(retry_count));
                    if !delay.is_zero() {
                        sleep_for(delay).await;
                    }
                    retry_count += 1;
                }
                Err(error) => return Err(error),
            }
        }
    }

    async fn get_json<R>(&self, path: &str) -> Result<ContrixResponse<R>, PushRegistrationError>
    where
        R: for<'de> Deserialize<'de>,
    {
        let mut retry_count = 0;

        loop {
            let result = self.get_json_once(path).await;

            match result {
                Ok(response) => return Ok(response),
                Err(error)
                    if retry_count < self.retry_policy.max_retries
                        && error.is_retryable()
                        && !self.retry_policy.retries_disabled_for(error.kind()) =>
                {
                    let delay = error
                        .retry_after_duration()
                        .unwrap_or_else(|| self.backoff_delay(retry_count));
                    if !delay.is_zero() {
                        sleep_for(delay).await;
                    }
                    retry_count += 1;
                }
                Err(error) => return Err(error),
            }
        }
    }

    async fn post_json_once<T, R>(
        &self,
        path: &str,
        body: &T,
        idempotency_key: Option<&str>,
        request_id: Option<&str>,
    ) -> Result<ContrixResponse<R>, PushRegistrationError>
    where
        T: Serialize + ?Sized,
        R: for<'de> Deserialize<'de>,
    {
        let url = try_contrix_api_url(&self.service_base_url, path)?;
        let mut request = self
            .http
            .post(url)
            .header(reqwest::header::USER_AGENT, self.user_agent.as_str())
            .json(body);

        if let Some(timeout) = self.timeout {
            request = request.timeout(timeout);
        }

        if let Some(token) = &self.bearer_token {
            // `SecretString::expose` is the one and only sanctioned
            // place to materialise the bearer secret — it is consumed
            // immediately by reqwest's builder. Do not stash the
            // returned `&str` elsewhere.
            request = request.bearer_auth(token.expose());
        }

        if let Some(idempotency_key) = idempotency_key {
            request = request.header("Idempotency-Key", idempotency_key);
        }

        if let Some(request_id) = request_id {
            let request_id = reqwest::header::HeaderValue::from_str(request_id).map_err(|_| {
                PushRegistrationError::InvalidHeader {
                    name: CONTRIX_REQUEST_ID_HEADER.to_owned(),
                }
            })?;
            request = request.header(CONTRIX_REQUEST_ID_HEADER, request_id);
        }

        for (name, value) in &self.headers {
            request = request.header(name, value);
        }

        let response = request.send().await?;
        let status = response.status();
        let headers = response.headers().clone();
        let retry_after = header_value(&headers, RETRY_AFTER_HEADER);
        let request_id = header_value(&headers, CONTRIX_REQUEST_ID_HEADER);
        let body = response.text().await?;

        if !status.is_success() {
            let error = serde_json::from_str::<ContrixErrorEnvelope>(&body)
                .ok()
                .map(Box::new);
            let kind = classify_http_error(status.as_u16(), error.as_deref());
            return Err(PushRegistrationError::HttpStatus {
                status: status.as_u16(),
                kind,
                error,
                body,
                retry_after,
                request_id,
            });
        }

        Ok(ContrixResponse {
            body: serde_json::from_str(&body)?,
            request_id,
            retry_after,
        })
    }

    async fn get_json_once<R>(
        &self,
        path: &str,
    ) -> Result<ContrixResponse<R>, PushRegistrationError>
    where
        R: for<'de> Deserialize<'de>,
    {
        let url = try_contrix_api_url(&self.service_base_url, path)?;
        let mut request = self
            .http
            .get(url)
            .header(reqwest::header::USER_AGENT, self.user_agent.as_str());

        if let Some(timeout) = self.timeout {
            request = request.timeout(timeout);
        }

        if let Some(token) = &self.bearer_token {
            // `SecretString::expose` is the one and only sanctioned
            // place to materialise the bearer secret — it is consumed
            // immediately by reqwest's builder. Do not stash the
            // returned `&str` elsewhere.
            request = request.bearer_auth(token.expose());
        }

        if let Some(request_id) = self.default_request_id.as_deref() {
            let request_id = reqwest::header::HeaderValue::from_str(request_id).map_err(|_| {
                PushRegistrationError::InvalidHeader {
                    name: CONTRIX_REQUEST_ID_HEADER.to_owned(),
                }
            })?;
            request = request.header(CONTRIX_REQUEST_ID_HEADER, request_id);
        }

        for (name, value) in &self.headers {
            request = request.header(name, value);
        }

        let response = request.send().await?;
        let status = response.status();
        let headers = response.headers().clone();
        let retry_after = header_value(&headers, RETRY_AFTER_HEADER);
        let request_id = header_value(&headers, CONTRIX_REQUEST_ID_HEADER);
        let body = response.text().await?;

        if !status.is_success() {
            let error = serde_json::from_str::<ContrixErrorEnvelope>(&body)
                .ok()
                .map(Box::new);
            let kind = classify_http_error(status.as_u16(), error.as_deref());
            return Err(PushRegistrationError::HttpStatus {
                status: status.as_u16(),
                kind,
                error,
                body,
                retry_after,
                request_id,
            });
        }

        Ok(ContrixResponse {
            body: serde_json::from_str(&body)?,
            request_id,
            retry_after,
        })
    }

    fn assert_session_grant_if_required(&self) -> Result<(), PushRegistrationError> {
        if self.require_session_grant && !self.has_header(CONTRIX_SESSION_GRANT_HEADER) {
            return Err(PushRegistrationError::MissingField("session_grant"));
        }
        Ok(())
    }

    fn has_header(&self, name: &str) -> bool {
        self.headers
            .iter()
            .any(|(header_name, _)| header_name.as_str().eq_ignore_ascii_case(name))
    }

    fn backoff_delay(&self, retry_count: u32) -> Duration {
        let factor = 1_u32.checked_shl(retry_count.min(31)).unwrap_or(u32::MAX);
        let base = self
            .retry_policy
            .initial_backoff
            .saturating_mul(factor)
            .min(self.retry_policy.max_backoff);
        base.saturating_add(self.jitter_delay(retry_count))
            .min(self.retry_policy.max_backoff)
    }

    fn jitter_delay(&self, retry_count: u32) -> Duration {
        if self.retry_policy.jitter.is_zero() {
            return Duration::ZERO;
        }

        let max_nanos = self.retry_policy.jitter.as_nanos().min(u64::MAX as u128) as u64;
        if max_nanos == 0 {
            return Duration::ZERO;
        }

        // C.6 #10 — re-seed the jitter mixer per attempt by folding in
        // a fresh wall-clock sample. Without this every retry of a
        // given `(client, retry_count)` pair would produce the same
        // jitter — which means concurrent retries from many clients
        // that happen to share a construction timestamp (e.g. a fleet
        // restarting at the same minute) would line up into thundering
        // herds. The fresh-per-attempt seed breaks the alignment without
        // pulling in the `rand` crate.
        let attempt_seed = retry_jitter_seed();
        let mut value = self
            .retry_jitter_seed
            .wrapping_add(attempt_seed)
            ^ ((retry_count as u64).wrapping_add(1) * 0x9E37_79B9_7F4A_7C15);
        value ^= value >> 30;
        value = value.wrapping_mul(0xBF58_476D_1CE4_E5B9);
        value ^= value >> 27;
        value = value.wrapping_mul(0x94D0_49BB_1331_11EB);
        value ^= value >> 31;
        Duration::from_nanos(value % (max_nanos.saturating_add(1)))
    }
}

fn retry_jitter_seed() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|duration| duration.as_nanos().min(u64::MAX as u128) as u64)
        .unwrap_or(0xC0DE_CAFE)
}

/// Per-target async sleep used by the retry/backoff loop.
///
/// Native targets dispatch to `tokio::time::sleep` (the `http` feature
/// pulls in tokio with the `time` driver). The wasm32 build has no
/// tokio runtime on the browser main thread so it dispatches through
/// `gloo_timers::future::sleep`, which is a thin wrapper over
/// `setTimeout` and works inside the wasm-bindgen-futures executor that
/// `wasm_bindgen_futures::spawn_local` provides.
#[cfg(not(target_arch = "wasm32"))]
async fn sleep_for(delay: Duration) {
    tokio::time::sleep(delay).await;
}

#[cfg(target_arch = "wasm32")]
async fn sleep_for(delay: Duration) {
    gloo_timers::future::sleep(delay).await;
}

/// Generate a per-request idempotency key from process-monotonic state.
///
/// Used as a fallback when the caller does not provide
/// `PushDeviceConfig::idempotency_key` and the client has no
/// `default_idempotency_key` configured. The same key is reused across retries
/// of the same logical request so the gateway can deduplicate.
fn generate_idempotency_key() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    let mut hasher = Sha256::new();
    hasher.update(b"cx-idempotency-v1");
    hasher.update(nanos.to_le_bytes());
    hasher.update(counter.to_le_bytes());
    let digest = hasher.finalize();

    use std::fmt::Write as _;
    let mut output = String::with_capacity("cx-sdk-".len() + 32);
    output.push_str("cx-sdk-");
    for byte in &digest[..16] {
        let _ = write!(output, "{byte:02x}");
    }
    output
}

/// Percent-encode a value for use as a URL query parameter.
///
/// Minimal implementation — the typed `cx:scope:opaque` strings chime
/// builds for unsubscribe only need `:` and a small punctuation set
/// encoded. We avoid pulling in `percent-encoding` just for this one
/// call site.
fn urlencode_for_query(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char);
            }
            _ => {
                use std::fmt::Write as _;
                let _ = write!(out, "%{byte:02X}");
            }
        }
    }
    out
}

fn header_value(headers: &reqwest::header::HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};
    use std::thread;

    struct MockResponse {
        status: &'static str,
        headers: Vec<(&'static str, &'static str)>,
        body: &'static str,
    }

    fn spawn_mock_server(responses: Vec<MockResponse>) -> (String, Arc<Mutex<Vec<String>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let requests_for_thread = Arc::clone(&requests);

        thread::spawn(move || {
            for response in responses {
                let (mut stream, _) = listener.accept().unwrap();
                let mut buffer = [0_u8; 8192];
                let bytes_read = stream.read(&mut buffer).unwrap();
                requests_for_thread
                    .lock()
                    .unwrap()
                    .push(String::from_utf8_lossy(&buffer[..bytes_read]).to_string());

                let mut raw = format!(
                    "HTTP/1.1 {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n",
                    response.status,
                    response.body.len()
                );
                for (name, value) in response.headers {
                    raw.push_str(name);
                    raw.push_str(": ");
                    raw.push_str(value);
                    raw.push_str("\r\n");
                }
                raw.push_str("\r\n");
                raw.push_str(response.body);
                stream.write_all(raw.as_bytes()).unwrap();
            }
        });

        (format!("http://{addr}"), requests)
    }

    fn config<'a>() -> PushDeviceConfig<'a> {
        PushDeviceConfig {
            principal_did: Some("did:web:alice.example"),
            device_id: "did:web:alice.example#device-phone",
            push_key: Some("fcm:very-secret-token"),
            platform: Some("android"),
            app_id: Some("app.example.android"),
            domestic_app_id: None,
            registration_id: Some("cx:pushreg:01JS0KE000000000000000000"),
            display_name: Some("Alice Phone"),
            idempotency_key: Some("idem-1"),
            request_id: Some("cx:request:test"),
            proof: None,
        }
    }

    fn prefs() -> PushPreferences {
        PushPreferences {
            enabled: true,
            ..Default::default()
        }
    }

    fn binding() -> crate::GatewayBinding {
        crate::GatewayBinding::new(
            crate::PushGatewayType::Standard,
            "https://push.example.com/api/v1/push/notify",
        )
    }

    /// Build a happy-path client with a dummy session grant pre-attached.
    ///
    /// Mirrors production usage where every register/unregister call is
    /// expected to carry a soland session grant. Tests that specifically
    /// exercise the "missing grant" path use raw `ContrixPushClient::new`.
    fn client(base_url: impl Into<String>) -> ContrixPushClient {
        ContrixPushClient::new(base_url)
            .with_session_grant("test-session-grant")
            .expect("test session grant header is valid")
    }

    #[tokio::test]
    async fn register_success_exposes_response_context_and_headers() {
        let (base_url, requests) = spawn_mock_server(vec![MockResponse {
            status: "200 OK",
            headers: vec![(CONTRIX_REQUEST_ID_HEADER, "cx:request:server")],
            body: r#"{"ok":true,"registration_id":"reg-1","expires_at":"2026-04-29T00:00:00Z"}"#,
        }]);

        let response = client(base_url)
            .with_bearer_token("session-secret")
            .with_user_agent("test-agent")
            .with_header(
                "Signature-Input",
                r#"sig1=("@method" "@target-uri" "content-digest")"#,
            )
            .unwrap()
            .register_device_with_context(&config(), &binding(), &prefs())
            .await
            .unwrap();

        assert!(response.body.ok);
        assert_eq!(response.body.registration_id.as_deref(), Some("reg-1"));
        assert_eq!(response.request_id.as_deref(), Some("cx:request:server"));

        let request = requests.lock().unwrap().join("\n");
        assert!(request.contains("POST /api/v1/push/register-device HTTP/1.1"));
        assert!(request.contains("authorization: Bearer session-secret"));
        assert!(request.contains("idempotency-key: idem-1"));
        assert!(request.contains("x-contrix-request-id: cx:request:test"));
        assert!(request.contains("user-agent: test-agent"));
        assert!(request.contains("\"idempotency_key\":\"idem-1\""));
    }

    #[tokio::test]
    async fn client_default_headers_fill_request_metadata() {
        let (base_url, requests) = spawn_mock_server(vec![MockResponse {
            status: "200 OK",
            headers: vec![],
            body: r#"{"ok":true}"#,
        }]);
        let mut config = config();
        config.idempotency_key = None;
        config.request_id = None;

        ContrixPushClient::new(base_url)
            .with_default_idempotency_key("client-idem")
            .with_default_request_id("cx:request:client")
            .with_session_grant("coauth-grant-secret")
            .unwrap()
            .register_device(&config, &binding(), &prefs())
            .await
            .unwrap();

        let request = requests.lock().unwrap().join("\n");
        assert!(request.contains("idempotency-key: client-idem"));
        assert!(request.contains("x-contrix-request-id: cx:request:client"));
        assert!(request.contains("x-contrix-session-grant: coauth-grant-secret"));
    }

    #[tokio::test]
    async fn unregister_success() {
        let (base_url, requests) = spawn_mock_server(vec![MockResponse {
            status: "200 OK",
            headers: vec![],
            body: r#"{"ok":true}"#,
        }]);

        let response = client(base_url)
            .unregister_device(&config(), &binding(), &prefs())
            .await
            .unwrap();

        assert!(response.ok);
        let request = requests.lock().unwrap().join("\n");
        assert!(request.contains("POST /api/v1/push/unregister-device HTTP/1.1"));
        assert!(request.contains("\"registration_id\":\"cx:pushreg:01JS0KE000000000000000000\""));
    }

    #[tokio::test]
    async fn unregister_not_found_is_idempotent_success() {
        let (base_url, _) = spawn_mock_server(vec![MockResponse {
            status: "404 Not Found",
            headers: vec![(CONTRIX_REQUEST_ID_HEADER, "cx:request:not-found")],
            body: r#"{"ok":false,"error":{"code":"not_found","message":"missing"}}"#,
        }]);

        let response = client(base_url)
            .unregister_device_with_context(&config(), &binding(), &prefs())
            .await
            .unwrap();

        assert!(response.body.ok);
        assert_eq!(response.request_id.as_deref(), Some("cx:request:not-found"));
    }

    #[tokio::test]
    async fn classifies_json_error_responses() {
        let cases = [
            (
                "400 Bad Request",
                "schema_violation",
                PushErrorKind::SchemaViolation,
            ),
            (
                "401 Unauthorized",
                "unauthenticated",
                PushErrorKind::Unauthenticated,
            ),
            (
                "403 Forbidden",
                "capability_denied",
                PushErrorKind::CapabilityDenied,
            ),
            (
                "409 Conflict",
                "duplicate_conflict",
                PushErrorKind::DuplicateConflict,
            ),
        ];

        for (status, code, expected) in cases {
            let body = format!(
                r#"{{"ok":false,"error":{{"code":"{code}","message":"x"}},"request_id":"cx:request:error"}}"#
            );
            let (base_url, _) = spawn_mock_server(vec![MockResponse {
                status,
                headers: vec![],
                body: Box::leak(body.into_boxed_str()),
            }]);

            let err = client(base_url)
                .register_device(&config(), &binding(), &prefs())
                .await
                .unwrap_err();

            assert_eq!(err.kind(), expected);
            assert_eq!(err.request_id(), Some("cx:request:error"));
        }
    }

    #[tokio::test]
    async fn exposes_non_json_error_body_without_debug_leak() {
        let (base_url, _) = spawn_mock_server(vec![MockResponse {
            status: "500 Internal Server Error",
            headers: vec![],
            body: "not json",
        }]);

        let err = client(base_url)
            .register_device(&config(), &binding(), &prefs())
            .await
            .unwrap_err();

        assert_eq!(err.kind(), PushErrorKind::HttpStatus);
        assert!(format!("{err:?}").contains("body_len"));
        assert!(!format!("{err:?}").contains("not json"));
    }

    #[tokio::test]
    async fn invalid_success_schema_is_invalid_response() {
        let (base_url, _) = spawn_mock_server(vec![MockResponse {
            status: "200 OK",
            headers: vec![],
            body: r#"{"ok":"yes","registration_id":42}"#,
        }]);

        let err = client(base_url)
            .register_device(&config(), &binding(), &prefs())
            .await
            .unwrap_err();

        assert_eq!(err.kind(), PushErrorKind::InvalidResponse);
    }

    #[tokio::test]
    async fn error_debug_redacts_envelope_message_and_details() {
        let (base_url, _) = spawn_mock_server(vec![MockResponse {
            status: "403 Forbidden",
            headers: vec![],
            body: r#"{"ok":false,"error":{"code":"capability_denied","message":"token fcm:very-secret-token proof super-secret-proof","details":{"proof":"super-secret-proof","push_key":"fcm:very-secret-token"}}}"#,
        }]);

        let err = client(base_url)
            .register_device(&config(), &binding(), &prefs())
            .await
            .unwrap_err();

        let debug = format!("{err:?}");
        assert_eq!(err.kind(), PushErrorKind::CapabilityDenied);
        assert!(!debug.contains("very-secret-token"));
        assert!(!debug.contains("super-secret-proof"));
        assert!(debug.contains("details_present"));
    }

    #[tokio::test]
    async fn retries_429_and_honors_retry_after() {
        let (base_url, requests) = spawn_mock_server(vec![
            MockResponse {
                status: "429 Too Many Requests",
                headers: vec![(RETRY_AFTER_HEADER, "0")],
                body: r#"{"ok":false,"error":{"code":"rate_limited","message":"slow"}}"#,
            },
            MockResponse {
                status: "200 OK",
                headers: vec![],
                body: r#"{"ok":true}"#,
            },
        ]);

        let response = client(base_url)
            .with_retry_policy(PushRetryPolicy {
                max_retries: 1,
                initial_backoff: Duration::ZERO,
                max_backoff: Duration::ZERO,
                jitter: Duration::ZERO,
                disabled_kinds_mask: 0,
            })
            .register_device(&config(), &binding(), &prefs())
            .await
            .unwrap();

        assert!(response.ok);
        assert_eq!(requests.lock().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn default_register_rejects_without_session_grant() {
        // Default `require_session_grant = true` ⇒ no mock server needed:
        // the call fails fast before any request is sent.
        let err = ContrixPushClient::new("https://principal.example")
            .register_device(&config(), &binding(), &prefs())
            .await
            .unwrap_err();

        assert_eq!(err.kind(), PushErrorKind::MissingField);
    }

    #[tokio::test]
    async fn default_register_allows_with_session_grant_header() {
        let (base_url, requests) = spawn_mock_server(vec![MockResponse {
            status: "200 OK",
            headers: vec![],
            body: r#"{"ok":true,"registration_id":"reg-1"}"#,
        }]);

        let response = ContrixPushClient::new(base_url)
            .with_session_grant("coauth-grant-secret")
            .unwrap()
            .register_device(&config(), &binding(), &prefs())
            .await
            .unwrap();

        assert!(response.ok);
        let raw = requests.lock().unwrap().join("\n");
        assert!(raw.contains("x-contrix-session-grant: coauth-grant-secret"));
    }

    #[tokio::test]
    async fn default_unregister_rejects_without_session_grant() {
        let err = ContrixPushClient::new("https://principal.example")
            .unregister_device(&config(), &binding(), &prefs())
            .await
            .unwrap_err();

        assert_eq!(err.kind(), PushErrorKind::MissingField);
    }

    #[tokio::test]
    async fn opting_out_session_grant_allows_register_without_header() {
        let (base_url, _) = spawn_mock_server(vec![MockResponse {
            status: "200 OK",
            headers: vec![],
            body: r#"{"ok":true}"#,
        }]);

        let response = ContrixPushClient::new(base_url)
            .with_required_session_grant(false)
            .register_device(&config(), &binding(), &prefs())
            .await
            .unwrap();

        assert!(response.ok);
    }

    #[tokio::test]
    async fn register_auto_generates_idempotency_key_when_omitted() {
        let (base_url, requests) = spawn_mock_server(vec![
            MockResponse {
                status: "503 Service Unavailable",
                headers: vec![(RETRY_AFTER_HEADER, "0")],
                body: r#"{"ok":false,"error":{"code":"temporarily_unavailable","message":"try later"}}"#,
            },
            MockResponse {
                status: "200 OK",
                headers: vec![],
                body: r#"{"ok":true}"#,
            },
        ]);
        let mut config = config();
        config.idempotency_key = None;

        let response = client(base_url)
            .with_retry_policy(PushRetryPolicy {
                max_retries: 1,
                initial_backoff: Duration::ZERO,
                max_backoff: Duration::ZERO,
                jitter: Duration::ZERO,
                disabled_kinds_mask: 0,
            })
            .register_device(&config, &binding(), &prefs())
            .await
            .unwrap();

        assert!(response.ok);

        let recorded = requests.lock().unwrap();
        assert_eq!(
            recorded.len(),
            2,
            "auto-generated key should make POST retryable"
        );

        let key_of = |raw: &String| -> Option<String> {
            raw.lines()
                .find(|line| line.to_ascii_lowercase().starts_with("idempotency-key:"))
                .and_then(|line| line.split_once(':'))
                .map(|(_, value)| value.trim().to_owned())
        };

        let first = key_of(&recorded[0]).expect("first request carries idempotency key");
        let second = key_of(&recorded[1]).expect("retry carries idempotency key");
        assert_eq!(first, second, "retry must reuse the same key");
        assert!(first.starts_with("cx-sdk-"));
    }

    #[tokio::test]
    async fn does_not_retry_duplicate_conflict() {
        let (base_url, requests) = spawn_mock_server(vec![MockResponse {
            status: "409 Conflict",
            headers: vec![],
            body: r#"{"ok":false,"error":{"code":"duplicate_conflict","message":"different body"}}"#,
        }]);

        let err = client(base_url)
            .with_retry_policy(PushRetryPolicy {
                max_retries: 2,
                initial_backoff: Duration::ZERO,
                max_backoff: Duration::ZERO,
                jitter: Duration::ZERO,
                disabled_kinds_mask: 0,
            })
            .register_device(&config(), &binding(), &prefs())
            .await
            .unwrap_err();

        assert_eq!(err.kind(), PushErrorKind::DuplicateConflict);
        assert_eq!(requests.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn retries_503() {
        let (base_url, requests) = spawn_mock_server(vec![
            MockResponse {
                status: "503 Service Unavailable",
                headers: vec![(RETRY_AFTER_HEADER, "0")],
                body: r#"{"ok":false,"error":{"code":"temporarily_unavailable","message":"try later"}}"#,
            },
            MockResponse {
                status: "200 OK",
                headers: vec![],
                body: r#"{"ok":true}"#,
            },
        ]);

        let response = client(base_url)
            .with_retry_policy(PushRetryPolicy {
                max_retries: 1,
                initial_backoff: Duration::ZERO,
                max_backoff: Duration::ZERO,
                jitter: Duration::ZERO,
                disabled_kinds_mask: 0,
            })
            .register_device(&config(), &binding(), &prefs())
            .await
            .unwrap();

        assert!(response.ok);
        assert_eq!(requests.lock().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn disabled_kinds_skip_otherwise_retryable_error() {
        // 503 normally retries, but with TemporarilyUnavailable disabled
        // the very first response should be surfaced immediately.
        let (base_url, requests) = spawn_mock_server(vec![MockResponse {
            status: "503 Service Unavailable",
            headers: vec![(RETRY_AFTER_HEADER, "0")],
            body: r#"{"ok":false,"error":{"code":"temporarily_unavailable","message":"down"}}"#,
        }]);

        let policy = PushRetryPolicy {
            max_retries: 3,
            initial_backoff: Duration::ZERO,
            max_backoff: Duration::ZERO,
            jitter: Duration::ZERO,
            disabled_kinds_mask: 0,
        }
        .with_disabled_kinds(&[PushErrorKind::TemporarilyUnavailable]);

        assert!(policy.retries_disabled_for(PushErrorKind::TemporarilyUnavailable));
        assert!(!policy.retries_disabled_for(PushErrorKind::RateLimited));

        let err = client(base_url)
            .with_retry_policy(policy)
            .register_device(&config(), &binding(), &prefs())
            .await
            .unwrap_err();

        assert_eq!(err.kind(), PushErrorKind::TemporarilyUnavailable);
        assert_eq!(requests.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn register_device_all_exercises_each_binding_independently() {
        // Two bindings → two responses. We pre-load the mock server
        // with one response per expected request.
        let (base_url, requests) = spawn_mock_server(vec![
            MockResponse {
                status: "200 OK",
                headers: vec![],
                body: r#"{"ok":true,"registration_id":"reg-standard"}"#,
            },
            MockResponse {
                status: "200 OK",
                headers: vec![],
                body: r#"{"ok":true,"registration_id":"reg-bugle"}"#,
            },
        ]);

        let prefs = PushPreferences {
            enabled: true,
            gateways: vec![
                crate::GatewayBinding::new(
                    crate::PushGatewayType::Standard,
                    "https://push.example.com/api/v1/push/notify",
                ),
                crate::GatewayBinding::new(
                    crate::PushGatewayType::Bugle,
                    "https://push.palpo.im/api/v1/push/notify",
                )
                .with_push_key("vendor-token-cn-aaaaaaaaaa")
                .with_app_id("app.example.android.cn"),
            ],
            ..Default::default()
        };

        let results = client(base_url)
            .register_device_all(&config(), &prefs)
            .await;

        assert_eq!(results.len(), 2);
        let r0 = results[0].as_ref().unwrap();
        let r1 = results[1].as_ref().unwrap();
        assert_eq!(r0.registration_id.as_deref(), Some("reg-standard"));
        assert_eq!(r1.registration_id.as_deref(), Some("reg-bugle"));

        let raw = requests.lock().unwrap().join("\n");
        // Standard gateway uses caller-supplied token; Bugle uses
        // per-binding override.
        assert!(raw.contains("https://push.example.com"));
        assert!(raw.contains("https://push.palpo.im"));
        assert!(raw.contains("vendor-token-cn-aaaaaaaaaa"));
        // Per-binding app_id override propagates to the Bugle request.
        assert!(raw.contains("app.example.android.cn"));
    }

    #[tokio::test]
    async fn register_device_all_returns_empty_when_no_bindings_configured() {
        // No mock server needed — empty `gateways` means no HTTP work.
        let results = client("http://127.0.0.1:1")
            .register_device_all(&config(), &prefs())
            .await;

        assert!(results.is_empty());
    }

    /// A.5 #2 — formatting a [`ContrixPushClient`] through `{:?}` MUST
    /// NOT leak the bearer token. We assert the redaction marker is
    /// present and the secret is absent in both the option-empty and
    /// option-present arms so a future refactor that drops the
    /// `SecretString` wrapper trips this test.
    #[test]
    fn bearer_token_is_redacted_in_debug_output() {
        let secret = "super-secret-session-bearer-do-not-log";

        let no_token = ContrixPushClient::new("https://principal.example");
        let no_token_debug = format!("{no_token:?}");
        assert!(no_token_debug.contains("bearer_token: None"));
        assert!(!no_token_debug.contains(secret));

        let with_token =
            ContrixPushClient::new("https://principal.example").with_bearer_token(secret);
        let debug = format!("{with_token:?}");
        assert!(
            !debug.contains(secret),
            "bearer token leaked through Debug: {debug}"
        );
        assert!(
            debug.contains("<redacted>"),
            "Debug output is missing the redaction marker: {debug}"
        );
    }
}
