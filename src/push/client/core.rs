use std::fmt;
use std::time::Duration;

use super::super::bridge_describe::{
    IntegrationView, PushBridgeDescribeOutcome, PushGatewayIntegrationDescribeOutcome,
};
use super::super::errors::{PushErrorKind, PushRegistrationError};
use super::super::registration::{build_register_device_request, build_unregister_device_request};
use super::super::urls::redact_url;
use super::super::wire::{
    ChimePushRegisterDeviceOutcome, ChimePushRegisterDeviceRequest,
    ChimePushUnregisterDeviceOutcome, ChimePushUnregisterDeviceRequest, PushDeviceConfig,
};
use super::super::{
    ARKRET_SESSION_GRANT_HEADER, FLORIA_INTEGRATION_DESCRIBE_PATH,
    FLORIA_PUSH_BRIDGE_DESCRIBE_PATH, REGISTER_DEVICE_PATH, SDK_USER_AGENT, SERVER_DESCRIBE_PATH,
    UNREGISTER_DEVICE_PATH,
};
use super::retry::{PushRetryPolicy, retry_jitter_seed};
use super::secret::SecretString;
use super::transport::{CokretHttpOutcome, default_http_client};
use crate::{GatewayBinding, PushPreferences};

#[derive(Clone)]
pub struct CokretPushClient {
    pub(super) http: reqwest::Client,
    pub(super) service_base_url: String,
    // A.5 #2 — bearer token is held in a zeroize-on-drop wrapper so
    // it does not linger in freed heap allocations after the client is
    // dropped. The Debug impl below redacts it.
    pub(super) bearer_token: Option<SecretString>,
    pub(super) timeout: Option<Duration>,
    pub(super) retry_policy: PushRetryPolicy,
    pub(super) retry_jitter_seed: u64,
    pub(super) user_agent: String,
    pub(super) headers: Vec<(reqwest::header::HeaderName, reqwest::header::HeaderValue)>,
    pub(super) default_idempotency_key: Option<String>,
    pub(super) default_request_id: Option<String>,
    pub(super) require_session_grant: bool,
    // Bridge-discovered path overrides. When the gateway advertises a
    // non-default register/unregister path through `bridge/describe`,
    // hosts (e.g. inkson) need to route through it instead of the
    // baked-in `REGISTER_DEVICE_PATH` constant.
    pub(super) register_device_path: Option<String>,
    pub(super) unregister_device_path: Option<String>,
}

impl fmt::Debug for CokretPushClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // A.5 #2 — `SecretString::Debug` already prints `<redacted>`,
        // so handing the `Option<SecretString>` straight to
        // `debug_struct` cannot leak the token. The explicit cast to
        // `Option<&SecretString>` makes that contract grep-able.
        let bearer: Option<&SecretString> = self.bearer_token.as_ref();
        f.debug_struct("CokretPushClient")
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

impl CokretPushClient {
    pub fn new(service_base_url: impl Into<String>) -> Self {
        Self {
            http: default_http_client(),
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

    /// Override the underlying `reqwest::Client`.
    ///
    /// On native targets, the injected client SHOULD disable redirect-following
    /// (`reqwest::redirect::Policy::none()`). Otherwise a cross-host 3xx from
    /// a compromised or misconfigured service can re-send the credential-bearing
    /// `x-arkret-session-grant` and HTTP Message Signature headers to the
    /// redirect target (reqwest does not strip custom headers across redirects).
    /// The default native client built by [`Self::new`] already disables
    /// redirects. On wasm32, reqwest delegates to browser Fetch and exposes no
    /// redirect-policy builder API.
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
        self.with_header(ARKRET_SESSION_GRANT_HEADER, session_grant)
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
    /// `X-Arkret-Session-Grant` header has been attached via
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

    /// Discover the Arkret service through the protocol `/_cokret/describe` surface.
    pub async fn server_describe(&self) -> Result<arkret::ServiceDescribe, PushRegistrationError> {
        Ok(self.server_describe_with_context().await?.body)
    }

    /// Discover the Arkret service and return response metadata.
    pub async fn server_describe_with_context(
        &self,
    ) -> Result<CokretHttpOutcome<arkret::ServiceDescribe>, PushRegistrationError> {
        self.get_json(SERVER_DESCRIBE_PATH).await
    }

    /// Discover floria's product-local active push gateway bridge contract.
    pub async fn floria_bridge_describe(
        &self,
    ) -> Result<PushBridgeDescribeOutcome, PushRegistrationError> {
        Ok(self.floria_bridge_describe_with_context().await?.body)
    }

    /// Discover floria's bridge contract and return response metadata.
    pub async fn floria_bridge_describe_with_context(
        &self,
    ) -> Result<CokretHttpOutcome<PushBridgeDescribeOutcome>, PushRegistrationError> {
        self.get_json(FLORIA_PUSH_BRIDGE_DESCRIBE_PATH).await
    }

    /// Discover floria's service-level push gateway integration manifest.
    pub async fn floria_integration_describe(
        &self,
    ) -> Result<PushGatewayIntegrationDescribeOutcome, PushRegistrationError> {
        Ok(self.floria_integration_describe_with_context().await?.body)
    }

    /// Discover floria's service-level integration manifest and return response metadata.
    pub async fn floria_integration_describe_with_context(
        &self,
    ) -> Result<CokretHttpOutcome<PushGatewayIntegrationDescribeOutcome>, PushRegistrationError>
    {
        self.get_json(FLORIA_INTEGRATION_DESCRIBE_PATH).await
    }

    /// Fetch both floria's service-level integration manifest and active bridge
    /// contract and return them as a single [`IntegrationView`].
    ///
    /// The two requests run sequentially. Either failure short-circuits.
    pub async fn floria_integration_view(&self) -> Result<IntegrationView, PushRegistrationError> {
        let manifest = self.floria_integration_describe().await?;
        let bridge = self.floria_bridge_describe().await?;
        Ok(IntegrationView::new(manifest, bridge))
    }

    /// Register a push-capable device with a Arkret service against
    /// a specific gateway binding.
    ///
    /// When `prefs.enabled` is false, this method performs an idempotent
    /// unregister call and returns an `ok` register-shaped response.
    ///
    /// ```rust,no_run
    /// # async fn doc_run() -> Result<(), chime::PushRegistrationError> {
    /// # use chime::{GatewayBinding, PushDeviceConfig, PushGatewayType, PushPreferences};
    /// # let config = PushDeviceConfig {
    /// #     principal_id: None,
    /// #     device_id: "did:web:alice.example#device-phone",
    /// #     push_key: Some("fcm-or-apns-device-token"),
    /// #     platform: None, app_id: None, domestic_app_id: None,
    /// #     registration_id: None, display_name: None,
    /// #     idempotency_key: None, request_id: None, proof: None,
    /// # };
    /// # let binding = GatewayBinding::new(
    /// #     PushGatewayType::Standard,
    /// #     "https://push.example.com/_cokret/edge/push/notify",
    /// # );
    /// # let prefs = PushPreferences {
    /// #     enabled: true,
    /// #     ..Default::default()
    /// # };
    /// use std::time::Duration;
    ///
    /// use chime::{CokretPushClient, PushRetryPolicy};
    ///
    /// let client = CokretPushClient::new("https://principal.example")
    ///     .with_bearer_token("session-token")
    ///     .with_timeout(Duration::from_secs(10))
    ///     .with_retry_policy(PushRetryPolicy::conservative());
    /// let response = client.register_device(&config, &binding, &prefs).await?;
    /// assert!(response.ok);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// Live coverage of this strand lives in `tests/live_floria_integration.rs`,
    /// which spawns a real `floria` push gateway on a loopback port.
    pub async fn register_device(
        &self,
        config: &PushDeviceConfig<'_>,
        binding: &GatewayBinding,
        prefs: &PushPreferences,
    ) -> Result<ChimePushRegisterDeviceOutcome, PushRegistrationError> {
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
    ) -> Result<CokretHttpOutcome<ChimePushRegisterDeviceOutcome>, PushRegistrationError> {
        self.assert_session_grant_if_required()?;
        if !prefs.enabled {
            let response = self
                .unregister_device_with_context(config, binding, prefs)
                .await?;
            return Ok(response.map_body(|body| ChimePushRegisterDeviceOutcome {
                ok: body.ok,
                registration_id: None,
                expires_at: None,
            }));
        }

        let body = build_register_device_request(config, binding, prefs)?;
        let sdk_body = body.to_sdk_request()?;
        let response: CokretHttpOutcome<arkret::PushRegisterDeviceOutcome> = self
            .post_json(
                self.effective_register_device_path(),
                &sdk_body,
                config.idempotency_key,
                config.request_id,
            )
            .await?;
        let response = response.map_body(ChimePushRegisterDeviceOutcome::from);

        tracing::info!(
            platform = body.platform.as_deref().unwrap_or("unspecified"),
            gateway = binding.gateway_type.display_name(),
            operation_id = crate::OPERATION_PUSH_REGISTER_DEVICE,
            request_id = response.request_id.as_deref(),
            "Arkret push device registered"
        );

        Ok(response)
    }

    /// Post a pre-built [`ChimePushRegisterDeviceRequest`] through the
    /// configured client (session-grant header, retry policy,
    /// caller-supplied headers, register-device path override all
    /// honored). Use this when callers already constructed the wire
    /// body — typically because they cached it for retry or built it
    /// in one place and post in another (inkson's bridge-discovered
    /// register strand does this) — and would otherwise have to rebuild
    /// it via `build_register_device_request`.
    pub async fn register_device_with_request(
        &self,
        body: &ChimePushRegisterDeviceRequest,
        idempotency_key: Option<&str>,
        request_id: Option<&str>,
    ) -> Result<CokretHttpOutcome<ChimePushRegisterDeviceOutcome>, PushRegistrationError> {
        self.assert_session_grant_if_required()?;
        let sdk_body = body.to_sdk_request()?;
        let response: CokretHttpOutcome<arkret::PushRegisterDeviceOutcome> = self
            .post_json(
                self.effective_register_device_path(),
                &sdk_body,
                idempotency_key.or(body.idempotency_key.as_deref()),
                request_id,
            )
            .await?;
        let response = response.map_body(ChimePushRegisterDeviceOutcome::from);

        tracing::info!(
            platform = body.platform.as_deref().unwrap_or("unspecified"),
            operation_id = crate::OPERATION_PUSH_REGISTER_DEVICE,
            request_id = response.request_id.as_deref(),
            "Arkret push device registered (prebuilt body)"
        );

        Ok(response)
    }

    /// Symmetric counterpart of
    /// [`register_device_with_request`](Self::register_device_with_request)
    /// for unregister strands.
    pub async fn unregister_device_with_request(
        &self,
        body: &ChimePushUnregisterDeviceRequest,
        idempotency_key: Option<&str>,
        request_id: Option<&str>,
    ) -> Result<CokretHttpOutcome<ChimePushUnregisterDeviceOutcome>, PushRegistrationError> {
        self.assert_session_grant_if_required()?;
        let sdk_body = body.to_sdk_request()?;
        let response = match self
            .post_json(
                self.effective_unregister_device_path(),
                &sdk_body,
                idempotency_key.or(body.idempotency_key.as_deref()),
                request_id,
            )
            .await
        {
            Ok(response) => {
                let response: CokretHttpOutcome<arkret::PushUnregisterDeviceOutcome> = response;
                let response_request_id = response.request_id.clone();
                response.map_body(|body| {
                    let mut body = ChimePushUnregisterDeviceOutcome::from(body);
                    body.request_id = response_request_id;
                    body
                })
            }
            Err(error) if error.kind() == PushErrorKind::NotFound => CokretHttpOutcome {
                body: ChimePushUnregisterDeviceOutcome {
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

    /// Unregister a push-capable device from a Arkret service against
    /// a specific gateway binding.
    pub async fn unregister_device(
        &self,
        config: &PushDeviceConfig<'_>,
        binding: &GatewayBinding,
        prefs: &PushPreferences,
    ) -> Result<ChimePushUnregisterDeviceOutcome, PushRegistrationError> {
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
    ) -> Result<CokretHttpOutcome<ChimePushUnregisterDeviceOutcome>, PushRegistrationError> {
        self.assert_session_grant_if_required()?;
        let body = build_unregister_device_request(config, binding, prefs)?;
        let sdk_body = body.to_sdk_request()?;
        let response = match self
            .post_json(
                self.effective_unregister_device_path(),
                &sdk_body,
                config.idempotency_key,
                config.request_id,
            )
            .await
        {
            Ok(response) => {
                let response: CokretHttpOutcome<arkret::PushUnregisterDeviceOutcome> = response;
                let response_request_id = response.request_id.clone();
                response.map_body(|body| {
                    let mut body = ChimePushUnregisterDeviceOutcome::from(body);
                    body.request_id = response_request_id;
                    body
                })
            }
            Err(error) if error.kind() == PushErrorKind::NotFound => CokretHttpOutcome {
                body: ChimePushUnregisterDeviceOutcome {
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
            "Arkret push device unregistered"
        );

        Ok(response)
    }

    /// Register the device against every binding in
    /// [`PushPreferences::gateways`](crate::PushPreferences::gateways).
    ///
    /// Each binding is exercised independently — a failure on one
    /// binding does not abort the others. Returns one
    /// `Result<ChimePushRegisterDeviceOutcome, _>` per binding, in the same
    /// order as `prefs.gateways`. When `prefs.gateways` is empty the
    /// returned `Vec` is empty.
    ///
    /// Per-binding `push_key` and `app_id` overrides on the binding
    /// take priority over the values in `config`. The base
    /// `device_id`, `principal_id`, `platform`, `idempotency_key`,
    /// `request_id`, and `proof` are shared across bindings.
    pub async fn register_device_all(
        &self,
        config: &PushDeviceConfig<'_>,
        prefs: &PushPreferences,
    ) -> Vec<Result<ChimePushRegisterDeviceOutcome, PushRegistrationError>> {
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
    ) -> Result<Option<ChimePushRegisterDeviceOutcome>, PushRegistrationError> {
        let plan =
            crate::plan_token_rotation_with_strategy(existing, config, binding, prefs, strategy)?;

        if !plan.token_changed {
            return Ok(None);
        }

        let response = match strategy {
            crate::PushTokenRotationStrategy::UnregisterOldFirst => {
                if plan.unregister_old.is_some() {
                    self.unregister_old_token_for_rotation(config, binding, prefs)
                        .await;
                }
                self.register_device(config, binding, prefs).await?
            }
            crate::PushTokenRotationStrategy::RegisterNewFirst => {
                let response = self.register_device(config, binding, prefs).await?;
                if plan.unregister_old.is_some() {
                    self.unregister_old_token_for_rotation(config, binding, prefs)
                        .await;
                }
                response
            }
        };

        Ok(Some(response))
    }

    async fn unregister_old_token_for_rotation(
        &self,
        config: &PushDeviceConfig<'_>,
        binding: &GatewayBinding,
        prefs: &PushPreferences,
    ) {
        if let Err(error) = self.unregister_device(config, binding, prefs).await {
            tracing::warn!(
                error_kind = ?error.kind(),
                status = error.status(),
                request_id = error.request_id(),
                gateway = binding.gateway_type.display_name(),
                "Arkret push old token unregister failed during token rotation"
            );
        }
    }

    pub(super) fn assert_session_grant_if_required(&self) -> Result<(), PushRegistrationError> {
        if self.require_session_grant && !self.has_header(ARKRET_SESSION_GRANT_HEADER) {
            return Err(PushRegistrationError::MissingField("session_grant"));
        }
        Ok(())
    }

    fn has_header(&self, name: &str) -> bool {
        self.headers
            .iter()
            .any(|(header_name, _)| header_name.as_str().eq_ignore_ascii_case(name))
    }
}
