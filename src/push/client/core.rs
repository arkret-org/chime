use std::fmt;
use std::time::Duration;

use arkret_models_integration::{PushRegisterDeviceOutcome, PushUnregisterDeviceOutcome};

use super::super::bridge_describe::PushBridgeDescribeOutcome;
use super::super::errors::{PushErrorKind, PushRegistrationError};
use super::super::urls::redact_url;
use super::super::wire::{ChimePushRegisterDeviceRequest, ChimePushUnregisterDeviceRequest};
use super::super::{
    ARKRET_SESSION_GRANT_HEADER, FLORIA_PUSH_BRIDGE_DESCRIBE_PATH, REGISTER_DEVICE_PATH,
    SDK_USER_AGENT, UNREGISTER_DEVICE_PATH,
};
use super::retry::{PushRetryPolicy, retry_jitter_seed};
use super::secret::SecretString;
use super::transport::{ArkretHttpOutcome, default_http_client};

#[derive(Clone)]
pub struct ArkretPushClient {
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
    pub(super) require_session_grant: bool,
}

impl fmt::Debug for ArkretPushClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // A.5 #2 — `SecretString::Debug` already prints `<redacted>`,
        // so handing the `Option<SecretString>` straight to
        // `debug_struct` cannot leak the token. The explicit cast to
        // `Option<&SecretString>` makes that contract grep-able.
        let bearer: Option<&SecretString> = self.bearer_token.as_ref();
        f.debug_struct("ArkretPushClient")
            .field("service_base_url", &redact_url(&self.service_base_url))
            .field("bearer_token", &bearer)
            .field("timeout", &self.timeout)
            .field("retry_policy", &self.retry_policy)
            .field("user_agent", &self.user_agent)
            .field("header_count", &self.headers.len())
            .field("require_session_grant", &self.require_session_grant)
            .finish()
    }
}

impl ArkretPushClient {
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
            // Default: register/unregister fail-closed unless the caller
            // attaches a session grant. Tests / dev sandboxes that want to
            // opt out can call `.with_required_session_grant(false)`.
            require_session_grant: true,
        }
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

    pub fn with_session_grant(
        self,
        session_grant: impl AsRef<str>,
    ) -> Result<Self, PushRegistrationError> {
        self.with_header(ARKRET_SESSION_GRANT_HEADER, session_grant)
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

    /// Add a caller-supplied header, for example an externally signed
    /// session-grant proof.
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

    /// Discover floria's product-local active push gateway bridge contract.
    pub async fn floria_bridge_describe(
        &self,
    ) -> Result<PushBridgeDescribeOutcome, PushRegistrationError> {
        Ok(self
            .get_json::<PushBridgeDescribeOutcome>(FLORIA_PUSH_BRIDGE_DESCRIBE_PATH)
            .await?
            .body)
    }

    /// Post a pre-built [`ChimePushRegisterDeviceRequest`] through the
    /// configured client (session-grant header, retry policy, and
    /// caller-supplied headers all honored). Use this when callers
    /// already constructed the wire body — typically because they
    /// cached it for retry or built it in one place and post in
    /// another (inkson's register strand does this) — via
    /// `build_register_device_request`.
    pub async fn register_device_with_request(
        &self,
        body: &ChimePushRegisterDeviceRequest,
        idempotency_key: Option<&str>,
        request_id: Option<&str>,
    ) -> Result<ArkretHttpOutcome<PushRegisterDeviceOutcome>, PushRegistrationError> {
        self.assert_session_grant_if_required()?;
        let sdk_body = body.to_sdk_request()?;
        let response: ArkretHttpOutcome<arkret_models_integration::PushRegisterDeviceOutcome> =
            self.post_json(
                REGISTER_DEVICE_PATH,
                &sdk_body,
                idempotency_key.or(body.idempotency_key.as_deref()),
                request_id,
            )
            .await?;

        tracing::info!(
            platform = body.platform.as_deref().unwrap_or("unspecified"),
            operation_id = arkret_wire::ServiceOperationId::EDGE_PUSH_COMMAND_REGISTER_DEVICE,
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
    ) -> Result<ArkretHttpOutcome<PushUnregisterDeviceOutcome>, PushRegistrationError> {
        self.assert_session_grant_if_required()?;
        let sdk_body = body.to_sdk_request()?;
        let response = match self
            .post_json(
                UNREGISTER_DEVICE_PATH,
                &sdk_body,
                idempotency_key.or(body.idempotency_key.as_deref()),
                request_id,
            )
            .await
        {
            Ok(response) => response,
            Err(error) if error.kind() == PushErrorKind::NotFound => ArkretHttpOutcome {
                body: PushUnregisterDeviceOutcome { ok: true },
                request_id: error.request_id().map(str::to_owned),
                retry_after: error.retry_after().map(str::to_owned),
            },
            Err(error) => return Err(error),
        };

        Ok(response)
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
