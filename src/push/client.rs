//! Async HTTP client for the Contrix push register/unregister/describe endpoints.
//!
//! Available only when the `http` feature is enabled.

use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::PushPreferences;

use super::bridge_describe::{
    IntegrationView, PushBridgeDescribeResponse, PushGatewayIntegrationDescribeResponse,
};
use super::errors::{PushErrorKind, PushRegistrationError, classify_http_error};
use super::registration::{build_register_device_request, build_unregister_device_request};
use super::urls::{redact_url, try_contrix_api_url};
use super::wire::{
    ContrixErrorEnvelope, PushDeviceConfig, RegisterDeviceResponse, UnregisterDeviceResponse,
};
use super::{
    CONTRIX_REQUEST_ID_HEADER, CONTRIX_SESSION_GRANT_HEADER, PUSH_BRIDGE_DESCRIBE_PATH,
    PUSH_INTEGRATION_DESCRIBE_PATH, REGISTER_DEVICE_PATH, RETRY_AFTER_HEADER, SDK_USER_AGENT,
    UNREGISTER_DEVICE_PATH,
};

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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PushRetryPolicy {
    pub max_retries: u32,
    pub initial_backoff: Duration,
    pub max_backoff: Duration,
    pub jitter: Duration,
}

impl PushRetryPolicy {
    pub const fn disabled() -> Self {
        Self {
            max_retries: 0,
            initial_backoff: Duration::from_millis(0),
            max_backoff: Duration::from_millis(0),
            jitter: Duration::from_millis(0),
        }
    }

    pub const fn conservative() -> Self {
        Self {
            max_retries: 2,
            initial_backoff: Duration::from_millis(200),
            max_backoff: Duration::from_secs(3),
            jitter: Duration::from_millis(100),
        }
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
    bearer_token: Option<String>,
    timeout: Option<Duration>,
    retry_policy: PushRetryPolicy,
    retry_jitter_seed: u64,
    user_agent: String,
    headers: Vec<(reqwest::header::HeaderName, reqwest::header::HeaderValue)>,
    default_idempotency_key: Option<String>,
    default_request_id: Option<String>,
    require_session_grant: bool,
}

impl fmt::Debug for ContrixPushClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ContrixPushClient")
            .field("service_base_url", &redact_url(&self.service_base_url))
            .field(
                "bearer_token",
                &self.bearer_token.as_ref().map(|_| "<redacted>"),
            )
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
            require_session_grant: false,
        }
    }

    pub fn with_http_client(mut self, http: reqwest::Client) -> Self {
        self.http = http;
        self
    }

    pub fn with_bearer_token(mut self, token: impl Into<String>) -> Self {
        self.bearer_token = Some(token.into());
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

    /// Require register/unregister calls to carry an `X-Contrix-Session-Grant`
    /// header.
    ///
    /// When enabled, [`register_device`](Self::register_device) /
    /// [`unregister_device`](Self::unregister_device) (and their
    /// `_with_context` variants) fail-closed with
    /// [`PushRegistrationError::MissingField("session_grant")`] before sending
    /// any request when no session grant header has been attached via
    /// [`with_session_grant`](Self::with_session_grant) or
    /// [`with_header`](Self::with_header).
    ///
    /// Default is `false`. Recommended for production deployments where
    /// register operations must be tied to a soland session.
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

    /// Register a push-capable device with a Contrix service.
    ///
    /// When `prefs.enabled` is false, this method performs an idempotent
    /// unregister call and returns an `ok` register-shaped response.
    ///
    /// ```rust,ignore
    /// use std::time::Duration;
    /// use chime::{ContrixPushClient, PushRetryPolicy};
    ///
    /// let client = ContrixPushClient::new("https://principal.example")
    ///     .with_bearer_token("session-token")
    ///     .with_timeout(Duration::from_secs(10))
    ///     .with_retry_policy(PushRetryPolicy::conservative());
    /// let response = client.register_device(&config, &prefs).await?;
    /// assert!(response.ok);
    /// ```
    pub async fn register_device(
        &self,
        config: &PushDeviceConfig<'_>,
        prefs: &PushPreferences,
    ) -> Result<RegisterDeviceResponse, PushRegistrationError> {
        Ok(self.register_device_with_context(config, prefs).await?.body)
    }

    /// Register a push-capable device and return response metadata.
    pub async fn register_device_with_context(
        &self,
        config: &PushDeviceConfig<'_>,
        prefs: &PushPreferences,
    ) -> Result<ContrixResponse<RegisterDeviceResponse>, PushRegistrationError> {
        self.assert_session_grant_if_required()?;
        if !prefs.enabled {
            let response = self.unregister_device_with_context(config, prefs).await?;
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

        let body = build_register_device_request(config, prefs)?;
        let response = self
            .post_json(
                REGISTER_DEVICE_PATH,
                &body,
                config.idempotency_key,
                config.request_id,
            )
            .await?;

        tracing::info!(
            platform = body.platform.as_deref().unwrap_or("unspecified"),
            gateway = prefs.gateway_type.display_name(),
            operation_id = crate::OPERATION_PUSH_REGISTER_DEVICE,
            request_id = response.request_id.as_deref(),
            "Contrix push device registered"
        );

        Ok(response)
    }

    /// Unregister a push-capable device from a Contrix service.
    pub async fn unregister_device(
        &self,
        config: &PushDeviceConfig<'_>,
        prefs: &PushPreferences,
    ) -> Result<UnregisterDeviceResponse, PushRegistrationError> {
        Ok(self
            .unregister_device_with_context(config, prefs)
            .await?
            .body)
    }

    /// Unregister a push-capable device and return response metadata.
    pub async fn unregister_device_with_context(
        &self,
        config: &PushDeviceConfig<'_>,
        prefs: &PushPreferences,
    ) -> Result<ContrixResponse<UnregisterDeviceResponse>, PushRegistrationError> {
        self.assert_session_grant_if_required()?;
        let body = build_unregister_device_request(config, prefs)?;
        let response = match self
            .post_json(
                UNREGISTER_DEVICE_PATH,
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
                    if retry_count < self.retry_policy.max_retries && error.is_retryable() =>
                {
                    let delay = error
                        .retry_after_duration()
                        .unwrap_or_else(|| self.backoff_delay(retry_count));
                    if !delay.is_zero() {
                        tokio::time::sleep(delay).await;
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
                    if retry_count < self.retry_policy.max_retries && error.is_retryable() =>
                {
                    let delay = error
                        .retry_after_duration()
                        .unwrap_or_else(|| self.backoff_delay(retry_count));
                    if !delay.is_zero() {
                        tokio::time::sleep(delay).await;
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
            request = request.bearer_auth(token);
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
            request = request.bearer_auth(token);
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

        let mut value =
            self.retry_jitter_seed ^ ((retry_count as u64).wrapping_add(1) * 0x9E37_79B9_7F4A_7C15);
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
            request_id: Some("cx:req:test"),
            proof: None,
        }
    }

    fn prefs() -> PushPreferences {
        PushPreferences {
            enabled: true,
            push_gateway: "https://push.example.com/api/v1/push/notify".to_owned(),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn register_success_exposes_response_context_and_headers() {
        let (base_url, requests) = spawn_mock_server(vec![MockResponse {
            status: "200 OK",
            headers: vec![(CONTRIX_REQUEST_ID_HEADER, "cx:req:server")],
            body: r#"{"ok":true,"registration_id":"reg-1","expires_at":"2026-04-29T00:00:00Z"}"#,
        }]);

        let response = ContrixPushClient::new(base_url)
            .with_bearer_token("session-secret")
            .with_user_agent("test-agent")
            .with_header(
                "Signature-Input",
                r#"sig1=("@method" "@target-uri" "content-digest")"#,
            )
            .unwrap()
            .register_device_with_context(&config(), &prefs())
            .await
            .unwrap();

        assert!(response.body.ok);
        assert_eq!(response.body.registration_id.as_deref(), Some("reg-1"));
        assert_eq!(response.request_id.as_deref(), Some("cx:req:server"));

        let request = requests.lock().unwrap().join("\n");
        assert!(request.contains("POST /api/v1/push/register-device HTTP/1.1"));
        assert!(request.contains("authorization: Bearer session-secret"));
        assert!(request.contains("idempotency-key: idem-1"));
        assert!(request.contains("x-contrix-request-id: cx:req:test"));
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
            .with_default_request_id("cx:req:client")
            .with_session_grant("coauth-grant-secret")
            .unwrap()
            .register_device(&config, &prefs())
            .await
            .unwrap();

        let request = requests.lock().unwrap().join("\n");
        assert!(request.contains("idempotency-key: client-idem"));
        assert!(request.contains("x-contrix-request-id: cx:req:client"));
        assert!(request.contains("x-contrix-session-grant: coauth-grant-secret"));
    }

    #[tokio::test]
    async fn unregister_success() {
        let (base_url, requests) = spawn_mock_server(vec![MockResponse {
            status: "200 OK",
            headers: vec![],
            body: r#"{"ok":true}"#,
        }]);

        let response = ContrixPushClient::new(base_url)
            .unregister_device(&config(), &prefs())
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
            headers: vec![(CONTRIX_REQUEST_ID_HEADER, "cx:req:not-found")],
            body: r#"{"ok":false,"error":{"code":"not_found","message":"missing"}}"#,
        }]);

        let response = ContrixPushClient::new(base_url)
            .unregister_device_with_context(&config(), &prefs())
            .await
            .unwrap();

        assert!(response.body.ok);
        assert_eq!(response.request_id.as_deref(), Some("cx:req:not-found"));
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
                r#"{{"ok":false,"error":{{"code":"{code}","message":"x"}},"request_id":"cx:req:error"}}"#
            );
            let (base_url, _) = spawn_mock_server(vec![MockResponse {
                status,
                headers: vec![],
                body: Box::leak(body.into_boxed_str()),
            }]);

            let err = ContrixPushClient::new(base_url)
                .register_device(&config(), &prefs())
                .await
                .unwrap_err();

            assert_eq!(err.kind(), expected);
            assert_eq!(err.request_id(), Some("cx:req:error"));
        }
    }

    #[tokio::test]
    async fn exposes_non_json_error_body_without_debug_leak() {
        let (base_url, _) = spawn_mock_server(vec![MockResponse {
            status: "500 Internal Server Error",
            headers: vec![],
            body: "not json",
        }]);

        let err = ContrixPushClient::new(base_url)
            .register_device(&config(), &prefs())
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

        let err = ContrixPushClient::new(base_url)
            .register_device(&config(), &prefs())
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

        let err = ContrixPushClient::new(base_url)
            .register_device(&config(), &prefs())
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

        let response = ContrixPushClient::new(base_url)
            .with_retry_policy(PushRetryPolicy {
                max_retries: 1,
                initial_backoff: Duration::ZERO,
                max_backoff: Duration::ZERO,
                jitter: Duration::ZERO,
            })
            .register_device(&config(), &prefs())
            .await
            .unwrap();

        assert!(response.ok);
        assert_eq!(requests.lock().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn require_session_grant_rejects_register_without_header() {
        // No mock server needed — the call fails before sending.
        let err = ContrixPushClient::new("https://principal.example")
            .with_required_session_grant(true)
            .register_device(&config(), &prefs())
            .await
            .unwrap_err();

        assert_eq!(err.kind(), PushErrorKind::MissingField);
    }

    #[tokio::test]
    async fn require_session_grant_allows_register_when_header_present() {
        let (base_url, requests) = spawn_mock_server(vec![MockResponse {
            status: "200 OK",
            headers: vec![],
            body: r#"{"ok":true,"registration_id":"reg-1"}"#,
        }]);

        let response = ContrixPushClient::new(base_url)
            .with_required_session_grant(true)
            .with_session_grant("coauth-grant-secret")
            .unwrap()
            .register_device(&config(), &prefs())
            .await
            .unwrap();

        assert!(response.ok);
        let raw = requests.lock().unwrap().join("\n");
        assert!(raw.contains("x-contrix-session-grant: coauth-grant-secret"));
    }

    #[tokio::test]
    async fn require_session_grant_rejects_unregister_without_header() {
        let err = ContrixPushClient::new("https://principal.example")
            .with_required_session_grant(true)
            .unregister_device(&config(), &prefs())
            .await
            .unwrap_err();

        assert_eq!(err.kind(), PushErrorKind::MissingField);
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

        let response = ContrixPushClient::new(base_url)
            .with_retry_policy(PushRetryPolicy {
                max_retries: 1,
                initial_backoff: Duration::ZERO,
                max_backoff: Duration::ZERO,
                jitter: Duration::ZERO,
            })
            .register_device(&config, &prefs())
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

        let err = ContrixPushClient::new(base_url)
            .with_retry_policy(PushRetryPolicy {
                max_retries: 2,
                initial_backoff: Duration::ZERO,
                max_backoff: Duration::ZERO,
                jitter: Duration::ZERO,
            })
            .register_device(&config(), &prefs())
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

        let response = ContrixPushClient::new(base_url)
            .with_retry_policy(PushRetryPolicy {
                max_retries: 1,
                initial_backoff: Duration::ZERO,
                max_backoff: Duration::ZERO,
                jitter: Duration::ZERO,
            })
            .register_device(&config(), &prefs())
            .await
            .unwrap();

        assert!(response.ok);
        assert_eq!(requests.lock().unwrap().len(), 2);
    }
}
