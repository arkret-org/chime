//! Contrix push device registration request types and HTTP helper.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::PushPreferences;

/// Contrix HTTP path for `cx.push.register_device`.
pub const REGISTER_DEVICE_PATH: &str = "/api/v1/push/register-device";

/// Contrix HTTP path for `cx.push.unregister_device`.
pub const UNREGISTER_DEVICE_PATH: &str = "/api/v1/push/unregister-device";

/// Supported Contrix push platform values.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PushPlatform {
    Android,
    Ios,
    Web,
    Desktop,
}

impl PushPlatform {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Android => "android",
            Self::Ios => "ios",
            Self::Web => "web",
            Self::Desktop => "desktop",
        }
    }
}

impl TryFrom<&str> for PushPlatform {
    type Error = PushRegistrationError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value.to_ascii_lowercase().as_str() {
            "android" => Ok(Self::Android),
            "ios" => Ok(Self::Ios),
            "web" => Ok(Self::Web),
            "desktop" => Ok(Self::Desktop),
            other => Err(PushRegistrationError::InvalidPlatform(other.to_owned())),
        }
    }
}

/// Device configuration supplied by the host app.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PushDeviceConfig<'a> {
    /// Contrix device id, usually a DID fragment such as
    /// `did:web:alice.example#device-phone`.
    pub device_id: &'a str,
    /// Platform push token, e.g. `fcm:...`, `apns:...`, `webpush:...`.
    pub push_key: &'a str,
    /// Optional platform value: `android`, `ios`, `web`, or `desktop`.
    pub platform: Option<&'a str>,
    /// Application package name, bundle id, web app id, or desktop app id.
    pub app_id: Option<&'a str>,
    /// Domestic Android app id used when `PushGatewayType::Bugle` is selected.
    pub domestic_app_id: Option<&'a str>,
    /// User-readable device name.
    pub display_name: Option<&'a str>,
    /// Optional idempotency key sent as the `Idempotency-Key` header by the
    /// HTTP helper.
    pub idempotency_key: Option<&'a str>,
}

/// Request body for `POST /api/v1/push/register-device`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterDeviceRequest {
    pub device_id: String,
    pub push_gateway: String,
    pub push_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub platform: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
}

/// Response body for `POST /api/v1/push/register-device`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterDeviceResponse {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registration_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
}

/// Request body for `POST /api/v1/push/unregister-device`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnregisterDeviceRequest {
    pub device_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub push_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_id: Option<String>,
}

/// Response body for `POST /api/v1/push/unregister-device`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnregisterDeviceResponse {
    pub ok: bool,
}

/// Contrix standard error object.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ContrixError {
    pub code: String,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_after_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub details: Option<Value>,
}

/// Contrix standard error envelope.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ContrixErrorEnvelope {
    pub ok: bool,
    pub error: ContrixError,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
}

#[derive(Debug, Error)]
pub enum PushRegistrationError {
    #[error("missing required Contrix push field: {0}")]
    MissingField(&'static str),
    #[error("unsupported push platform: {0}")]
    InvalidPlatform(String),
    #[error("Contrix service returned HTTP {status}")]
    HttpStatus {
        status: u16,
        error: Option<Box<ContrixErrorEnvelope>>,
        body: String,
    },
    #[cfg(feature = "http")]
    #[error(transparent)]
    Http(#[from] reqwest::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

/// Builds a normalized Contrix API URL.
///
/// `service_base_url` may be either an origin (`https://server.example`) or an
/// API root (`https://server.example/api/v1`).
pub fn contrix_api_url(service_base_url: &str, path: &str) -> String {
    let base = service_base_url.trim_end_matches('/');
    let path = path.trim_start_matches('/');
    let path = path.strip_prefix("api/v1/").unwrap_or(path);

    if base.ends_with("/api/v1") {
        format!("{base}/{path}")
    } else {
        format!("{base}/api/v1/{path}")
    }
}

/// Build the Contrix register-device request body from app configuration and
/// stored push preferences.
pub fn build_register_device_request(
    config: &PushDeviceConfig<'_>,
    prefs: &PushPreferences,
) -> Result<RegisterDeviceRequest, PushRegistrationError> {
    require_non_empty("device_id", config.device_id)?;
    require_non_empty("push_key", config.push_key)?;
    require_non_empty("push_gateway", &prefs.push_gateway)?;

    let platform = parse_platform(config.platform)?;
    let app_id = prefs.app_id(platform, config.app_id, config.domestic_app_id);

    Ok(RegisterDeviceRequest {
        device_id: config.device_id.to_owned(),
        push_gateway: prefs.push_gateway.clone(),
        push_key: config.push_key.to_owned(),
        platform: platform.map(|value| value.as_str().to_owned()),
        app_id: app_id.map(str::to_owned),
        display_name: config.display_name.map(str::to_owned),
    })
}

/// Build the Contrix unregister-device request body from app configuration and
/// stored push preferences.
pub fn build_unregister_device_request(
    config: &PushDeviceConfig<'_>,
    prefs: &PushPreferences,
) -> Result<UnregisterDeviceRequest, PushRegistrationError> {
    require_non_empty("device_id", config.device_id)?;

    let platform = parse_platform(config.platform)?;
    let app_id = prefs.app_id(platform, config.app_id, config.domestic_app_id);

    Ok(UnregisterDeviceRequest {
        device_id: config.device_id.to_owned(),
        push_key: non_empty(config.push_key).map(str::to_owned),
        app_id: app_id.map(str::to_owned),
    })
}

#[cfg(feature = "http")]
#[derive(Clone, Debug)]
pub struct ContrixPushClient {
    http: reqwest::Client,
    service_base_url: String,
    bearer_token: Option<String>,
}

#[cfg(feature = "http")]
impl ContrixPushClient {
    pub fn new(service_base_url: impl Into<String>) -> Self {
        Self {
            http: reqwest::Client::new(),
            service_base_url: service_base_url.into(),
            bearer_token: None,
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

    /// Register a push-capable device with a Contrix service.
    ///
    /// When `prefs.enabled` is false, this method performs an idempotent
    /// unregister call and returns an `ok` register-shaped response.
    pub async fn register_device(
        &self,
        config: &PushDeviceConfig<'_>,
        prefs: &PushPreferences,
    ) -> Result<RegisterDeviceResponse, PushRegistrationError> {
        if !prefs.enabled {
            let response = self.unregister_device(config, prefs).await?;
            return Ok(RegisterDeviceResponse {
                ok: response.ok,
                registration_id: None,
                expires_at: None,
            });
        }

        let body = build_register_device_request(config, prefs)?;
        let response = self
            .post_json(REGISTER_DEVICE_PATH, &body, config.idempotency_key)
            .await?;

        tracing::info!(
            platform = body.platform.as_deref().unwrap_or("unspecified"),
            gateway = prefs.gateway_type.display_name(),
            operation_id = crate::OPERATION_PUSH_REGISTER_DEVICE,
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
        let body = build_unregister_device_request(config, prefs)?;
        let response = self
            .post_json(UNREGISTER_DEVICE_PATH, &body, config.idempotency_key)
            .await?;

        tracing::info!(
            platform = config.platform.unwrap_or("unspecified"),
            operation_id = crate::OPERATION_PUSH_UNREGISTER_DEVICE,
            "Contrix push device unregistered"
        );

        Ok(response)
    }

    async fn post_json<T, R>(
        &self,
        path: &str,
        body: &T,
        idempotency_key: Option<&str>,
    ) -> Result<R, PushRegistrationError>
    where
        T: Serialize + ?Sized,
        R: for<'de> Deserialize<'de>,
    {
        let url = contrix_api_url(&self.service_base_url, path);
        let mut request = self.http.post(url).json(body);

        if let Some(token) = &self.bearer_token {
            request = request.bearer_auth(token);
        }

        if let Some(idempotency_key) = idempotency_key {
            request = request.header("Idempotency-Key", idempotency_key);
        }

        let response = request.send().await?;
        let status = response.status();
        let body = response.text().await?;

        if !status.is_success() {
            let error = serde_json::from_str::<ContrixErrorEnvelope>(&body)
                .ok()
                .map(Box::new);
            return Err(PushRegistrationError::HttpStatus {
                status: status.as_u16(),
                error,
                body,
            });
        }

        Ok(serde_json::from_str(&body)?)
    }
}

fn parse_platform(value: Option<&str>) -> Result<Option<PushPlatform>, PushRegistrationError> {
    value.map(PushPlatform::try_from).transpose()
}

fn require_non_empty(name: &'static str, value: &str) -> Result<(), PushRegistrationError> {
    if non_empty(value).is_some() {
        Ok(())
    } else {
        Err(PushRegistrationError::MissingField(name))
    }
}

fn non_empty(value: &str) -> Option<&str> {
    let value = value.trim();
    (!value.is_empty()).then_some(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DEFAULT_BUGLE_PUSH_GATEWAY_URL, PushGatewayType};

    fn config<'a>(platform: Option<&'a str>) -> PushDeviceConfig<'a> {
        PushDeviceConfig {
            device_id: "did:web:alice.example#device-phone",
            push_key: "fcm:token",
            platform,
            app_id: Some("app.example.android"),
            domestic_app_id: Some("app.example.android.cn"),
            display_name: Some("Alice Phone"),
            idempotency_key: Some("idem-1"),
        }
    }

    #[test]
    fn rejects_unknown_platform() {
        let err = PushPlatform::try_from("wearable").unwrap_err();
        assert!(
            matches!(err, PushRegistrationError::InvalidPlatform(value) if value == "wearable")
        );
    }

    #[test]
    fn register_request_matches_contrix_schema() {
        let mut prefs = PushPreferences {
            enabled: true,
            gateway_type: PushGatewayType::Bugle,
            ..Default::default()
        };
        prefs.apply_gateway_type_defaults();

        let request = build_register_device_request(&config(Some("android")), &prefs).unwrap();

        assert_eq!(request.device_id, "did:web:alice.example#device-phone");
        assert_eq!(request.push_gateway, DEFAULT_BUGLE_PUSH_GATEWAY_URL);
        assert_eq!(request.push_key, "fcm:token");
        assert_eq!(request.platform.as_deref(), Some("android"));
        assert_eq!(request.app_id.as_deref(), Some("app.example.android.cn"));
        assert_eq!(request.display_name.as_deref(), Some("Alice Phone"));
    }

    #[test]
    fn unregister_request_is_idempotent_shape() {
        let prefs = PushPreferences::default();
        let request = build_unregister_device_request(&config(Some("ios")), &prefs).unwrap();

        assert_eq!(request.device_id, "did:web:alice.example#device-phone");
        assert_eq!(request.push_key.as_deref(), Some("fcm:token"));
        assert_eq!(request.app_id.as_deref(), Some("app.example.android"));
    }

    #[test]
    fn requires_register_push_gateway() {
        let prefs = PushPreferences {
            push_gateway: " ".to_owned(),
            ..Default::default()
        };
        let err = build_register_device_request(&config(Some("android")), &prefs).unwrap_err();
        assert!(matches!(
            err,
            PushRegistrationError::MissingField("push_gateway")
        ));
    }

    #[test]
    fn url_builder_accepts_origin_or_api_root() {
        assert_eq!(
            contrix_api_url("https://server.example", REGISTER_DEVICE_PATH),
            "https://server.example/api/v1/push/register-device"
        );
        assert_eq!(
            contrix_api_url("https://server.example/api/v1", REGISTER_DEVICE_PATH),
            "https://server.example/api/v1/push/register-device"
        );
    }
}
