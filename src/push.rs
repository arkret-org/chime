//! Contrix push device registration request types and HTTP helper.

use std::fmt;
use std::net::IpAddr;
use std::time::{Duration, SystemTime};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;
use url::Url;

use crate::PushPreferences;

/// Contrix HTTP path for `cx.push.register_device`.
pub const REGISTER_DEVICE_PATH: &str = "/api/v1/push/register-device";

/// Contrix HTTP path for `cx.push.unregister_device`.
pub const UNREGISTER_DEVICE_PATH: &str = "/api/v1/push/unregister-device";

/// Contrix HTTP path for discovering the active push gateway bridge contract.
pub const PUSH_BRIDGE_DESCRIBE_PATH: &str = "/api/v1/push/bridge/describe";

/// Header used to correlate Contrix requests across clients and services.
pub const CONTRIX_REQUEST_ID_HEADER: &str = "X-Contrix-Request-Id";

/// RFC 9530 content digest header covered by request signatures.
pub const CONTENT_DIGEST_HEADER: &str = "Content-Digest";

/// Contrix operation id header covered by request signatures.
pub const CONTRIX_OPERATION_ID_HEADER: &str = "X-Contrix-Operation-Id";

/// Contrix device id header covered by request signatures.
pub const CONTRIX_DEVICE_ID_HEADER: &str = "X-Contrix-Device-Id";

/// Contrix request creation timestamp header covered by request signatures.
pub const CONTRIX_CREATED_AT_HEADER: &str = "X-Contrix-Created-At";

/// Contrix request audience header covered by request signatures.
pub const CONTRIX_AUDIENCE_HEADER: &str = "X-Contrix-Audience";

/// Contrix actor DID header covered by request signatures.
pub const CONTRIX_ACTOR_DID_HEADER: &str = "X-Contrix-Actor-Did";

/// Contrix request expiry timestamp header covered by request signatures.
pub const CONTRIX_EXPIRES_AT_HEADER: &str = "X-Contrix-Expires-At";

/// Contrix request origin URL header covered by request signatures.
pub const CONTRIX_ORIGIN_HEADER: &str = "X-Contrix-Origin";

/// Contrix origin service DID header covered by request signatures.
pub const CONTRIX_ORIGIN_SERVICE_DID_HEADER: &str = "X-Contrix-Origin-Service-Did";

/// Contrix destination service DID header covered by request signatures.
pub const CONTRIX_DESTINATION_SERVICE_DID_HEADER: &str = "X-Contrix-Destination-Service-Did";

/// Contrix nonce header covered by request signatures.
pub const CONTRIX_NONCE_HEADER: &str = "X-Contrix-Nonce";

/// Contrix idempotency key metadata header covered by request signatures.
pub const CONTRIX_IDEMPOTENCY_KEY_HEADER: &str = "X-Contrix-Idempotency-Key";

/// Header used to carry an externally supplied coauth/soland session grant.
pub const CONTRIX_SESSION_GRANT_HEADER: &str = "X-Contrix-Session-Grant";

/// HTTP Message Signatures input header.
pub const SIGNATURE_INPUT_HEADER: &str = "Signature-Input";

/// HTTP Message Signatures signature header.
pub const SIGNATURE_HEADER: &str = "Signature";

#[cfg(feature = "http")]
const SDK_USER_AGENT: &str = concat!("chime/", env!("CARGO_PKG_VERSION"));
#[cfg(feature = "http")]
const RETRY_AFTER_HEADER: &str = "Retry-After";

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
#[derive(Clone, Copy)]
pub struct PushDeviceConfig<'a> {
    /// Contrix principal DID that owns this device registration.
    pub principal_did: Option<&'a str>,
    /// Contrix device id, usually a DID fragment such as
    /// `did:web:alice.example#device-phone`.
    pub device_id: &'a str,
    /// Platform push token, e.g. `fcm:...`, `apns:...`, `webpush:...`.
    pub push_key: Option<&'a str>,
    /// Optional platform value: `android`, `ios`, `web`, or `desktop`.
    pub platform: Option<&'a str>,
    /// Application package name, bundle id, web app id, or desktop app id.
    pub app_id: Option<&'a str>,
    /// Domestic Android app id used when `PushGatewayType::Bugle` is selected.
    pub domestic_app_id: Option<&'a str>,
    /// Server-assigned registration id, when known.
    pub registration_id: Option<&'a str>,
    /// User-readable device name.
    pub display_name: Option<&'a str>,
    /// Idempotency key sent both as request metadata and, for services that
    /// persist it, as an optional request body field.
    pub idempotency_key: Option<&'a str>,
    /// Request id sent as `X-Contrix-Request-Id`.
    pub request_id: Option<&'a str>,
    /// Optional caller-supplied DID proof or canonical proof body.
    ///
    /// `chime` does not sign this proof; it only carries the already-built
    /// proof through the wire model.
    pub proof: Option<&'a Value>,
}

impl fmt::Debug for PushDeviceConfig<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PushDeviceConfig")
            .field("principal_did", &self.principal_did)
            .field("device_id", &self.device_id)
            .field("push_key", &self.push_key.map(redact_push_key))
            .field("platform", &self.platform)
            .field("app_id", &self.app_id)
            .field("domestic_app_id", &self.domestic_app_id)
            .field("registration_id", &self.registration_id)
            .field("display_name", &self.display_name)
            .field("idempotency_key", &self.idempotency_key)
            .field("request_id", &self.request_id)
            .field("proof", &self.proof.map(|_| "<present>"))
            .finish()
    }
}

/// Request body for `POST /api/v1/push/register-device`.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct RegisterDeviceRequest {
    pub operation_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub principal_did: Option<String>,
    pub device_id: String,
    pub push_gateway: String,
    pub push_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub platform: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<Value>,
}

impl fmt::Debug for RegisterDeviceRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RegisterDeviceRequest")
            .field("operation_id", &self.operation_id)
            .field("principal_did", &self.principal_did)
            .field("device_id", &self.device_id)
            .field("push_gateway", &redact_url(&self.push_gateway))
            .field("push_key", &redact_push_key(&self.push_key))
            .field("platform", &self.platform)
            .field("app_id", &self.app_id)
            .field("display_name", &self.display_name)
            .field("idempotency_key", &self.idempotency_key)
            .field("request_id", &self.request_id)
            .field("proof", &self.proof.as_ref().map(|_| "<present>"))
            .finish()
    }
}

/// Response body for `POST /api/v1/push/register-device`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterDeviceResponse {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registration_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accepted_gateway: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub push_key_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub push_key_preview: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_hint: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
}

/// Request body for `POST /api/v1/push/unregister-device`.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct UnregisterDeviceRequest {
    pub operation_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub principal_did: Option<String>,
    pub device_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registration_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub push_gateway: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub push_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub push_key_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub push_key_preview: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<Value>,
}

impl fmt::Debug for UnregisterDeviceRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UnregisterDeviceRequest")
            .field("operation_id", &self.operation_id)
            .field("principal_did", &self.principal_did)
            .field("device_id", &self.device_id)
            .field("registration_id", &self.registration_id)
            .field(
                "push_gateway",
                &self.push_gateway.as_deref().map(redact_url),
            )
            .field("push_key", &self.push_key.as_deref().map(redact_push_key))
            .field("push_key_hash", &self.push_key_hash)
            .field("push_key_preview", &self.push_key_preview)
            .field("app_id", &self.app_id)
            .field("idempotency_key", &self.idempotency_key)
            .field("request_id", &self.request_id)
            .field("proof", &self.proof.as_ref().map(|_| "<present>"))
            .finish()
    }
}

/// Response body for `POST /api/v1/push/unregister-device`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnregisterDeviceResponse {
    pub ok: bool,
    #[serde(default)]
    pub already_removed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub removed_registration_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
}

/// Response body for `GET /api/v1/push/bridge/describe`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushBridgeDescribeResponse {
    pub contract: String,
    pub version: String,
    pub api_base_path: String,
    pub gateway: PushBridgeDescribeGatewayDescriptor,
    pub notify: PushBridgeDescribeNotifyDescriptor,
    pub privacy: PushBridgeDescribePrivacyDescriptor,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub todos: Vec<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushBridgeDescribeGatewayDescriptor {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_did: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub supported_profiles: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub supported_providers: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub auth_modes: Vec<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushBridgeDescribeNotifyDescriptor {
    pub notify_path: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub legacy_notify_aliases: Vec<String>,
    pub operation_id: String,
    pub request_id_header: String,
    pub idempotency_key_header: String,
    pub origin_service_did_header: String,
    pub destination_service_did_header: String,
    pub max_request_size_bytes: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dedup_backend: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dedup_ttl_seconds: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate_limit_window_seconds: Option<u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rate_limit_scopes: Vec<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushBridgeDescribePrivacyDescriptor {
    pub default_mode: String,
    pub plaintext_visibility_class: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub active_reference_fields: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rejected_legacy_fields: Vec<String>,
}

/// Contrix standard error object.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct ContrixError {
    pub code: String,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_after_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub details: Option<Value>,
}

impl fmt::Debug for ContrixError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ContrixError")
            .field("code", &self.code)
            .field("message", &"<redacted>")
            .field("retry_after_ms", &self.retry_after_ms)
            .field("details_present", &self.details.is_some())
            .finish()
    }
}

/// Contrix standard error envelope.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct ContrixErrorEnvelope {
    pub ok: bool,
    pub error: ContrixError,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
}

impl fmt::Debug for ContrixErrorEnvelope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ContrixErrorEnvelope")
            .field("ok", &self.ok)
            .field("error", &self.error)
            .field("request_id", &self.request_id)
            .finish()
    }
}

/// Stable high-level category for push registration failures.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PushErrorKind {
    MissingField,
    InvalidPlatform,
    InvalidPushGatewayUrl,
    InvalidWebPushEndpoint,
    WebPushEndpointNotAllowed,
    ForbiddenPushGatewayQueryParam,
    InvalidHeader,
    Unauthenticated,
    CapabilityDenied,
    RateLimited,
    TemporarilyUnavailable,
    DuplicateConflict,
    NotFound,
    SchemaViolation,
    NetworkTimeout,
    Network,
    InvalidResponse,
    HttpStatus,
}

/// Canonical data that callers can bind into DID proofs or HTTP Message Signatures.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushRequestSigningContext {
    pub operation_id: String,
    pub method: String,
    pub path: String,
    pub target_uri: String,
    pub content_digest: String,
    pub device_id: String,
    pub created_at: String,
    pub audience: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor_did: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub origin: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub origin_service_did: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destination_service_did: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_grant: Option<String>,
}

impl fmt::Debug for PushRequestSigningContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PushRequestSigningContext")
            .field("operation_id", &self.operation_id)
            .field("method", &self.method)
            .field("path", &self.path)
            .field("target_uri", &redact_url(&self.target_uri))
            .field("content_digest", &self.content_digest)
            .field("device_id", &self.device_id)
            .field("created_at", &self.created_at)
            .field("audience", &self.audience)
            .field("actor_did", &self.actor_did)
            .field("expires_at", &self.expires_at)
            .field("origin", &self.origin)
            .field("origin_service_did", &self.origin_service_did)
            .field("destination_service_did", &self.destination_service_did)
            .field("nonce", &self.nonce)
            .field("idempotency_key", &self.idempotency_key)
            .field(
                "session_grant",
                &self.session_grant.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

impl PushRequestSigningContext {
    /// Return the canonical JSON value callers can sign as a DID proof body.
    pub fn canonical_proof_body(&self) -> Result<Value, PushRegistrationError> {
        Ok(serde_json::to_value(self)?)
    }

    /// Return deterministic metadata headers that should be present on the
    /// HTTP request and covered by HTTP Message Signatures.
    pub fn signed_metadata_headers(&self) -> Vec<(&'static str, String)> {
        let mut headers = vec![
            (CONTENT_DIGEST_HEADER, self.content_digest.clone()),
            (CONTRIX_OPERATION_ID_HEADER, self.operation_id.clone()),
            (CONTRIX_DEVICE_ID_HEADER, self.device_id.clone()),
            (CONTRIX_CREATED_AT_HEADER, self.created_at.clone()),
            (CONTRIX_AUDIENCE_HEADER, self.audience.clone()),
        ];

        if let Some(actor_did) = &self.actor_did {
            headers.push((CONTRIX_ACTOR_DID_HEADER, actor_did.clone()));
        }
        if let Some(expires_at) = &self.expires_at {
            headers.push((CONTRIX_EXPIRES_AT_HEADER, expires_at.clone()));
        }
        if let Some(origin) = &self.origin {
            headers.push((CONTRIX_ORIGIN_HEADER, origin.clone()));
        }
        if let Some(origin_service_did) = &self.origin_service_did {
            headers.push((
                CONTRIX_ORIGIN_SERVICE_DID_HEADER,
                origin_service_did.clone(),
            ));
        }
        if let Some(destination_service_did) = &self.destination_service_did {
            headers.push((
                CONTRIX_DESTINATION_SERVICE_DID_HEADER,
                destination_service_did.clone(),
            ));
        }
        if let Some(nonce) = &self.nonce {
            headers.push((CONTRIX_NONCE_HEADER, nonce.clone()));
        }
        if let Some(idempotency_key) = &self.idempotency_key {
            headers.push((CONTRIX_IDEMPOTENCY_KEY_HEADER, idempotency_key.clone()));
        }
        if let Some(session_grant) = &self.session_grant {
            headers.push((CONTRIX_SESSION_GRANT_HEADER, session_grant.clone()));
        }

        headers
    }

    /// Build the `Signature-Input` header value for this request context.
    pub fn http_message_signature_input(
        &self,
        label: &str,
    ) -> Result<String, PushRegistrationError> {
        validate_signature_label(label)?;

        let mut components = vec![
            "@method",
            "@target-uri",
            "content-digest",
            "x-contrix-operation-id",
            "x-contrix-device-id",
            "x-contrix-created-at",
            "x-contrix-audience",
        ];

        if self.actor_did.is_some() {
            components.push("x-contrix-actor-did");
        }
        if self.expires_at.is_some() {
            components.push("x-contrix-expires-at");
        }
        if self.origin.is_some() {
            components.push("x-contrix-origin");
        }
        if self.origin_service_did.is_some() {
            components.push("x-contrix-origin-service-did");
        }
        if self.destination_service_did.is_some() {
            components.push("x-contrix-destination-service-did");
        }
        if self.nonce.is_some() {
            components.push("x-contrix-nonce");
        }
        if self.idempotency_key.is_some() {
            components.push("x-contrix-idempotency-key");
        }
        if self.session_grant.is_some() {
            components.push("x-contrix-session-grant");
        }

        let covered = components
            .into_iter()
            .map(|component| format!("\"{component}\""))
            .collect::<Vec<_>>()
            .join(" ");

        Ok(format!("{label}=({covered})"))
    }

    /// Build the `Signature` header value from a precomputed base64 signature.
    pub fn http_message_signature_header(
        label: &str,
        signature: &str,
    ) -> Result<String, PushRegistrationError> {
        validate_signature_label(label)?;
        validate_signature_value(signature)?;
        Ok(format!("{label}=:{signature}:"))
    }

    /// Return the metadata, `Signature-Input`, and `Signature` headers needed
    /// to attach a precomputed HTTP Message Signature to the request.
    pub fn http_message_signature_headers(
        &self,
        label: &str,
        signature: &str,
    ) -> Result<Vec<(&'static str, String)>, PushRegistrationError> {
        let mut headers = self.signed_metadata_headers();
        headers.push((
            SIGNATURE_INPUT_HEADER,
            self.http_message_signature_input(label)?,
        ));
        headers.push((
            SIGNATURE_HEADER,
            Self::http_message_signature_header(label, signature)?,
        ));
        Ok(headers)
    }
}

/// Inputs used to build a request signing context.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushRequestSigningOptions {
    pub created_at: String,
    pub audience: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor_did: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub origin: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub origin_service_did: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destination_service_did: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_grant: Option<String>,
}

impl PushRequestSigningOptions {
    pub fn new(created_at: impl Into<String>, audience: impl Into<String>) -> Self {
        Self {
            created_at: created_at.into(),
            audience: audience.into(),
            actor_did: None,
            expires_at: None,
            origin: None,
            origin_service_did: None,
            destination_service_did: None,
            nonce: None,
            idempotency_key: None,
            session_grant: None,
        }
    }

    pub fn with_actor_did(mut self, actor_did: impl Into<String>) -> Self {
        self.actor_did = Some(actor_did.into());
        self
    }

    pub fn with_expires_at(mut self, expires_at: impl Into<String>) -> Self {
        self.expires_at = Some(expires_at.into());
        self
    }

    pub fn with_origin(mut self, origin: impl Into<String>) -> Self {
        self.origin = Some(origin.into());
        self
    }

    pub fn with_origin_service_did(mut self, origin_service_did: impl Into<String>) -> Self {
        self.origin_service_did = Some(origin_service_did.into());
        self
    }

    pub fn with_destination_service_did(
        mut self,
        destination_service_did: impl Into<String>,
    ) -> Self {
        self.destination_service_did = Some(destination_service_did.into());
        self
    }

    pub fn with_nonce(mut self, nonce: impl Into<String>) -> Self {
        self.nonce = Some(nonce.into());
        self
    }

    pub fn with_idempotency_key(mut self, idempotency_key: impl Into<String>) -> Self {
        self.idempotency_key = Some(idempotency_key.into());
        self
    }

    /// Attach an externally supplied coauth/soland session grant.
    ///
    /// `chime` only carries this value into the signing context and metadata
    /// headers; it never owns private keys or attempts to mint grants.
    pub fn with_session_grant(mut self, session_grant: impl Into<String>) -> Self {
        self.session_grant = Some(session_grant.into());
        self
    }
}

#[derive(Error)]
pub enum PushRegistrationError {
    #[error("missing required Contrix push field: {0}")]
    MissingField(&'static str),
    #[error("unsupported push platform: {0}")]
    InvalidPlatform(String),
    #[error("invalid push gateway URL: {reason}")]
    InvalidPushGatewayUrl { url: String, reason: String },
    #[error("invalid WebPush endpoint: {reason}")]
    InvalidWebPushEndpoint { endpoint: String, reason: String },
    #[error("WebPush endpoint origin is not allowed: {origin}")]
    WebPushEndpointNotAllowed { endpoint: String, origin: String },
    #[error("push gateway URL contains forbidden query parameter: {param}")]
    ForbiddenPushGatewayQueryParam { param: String },
    #[error("invalid HTTP header `{name}`")]
    InvalidHeader { name: String },
    #[error("Contrix service returned HTTP {status}")]
    HttpStatus {
        status: u16,
        kind: PushErrorKind,
        error: Option<Box<ContrixErrorEnvelope>>,
        body: String,
        retry_after: Option<String>,
        request_id: Option<String>,
    },
    #[cfg(feature = "http")]
    #[error(transparent)]
    Http(#[from] reqwest::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

impl fmt::Debug for PushRegistrationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingField(field) => f.debug_tuple("MissingField").field(field).finish(),
            Self::InvalidPlatform(platform) => {
                f.debug_tuple("InvalidPlatform").field(platform).finish()
            }
            Self::InvalidPushGatewayUrl { url, reason } => f
                .debug_struct("InvalidPushGatewayUrl")
                .field("url", &redact_url(url))
                .field("reason", reason)
                .finish(),
            Self::InvalidWebPushEndpoint { endpoint, reason } => f
                .debug_struct("InvalidWebPushEndpoint")
                .field("endpoint", &redact_webpush_endpoint(endpoint))
                .field("reason", reason)
                .finish(),
            Self::WebPushEndpointNotAllowed { endpoint, origin } => f
                .debug_struct("WebPushEndpointNotAllowed")
                .field("endpoint", &redact_webpush_endpoint(endpoint))
                .field("origin", origin)
                .finish(),
            Self::ForbiddenPushGatewayQueryParam { param } => f
                .debug_struct("ForbiddenPushGatewayQueryParam")
                .field("param", param)
                .finish(),
            Self::InvalidHeader { name } => {
                f.debug_struct("InvalidHeader").field("name", name).finish()
            }
            Self::HttpStatus {
                status,
                kind,
                error,
                body,
                retry_after,
                request_id,
            } => f
                .debug_struct("HttpStatus")
                .field("status", status)
                .field("kind", kind)
                .field("error", error)
                .field("body_len", &body.len())
                .field("retry_after", retry_after)
                .field("request_id", request_id)
                .finish(),
            #[cfg(feature = "http")]
            Self::Http(error) => f.debug_tuple("Http").field(error).finish(),
            Self::Json(error) => f.debug_tuple("Json").field(error).finish(),
        }
    }
}

impl PushRegistrationError {
    pub fn kind(&self) -> PushErrorKind {
        match self {
            Self::MissingField(_) => PushErrorKind::MissingField,
            Self::InvalidPlatform(_) => PushErrorKind::InvalidPlatform,
            Self::InvalidPushGatewayUrl { .. } => PushErrorKind::InvalidPushGatewayUrl,
            Self::InvalidWebPushEndpoint { .. } => PushErrorKind::InvalidWebPushEndpoint,
            Self::WebPushEndpointNotAllowed { .. } => PushErrorKind::WebPushEndpointNotAllowed,
            Self::ForbiddenPushGatewayQueryParam { .. } => {
                PushErrorKind::ForbiddenPushGatewayQueryParam
            }
            Self::InvalidHeader { .. } => PushErrorKind::InvalidHeader,
            Self::HttpStatus { kind, .. } => *kind,
            #[cfg(feature = "http")]
            Self::Http(error) if error.is_timeout() => PushErrorKind::NetworkTimeout,
            #[cfg(feature = "http")]
            Self::Http(_) => PushErrorKind::Network,
            Self::Json(_) => PushErrorKind::InvalidResponse,
        }
    }

    pub fn status(&self) -> Option<u16> {
        match self {
            Self::HttpStatus { status, .. } => Some(*status),
            _ => None,
        }
    }

    pub fn contrix_error(&self) -> Option<&ContrixErrorEnvelope> {
        match self {
            Self::HttpStatus { error, .. } => error.as_deref(),
            _ => None,
        }
    }

    pub fn retry_after(&self) -> Option<&str> {
        match self {
            Self::HttpStatus { retry_after, .. } => retry_after.as_deref(),
            _ => None,
        }
    }

    pub fn retry_after_duration(&self) -> Option<Duration> {
        let value = self.retry_after()?;
        parse_retry_after(value)
    }

    pub fn request_id(&self) -> Option<&str> {
        match self {
            Self::HttpStatus {
                request_id, error, ..
            } => request_id.as_deref().or_else(|| {
                error
                    .as_deref()
                    .and_then(|envelope| envelope.request_id.as_deref())
            }),
            _ => None,
        }
    }

    #[cfg(feature = "http")]
    fn is_retryable(&self) -> bool {
        matches!(
            self.kind(),
            PushErrorKind::RateLimited
                | PushErrorKind::TemporarilyUnavailable
                | PushErrorKind::NetworkTimeout
        )
    }
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

/// Validate a Contrix push gateway endpoint.
///
/// Production gateway URLs must be HTTPS. Plain HTTP is accepted only for
/// loopback hosts when `allow_insecure_loopback` is true.
pub fn validate_push_gateway_url(
    value: &str,
    allow_insecure_loopback: bool,
) -> Result<(), PushRegistrationError> {
    require_non_empty("push_gateway", value)?;

    let url = Url::parse(value).map_err(|error| PushRegistrationError::InvalidPushGatewayUrl {
        url: value.to_owned(),
        reason: error.to_string(),
    })?;

    if !url.username().is_empty() || url.password().is_some() {
        return Err(PushRegistrationError::InvalidPushGatewayUrl {
            url: value.to_owned(),
            reason: "embedded credentials are not allowed".to_owned(),
        });
    }

    for (param, _) in url.query_pairs() {
        if is_forbidden_secret_query_param(&param) {
            return Err(PushRegistrationError::ForbiddenPushGatewayQueryParam {
                param: param.into_owned(),
            });
        }
    }

    match url.scheme() {
        "https" => Ok(()),
        "http" if allow_insecure_loopback && is_loopback_url(&url) => Ok(()),
        "http" => Err(PushRegistrationError::InvalidPushGatewayUrl {
            url: value.to_owned(),
            reason: "plain HTTP is only allowed for loopback development URLs".to_owned(),
        }),
        scheme => Err(PushRegistrationError::InvalidPushGatewayUrl {
            url: value.to_owned(),
            reason: format!("unsupported URL scheme `{scheme}`"),
        }),
    }
}

/// Validate a WebPush endpoint against an optional allowlist.
///
/// Empty allowlists accept both opaque WebPush tokens and HTTPS endpoints. When
/// an allowlist is provided, `push_key` must be a WebPush endpoint URL, either
/// directly or prefixed as `webpush:<endpoint>`, and its origin/host must match
/// an allowlist entry.
pub fn validate_webpush_endpoint_allowlist(
    push_key: &str,
    allowlist: &[String],
) -> Result<(), PushRegistrationError> {
    let Some(endpoint) = webpush_endpoint_from_push_key(push_key) else {
        return if allowlist.is_empty() {
            Ok(())
        } else {
            Err(PushRegistrationError::InvalidWebPushEndpoint {
                endpoint: push_key.to_owned(),
                reason: "allowlisted WebPush registrations must use an endpoint URL".to_owned(),
            })
        };
    };

    let url =
        Url::parse(endpoint).map_err(|error| PushRegistrationError::InvalidWebPushEndpoint {
            endpoint: push_key.to_owned(),
            reason: error.to_string(),
        })?;

    if !url.username().is_empty() || url.password().is_some() {
        return Err(PushRegistrationError::InvalidWebPushEndpoint {
            endpoint: push_key.to_owned(),
            reason: "embedded credentials are not allowed".to_owned(),
        });
    }

    for (param, _) in url.query_pairs() {
        if is_forbidden_secret_query_param(&param) {
            return Err(PushRegistrationError::ForbiddenPushGatewayQueryParam {
                param: param.into_owned(),
            });
        }
    }

    if url.scheme() != "https" {
        return Err(PushRegistrationError::InvalidWebPushEndpoint {
            endpoint: push_key.to_owned(),
            reason: "WebPush endpoints must use HTTPS".to_owned(),
        });
    }

    if allowlist.is_empty() {
        return Ok(());
    }

    let origin = url_origin(&url).ok_or_else(|| PushRegistrationError::InvalidWebPushEndpoint {
        endpoint: push_key.to_owned(),
        reason: "endpoint URL has no host".to_owned(),
    })?;

    if allowlist
        .iter()
        .any(|entry| webpush_allowlist_entry_matches(&url, entry))
    {
        Ok(())
    } else {
        Err(PushRegistrationError::WebPushEndpointNotAllowed {
            endpoint: push_key.to_owned(),
            origin,
        })
    }
}

/// Return a non-secret preview of a platform push token.
pub fn redact_push_key(value: &str) -> String {
    let value = value.trim();
    if value.is_empty() {
        return "<empty>".to_owned();
    }

    let len = value.chars().count();
    if let Some((prefix, token)) = value.split_once(':')
        && is_safe_token_prefix(prefix)
        && !token.is_empty()
    {
        return format!("{prefix}:<redacted,len={}>", token.chars().count());
    }

    format!("<redacted,len={len}>")
}

/// Build the Contrix register-device request body from app configuration and
/// stored push preferences.
///
/// ```rust
/// use chime::{PushDeviceConfig, PushPreferences, build_register_device_request};
///
/// let config = PushDeviceConfig {
///     principal_did: Some("did:web:alice.example"),
///     device_id: "did:web:alice.example#device-phone",
///     push_key: Some("fcm:token"),
///     platform: Some("android"),
///     app_id: Some("app.example.android"),
///     domestic_app_id: None,
///     registration_id: None,
///     display_name: Some("Alice Phone"),
///     idempotency_key: Some("register-phone-v1"),
///     request_id: None,
///     proof: None,
/// };
/// let prefs = PushPreferences {
///     enabled: true,
///     push_gateway: "https://push.example.com/api/v1/push/notify".to_owned(),
///     ..Default::default()
/// };
///
/// let request = build_register_device_request(&config, &prefs).unwrap();
/// assert_eq!(request.device_id, "did:web:alice.example#device-phone");
/// ```
pub fn build_register_device_request(
    config: &PushDeviceConfig<'_>,
    prefs: &PushPreferences,
) -> Result<RegisterDeviceRequest, PushRegistrationError> {
    require_non_empty("device_id", config.device_id)?;
    let push_key = require_optional_non_empty("push_key", config.push_key)?;
    validate_push_gateway_url(
        &prefs.push_gateway,
        prefs.allow_insecure_loopback_push_gateway,
    )?;

    let platform = parse_platform(config.platform)?;
    let app_id = prefs.app_id(platform, config.app_id, config.domestic_app_id);
    if platform == Some(PushPlatform::Web) {
        validate_webpush_endpoint_allowlist(push_key, &prefs.webpush_endpoint_allowlist)?;
    }

    Ok(RegisterDeviceRequest {
        operation_id: crate::OPERATION_PUSH_REGISTER_DEVICE.to_owned(),
        principal_did: config.principal_did.and_then(non_empty).map(str::to_owned),
        device_id: config.device_id.to_owned(),
        push_gateway: prefs.push_gateway.clone(),
        push_key: push_key.to_owned(),
        platform: platform.map(|value| value.as_str().to_owned()),
        app_id: app_id.map(str::to_owned),
        display_name: config.display_name.map(str::to_owned),
        idempotency_key: config.idempotency_key.map(str::to_owned),
        request_id: config.request_id.map(str::to_owned),
        proof: config.proof.cloned(),
    })
}

/// Build the Contrix unregister-device request body from app configuration and
/// stored push preferences.
///
/// ```rust
/// use chime::{PushDeviceConfig, PushPreferences, build_unregister_device_request};
///
/// let config = PushDeviceConfig {
///     principal_did: Some("did:web:alice.example"),
///     device_id: "did:web:alice.example#device-phone",
///     push_key: None,
///     platform: Some("android"),
///     app_id: Some("app.example.android"),
///     domestic_app_id: None,
///     registration_id: Some("cx:pushreg:01JS0KE000000000000000000"),
///     display_name: None,
///     idempotency_key: Some("unregister-phone-v1"),
///     request_id: None,
///     proof: None,
/// };
/// let request = build_unregister_device_request(&config, &PushPreferences::default()).unwrap();
/// assert_eq!(request.registration_id.as_deref(), Some("cx:pushreg:01JS0KE000000000000000000"));
/// ```
pub fn build_unregister_device_request(
    config: &PushDeviceConfig<'_>,
    prefs: &PushPreferences,
) -> Result<UnregisterDeviceRequest, PushRegistrationError> {
    require_non_empty("device_id", config.device_id)?;
    if non_empty(&prefs.push_gateway).is_some() {
        validate_push_gateway_url(
            &prefs.push_gateway,
            prefs.allow_insecure_loopback_push_gateway,
        )?;
    }

    let platform = parse_platform(config.platform)?;
    let app_id = prefs.app_id(platform, config.app_id, config.domestic_app_id);
    let push_key = config.push_key.and_then(non_empty);

    Ok(UnregisterDeviceRequest {
        operation_id: crate::OPERATION_PUSH_UNREGISTER_DEVICE.to_owned(),
        principal_did: config.principal_did.and_then(non_empty).map(str::to_owned),
        device_id: config.device_id.to_owned(),
        registration_id: non_empty(config.registration_id.unwrap_or_default()).map(str::to_owned),
        push_gateway: non_empty(&prefs.push_gateway).map(str::to_owned),
        push_key: push_key.map(str::to_owned),
        push_key_hash: push_key.map(hash_push_key_for_wire),
        push_key_preview: push_key.map(redact_push_key),
        app_id: app_id.map(str::to_owned),
        idempotency_key: config.idempotency_key.map(str::to_owned),
        request_id: config.request_id.map(str::to_owned),
        proof: config.proof.cloned(),
    })
}

/// Build the signing context for `cx.push.register_device`.
///
/// ```rust
/// use chime::{
///     PushDeviceConfig, PushPreferences, build_register_device_request,
///     build_register_signing_context,
/// };
///
/// let config = PushDeviceConfig {
///     principal_did: Some("did:web:alice.example"),
///     device_id: "did:web:alice.example#device-phone",
///     push_key: Some("fcm:token"),
///     platform: Some("android"),
///     app_id: Some("app.example.android"),
///     domestic_app_id: None,
///     registration_id: None,
///     display_name: None,
///     idempotency_key: None,
///     request_id: None,
///     proof: None,
/// };
/// let prefs = PushPreferences {
///     enabled: true,
///     push_gateway: "https://push.example.com/api/v1/push/notify".to_owned(),
///     ..Default::default()
/// };
/// let request = build_register_device_request(&config, &prefs).unwrap();
/// let context = build_register_signing_context(
///     "https://principal.example",
///     &request,
///     "2026-04-29T00:00:00Z",
///     "https://principal.example",
/// )
/// .unwrap();
/// assert_eq!(context.path, chime::REGISTER_DEVICE_PATH);
/// assert!(context.content_digest.starts_with("sha-256=:"));
/// ```
pub fn build_register_signing_context(
    service_base_url: &str,
    request: &RegisterDeviceRequest,
    created_at: impl Into<String>,
    audience: impl Into<String>,
) -> Result<PushRequestSigningContext, PushRegistrationError> {
    build_register_signing_context_with_options(
        service_base_url,
        request,
        PushRequestSigningOptions::new(created_at, audience),
    )
}

/// Build the signing context for `cx.push.register_device` with actor and
/// expiry metadata.
pub fn build_register_signing_context_with_options(
    service_base_url: &str,
    request: &RegisterDeviceRequest,
    options: PushRequestSigningOptions,
) -> Result<PushRequestSigningContext, PushRegistrationError> {
    build_signing_context(
        service_base_url,
        crate::OPERATION_PUSH_REGISTER_DEVICE,
        REGISTER_DEVICE_PATH,
        &request.device_id,
        request,
        options,
    )
}

/// Build the signing context for `cx.push.unregister_device`.
pub fn build_unregister_signing_context(
    service_base_url: &str,
    request: &UnregisterDeviceRequest,
    created_at: impl Into<String>,
    audience: impl Into<String>,
) -> Result<PushRequestSigningContext, PushRegistrationError> {
    build_unregister_signing_context_with_options(
        service_base_url,
        request,
        PushRequestSigningOptions::new(created_at, audience),
    )
}

/// Build the signing context for `cx.push.unregister_device` with actor and
/// expiry metadata.
pub fn build_unregister_signing_context_with_options(
    service_base_url: &str,
    request: &UnregisterDeviceRequest,
    options: PushRequestSigningOptions,
) -> Result<PushRequestSigningContext, PushRegistrationError> {
    build_signing_context(
        service_base_url,
        crate::OPERATION_PUSH_UNREGISTER_DEVICE,
        UNREGISTER_DEVICE_PATH,
        &request.device_id,
        request,
        options,
    )
}

/// Return an RFC 9530-style `Content-Digest` value for the serialized JSON body.
///
/// The body is serialized with `serde_json`. The current helper is intended for
/// SDK request signing and HTTP Message Signature transcript construction; it
/// does not claim to replace the protocol's canonical JSON encoder.
pub fn content_digest_sha256<T>(body: &T) -> Result<String, PushRegistrationError>
where
    T: Serialize + ?Sized,
{
    let json = serde_json::to_vec(body)?;
    let digest = Sha256::digest(&json);
    Ok(format!("sha-256=:{}:", BASE64_STANDARD.encode(digest)))
}

/// HTTP response body plus Contrix response metadata.
#[cfg(feature = "http")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContrixResponse<T> {
    pub body: T,
    pub request_id: Option<String>,
    pub retry_after: Option<String>,
}

#[cfg(feature = "http")]
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
#[cfg(feature = "http")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PushRetryPolicy {
    pub max_retries: u32,
    pub initial_backoff: Duration,
    pub max_backoff: Duration,
    pub jitter: Duration,
}

#[cfg(feature = "http")]
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

#[cfg(feature = "http")]
impl Default for PushRetryPolicy {
    fn default() -> Self {
        Self::disabled()
    }
}

#[cfg(feature = "http")]
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
}

#[cfg(feature = "http")]
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
            .finish()
    }
}

#[cfg(feature = "http")]
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
        let idempotency_key = idempotency_key.or(self.default_idempotency_key.as_deref());
        let request_id = request_id.or(self.default_request_id.as_deref());
        let retry_is_safe = idempotency_key.is_some() || path == UNREGISTER_DEVICE_PATH;

        loop {
            let result = self
                .post_json_once(path, body, idempotency_key, request_id)
                .await;

            match result {
                Ok(response) => return Ok(response),
                Err(error)
                    if retry_is_safe
                        && retry_count < self.retry_policy.max_retries
                        && error.is_retryable() =>
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

    async fn get_json_once<R>(&self, path: &str) -> Result<ContrixResponse<R>, PushRegistrationError>
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

fn parse_platform(value: Option<&str>) -> Result<Option<PushPlatform>, PushRegistrationError> {
    value.map(PushPlatform::try_from).transpose()
}

fn build_signing_context<T>(
    service_base_url: &str,
    operation_id: &str,
    path: &str,
    device_id: &str,
    body: &T,
    options: PushRequestSigningOptions,
) -> Result<PushRequestSigningContext, PushRegistrationError>
where
    T: Serialize + ?Sized,
{
    let created_at = require_owned_non_empty("created_at", options.created_at)?;
    let audience = require_owned_non_empty("audience", options.audience)?;
    let actor_did = require_optional_owned_non_empty("actor_did", options.actor_did)?;
    let expires_at = require_optional_owned_non_empty("expires_at", options.expires_at)?;
    let origin = require_optional_owned_non_empty("origin", options.origin)?;
    let origin_service_did =
        require_optional_owned_non_empty("origin_service_did", options.origin_service_did)?;
    let destination_service_did = require_optional_owned_non_empty(
        "destination_service_did",
        options.destination_service_did,
    )?;
    let nonce = require_optional_owned_non_empty("nonce", options.nonce)?;
    let idempotency_key =
        require_optional_owned_non_empty("idempotency_key", options.idempotency_key)?;
    let session_grant = require_optional_owned_non_empty("session_grant", options.session_grant)?;

    Ok(PushRequestSigningContext {
        operation_id: operation_id.to_owned(),
        method: "POST".to_owned(),
        path: path.to_owned(),
        target_uri: try_contrix_api_url(service_base_url, path)?,
        content_digest: content_digest_sha256(body)?,
        device_id: device_id.to_owned(),
        created_at,
        audience,
        actor_did,
        expires_at,
        origin,
        origin_service_did,
        destination_service_did,
        nonce,
        idempotency_key,
        session_grant,
    })
}

fn require_non_empty(name: &'static str, value: &str) -> Result<(), PushRegistrationError> {
    if non_empty(value).is_some() {
        Ok(())
    } else {
        Err(PushRegistrationError::MissingField(name))
    }
}

fn require_optional_non_empty<'a>(
    name: &'static str,
    value: Option<&'a str>,
) -> Result<&'a str, PushRegistrationError> {
    value
        .and_then(non_empty)
        .ok_or(PushRegistrationError::MissingField(name))
}

fn require_owned_non_empty(
    name: &'static str,
    value: String,
) -> Result<String, PushRegistrationError> {
    non_empty(&value)
        .map(str::to_owned)
        .ok_or(PushRegistrationError::MissingField(name))
}

fn require_optional_owned_non_empty(
    name: &'static str,
    value: Option<String>,
) -> Result<Option<String>, PushRegistrationError> {
    value
        .map(|value| require_owned_non_empty(name, value))
        .transpose()
}

fn non_empty(value: &str) -> Option<&str> {
    let value = value.trim();
    (!value.is_empty()).then_some(value)
}

fn hash_push_key_for_wire(push_key: &str) -> String {
    let digest = Sha256::digest(push_key.as_bytes());
    let mut output = String::with_capacity("sha256:".len() + digest.len() * 2);
    output.push_str("sha256:");
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

fn validate_signature_label(label: &str) -> Result<(), PushRegistrationError> {
    let valid = !label.is_empty()
        && label
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.'));

    if valid {
        Ok(())
    } else {
        Err(PushRegistrationError::InvalidHeader {
            name: SIGNATURE_INPUT_HEADER.to_owned(),
        })
    }
}

fn validate_signature_value(signature: &str) -> Result<(), PushRegistrationError> {
    let valid = non_empty(signature).is_some()
        && signature
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && byte != b':');

    if valid {
        Ok(())
    } else {
        Err(PushRegistrationError::InvalidHeader {
            name: SIGNATURE_HEADER.to_owned(),
        })
    }
}

fn is_forbidden_secret_query_param(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "access_token"
            | "session_token"
            | "api_key"
            | "auth"
            | "authorization"
            | "signature"
            | "token"
            | "bearer_token"
    )
}

fn is_loopback_url(url: &Url) -> bool {
    match url.host_str() {
        Some("localhost") => true,
        Some(host) => host
            .parse::<IpAddr>()
            .map(|addr| addr.is_loopback())
            .unwrap_or(false),
        None => false,
    }
}

fn is_safe_token_prefix(prefix: &str) -> bool {
    !prefix.is_empty()
        && prefix.len() <= 24
        && prefix
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.'))
}

fn try_contrix_api_url(
    service_base_url: &str,
    path: &str,
) -> Result<String, PushRegistrationError> {
    validate_service_base_url(service_base_url)?;
    Ok(contrix_api_url(service_base_url, path))
}

fn validate_service_base_url(value: &str) -> Result<(), PushRegistrationError> {
    require_non_empty("service_base_url", value)?;

    let url = Url::parse(value).map_err(|error| PushRegistrationError::InvalidPushGatewayUrl {
        url: value.to_owned(),
        reason: error.to_string(),
    })?;

    if !url.username().is_empty() || url.password().is_some() {
        return Err(PushRegistrationError::InvalidPushGatewayUrl {
            url: value.to_owned(),
            reason: "embedded credentials are not allowed".to_owned(),
        });
    }

    for (param, _) in url.query_pairs() {
        if is_forbidden_secret_query_param(&param) {
            return Err(PushRegistrationError::ForbiddenPushGatewayQueryParam {
                param: param.into_owned(),
            });
        }
    }

    if url.query().is_some() {
        return Err(PushRegistrationError::InvalidPushGatewayUrl {
            url: value.to_owned(),
            reason: "service base URL must not contain a query string".to_owned(),
        });
    }

    if url.fragment().is_some() {
        return Err(PushRegistrationError::InvalidPushGatewayUrl {
            url: value.to_owned(),
            reason: "service base URL must not contain a fragment".to_owned(),
        });
    }

    match url.scheme() {
        "https" => Ok(()),
        "http" if is_loopback_url(&url) => Ok(()),
        "http" => Err(PushRegistrationError::InvalidPushGatewayUrl {
            url: value.to_owned(),
            reason: "plain HTTP service URLs are only allowed for loopback development".to_owned(),
        }),
        scheme => Err(PushRegistrationError::InvalidPushGatewayUrl {
            url: value.to_owned(),
            reason: format!("unsupported URL scheme `{scheme}`"),
        }),
    }
}

fn webpush_endpoint_from_push_key(push_key: &str) -> Option<&str> {
    let value = push_key.trim();
    let endpoint = value.strip_prefix("webpush:").unwrap_or(value);
    (endpoint.starts_with("https://") || endpoint.starts_with("http://")).then_some(endpoint)
}

fn webpush_allowlist_entry_matches(endpoint: &Url, entry: &str) -> bool {
    let entry = entry.trim();
    if entry.is_empty() {
        return false;
    }

    if let Ok(allowed) = Url::parse(entry) {
        return endpoint.scheme() == allowed.scheme()
            && endpoint.host_str() == allowed.host_str()
            && endpoint.port_or_known_default() == allowed.port_or_known_default();
    }

    let Some(host) = endpoint.host_str() else {
        return false;
    };
    let host = host.to_ascii_lowercase();
    let pattern = entry.to_ascii_lowercase();

    if let Some(suffix) = pattern.strip_prefix("*.") {
        host == suffix || host.ends_with(&format!(".{suffix}"))
    } else if let Some(suffix) = pattern.strip_prefix('.') {
        host.ends_with(&format!(".{suffix}"))
    } else {
        host == pattern
    }
}

fn url_origin(url: &Url) -> Option<String> {
    let host = url.host_str()?;
    let mut origin = format!("{}://{}", url.scheme(), host);
    if let Some(port) = url.port() {
        origin.push(':');
        origin.push_str(&port.to_string());
    }
    Some(origin)
}

fn redact_url(value: &str) -> String {
    match Url::parse(value) {
        Ok(mut url) => {
            let _ = url.set_username("");
            let _ = url.set_password(None);
            if url.query().is_some() {
                url.set_query(Some("<redacted>"));
            }
            url.to_string()
        }
        Err(_) => format!("<invalid-url,len={}>", value.chars().count()),
    }
}

fn redact_webpush_endpoint(value: &str) -> String {
    format!("<redacted-webpush-endpoint,len={}>", value.chars().count())
}

#[cfg(any(test, feature = "http"))]
fn classify_http_error(status: u16, error: Option<&ContrixErrorEnvelope>) -> PushErrorKind {
    if let Some(code) = error.map(|envelope| envelope.error.code.as_str()) {
        return match code {
            "unauthenticated" | "auth_expired" | "soft_logged_out" => {
                PushErrorKind::Unauthenticated
            }
            "capability_denied" => PushErrorKind::CapabilityDenied,
            "rate_limited" => PushErrorKind::RateLimited,
            "temporarily_unavailable" => PushErrorKind::TemporarilyUnavailable,
            "duplicate_conflict" => PushErrorKind::DuplicateConflict,
            "not_found" => PushErrorKind::NotFound,
            "schema_violation" | "bad_json" | "bad_query" | "missing_param" | "invalid_param" => {
                PushErrorKind::SchemaViolation
            }
            _ => PushErrorKind::HttpStatus,
        };
    }

    match status {
        401 => PushErrorKind::Unauthenticated,
        403 => PushErrorKind::CapabilityDenied,
        404 => PushErrorKind::NotFound,
        409 => PushErrorKind::DuplicateConflict,
        400 | 422 => PushErrorKind::SchemaViolation,
        429 => PushErrorKind::RateLimited,
        503 => PushErrorKind::TemporarilyUnavailable,
        _ => PushErrorKind::HttpStatus,
    }
}

fn parse_retry_after(value: &str) -> Option<Duration> {
    if let Ok(seconds) = value.trim().parse::<u64>() {
        return Some(Duration::from_secs(seconds));
    }

    let retry_at = httpdate::parse_http_date(value).ok()?;
    let now = SystemTime::now();
    retry_at.duration_since(now).ok().or(Some(Duration::ZERO))
}

#[cfg(feature = "http")]
fn retry_jitter_seed() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|duration| duration.as_nanos().min(u64::MAX as u128) as u64)
        .unwrap_or(0xC0DE_CAFE)
}

#[cfg(feature = "http")]
fn header_value(headers: &reqwest::header::HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DEFAULT_BUGLE_PUSH_GATEWAY_URL, PushGatewayType};

    fn config<'a>(platform: Option<&'a str>) -> PushDeviceConfig<'a> {
        PushDeviceConfig {
            principal_did: Some("did:web:alice.example"),
            device_id: "did:web:alice.example#device-phone",
            push_key: Some("fcm:very-secret-token"),
            platform,
            app_id: Some("app.example.android"),
            domestic_app_id: Some("app.example.android.cn"),
            registration_id: Some("cx:pushreg:01JS0KE000000000000000000"),
            display_name: Some("Alice Phone"),
            idempotency_key: Some("idem-1"),
            request_id: Some("cx:req:01JS0KE000000000000000000"),
            proof: None,
        }
    }

    fn prefs(push_gateway: &str) -> PushPreferences {
        PushPreferences {
            enabled: true,
            push_gateway: push_gateway.to_owned(),
            ..Default::default()
        }
    }

    #[test]
    fn rejects_unknown_platform() {
        let err = PushPlatform::try_from("wearable").unwrap_err();
        assert_eq!(err.kind(), PushErrorKind::InvalidPlatform);
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

        assert_eq!(request.operation_id, crate::OPERATION_PUSH_REGISTER_DEVICE);
        assert_eq!(
            request.principal_did.as_deref(),
            Some("did:web:alice.example")
        );
        assert_eq!(request.device_id, "did:web:alice.example#device-phone");
        assert_eq!(request.push_gateway, DEFAULT_BUGLE_PUSH_GATEWAY_URL);
        assert_eq!(request.push_key, "fcm:very-secret-token");
        assert_eq!(request.platform.as_deref(), Some("android"));
        assert_eq!(request.app_id.as_deref(), Some("app.example.android.cn"));
        assert_eq!(request.display_name.as_deref(), Some("Alice Phone"));
        assert_eq!(request.idempotency_key.as_deref(), Some("idem-1"));
        assert_eq!(
            request.request_id.as_deref(),
            Some("cx:req:01JS0KE000000000000000000")
        );
    }

    #[test]
    fn unregister_request_supports_registration_id() {
        let request =
            build_unregister_device_request(&config(Some("ios")), &PushPreferences::default())
                .unwrap();

        assert_eq!(
            request.operation_id,
            crate::OPERATION_PUSH_UNREGISTER_DEVICE
        );
        assert_eq!(
            request.principal_did.as_deref(),
            Some("did:web:alice.example")
        );
        assert_eq!(request.device_id, "did:web:alice.example#device-phone");
        assert_eq!(
            request.registration_id.as_deref(),
            Some("cx:pushreg:01JS0KE000000000000000000")
        );
        assert_eq!(request.push_key.as_deref(), Some("fcm:very-secret-token"));
        assert!(
            request
                .push_key_hash
                .as_deref()
                .is_some_and(|value| value.starts_with("sha256:"))
        );
        assert_eq!(
            request.push_key_preview.as_deref(),
            Some("fcm:<redacted,len=17>")
        );
        assert_eq!(request.app_id.as_deref(), Some("app.example.android"));
        assert_eq!(request.idempotency_key.as_deref(), Some("idem-1"));
        assert_eq!(
            request.request_id.as_deref(),
            Some("cx:req:01JS0KE000000000000000000")
        );
    }

    #[test]
    fn response_models_cover_frozen_wire_metadata() {
        let register: RegisterDeviceResponse = serde_json::from_value(serde_json::json!({
            "ok": true,
            "registration_id": "reg-1",
            "accepted_gateway": "https://push.example.com/api/v1/push/notify",
            "push_key_hash": "sha256:abc",
            "push_key_preview": "fcm:<redacted,len=17>",
            "expires_at": "2026-05-02T00:00:00Z",
            "refresh_hint": "rotate_before_expiry",
            "warnings": ["duplicate-safe"],
            "request_id": "cx:req:123"
        }))
        .unwrap();

        assert!(register.ok);
        assert_eq!(
            register.accepted_gateway.as_deref(),
            Some("https://push.example.com/api/v1/push/notify")
        );
        assert_eq!(register.push_key_hash.as_deref(), Some("sha256:abc"));
        assert_eq!(
            register.push_key_preview.as_deref(),
            Some("fcm:<redacted,len=17>")
        );
        assert_eq!(
            register.refresh_hint.as_deref(),
            Some("rotate_before_expiry")
        );
        assert_eq!(register.warnings, vec!["duplicate-safe"]);
        assert_eq!(register.request_id.as_deref(), Some("cx:req:123"));

        let unregister: UnregisterDeviceResponse = serde_json::from_value(serde_json::json!({
            "ok": true,
            "already_removed": true,
            "removed_registration_id": "reg-1",
            "request_id": "cx:req:456"
        }))
        .unwrap();

        assert!(unregister.ok);
        assert!(unregister.already_removed);
        assert_eq!(unregister.removed_registration_id.as_deref(), Some("reg-1"));
        assert_eq!(unregister.request_id.as_deref(), Some("cx:req:456"));
    }

    #[test]
    fn requires_register_push_gateway() {
        let prefs = PushPreferences {
            push_gateway: " ".to_owned(),
            ..Default::default()
        };
        let err = build_register_device_request(&config(Some("android")), &prefs).unwrap_err();
        assert_eq!(err.kind(), PushErrorKind::MissingField);
    }

    #[test]
    fn requires_register_push_key() {
        let mut config = config(Some("android"));
        config.push_key = None;
        let err = build_register_device_request(
            &config,
            &prefs("https://push.example.com/api/v1/push/notify"),
        )
        .unwrap_err();
        assert_eq!(err.kind(), PushErrorKind::MissingField);
    }

    #[test]
    fn requires_device_id() {
        let mut config = config(Some("android"));
        config.device_id = " ";
        let err = build_register_device_request(
            &config,
            &prefs("https://push.example.com/api/v1/push/notify"),
        )
        .unwrap_err();
        assert_eq!(err.kind(), PushErrorKind::MissingField);
    }

    #[test]
    fn supports_web_and_desktop_platforms() {
        assert_eq!(PushPlatform::try_from("web").unwrap(), PushPlatform::Web);
        assert_eq!(
            PushPlatform::try_from("desktop").unwrap(),
            PushPlatform::Desktop
        );
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

    #[test]
    fn rejects_query_secret_in_push_gateway_url() {
        let err = validate_push_gateway_url(
            "https://push.example.com/api/v1/push/notify?access_token=secret",
            false,
        )
        .unwrap_err();
        assert_eq!(err.kind(), PushErrorKind::ForbiddenPushGatewayQueryParam);
    }

    #[test]
    fn validates_webpush_endpoint_allowlist() {
        let mut web_config = config(Some("web"));
        web_config.push_key =
            Some("webpush:https://updates.push.services.mozilla.com/wpush/v2/token-secret");
        let prefs = PushPreferences {
            enabled: true,
            push_gateway: "https://push.example.com/api/v1/push/notify".to_owned(),
            webpush_endpoint_allowlist: vec![
                "https://updates.push.services.mozilla.com".to_owned(),
            ],
            ..Default::default()
        };

        build_register_device_request(&web_config, &prefs).unwrap();

        let mut blocked = prefs;
        blocked.webpush_endpoint_allowlist = vec!["https://fcm.googleapis.com".to_owned()];
        let err = build_register_device_request(&web_config, &blocked).unwrap_err();
        assert_eq!(err.kind(), PushErrorKind::WebPushEndpointNotAllowed);

        let debug = format!("{err:?}");
        assert!(!debug.contains("token-secret"));
        assert!(!debug.contains("wpush/v2"));
    }

    #[test]
    fn rejects_insecure_webpush_endpoint_when_url_is_present() {
        let err = validate_webpush_endpoint_allowlist(
            "webpush:http://push.example.com/wpush/v2/token-secret",
            &[],
        )
        .unwrap_err();

        assert_eq!(err.kind(), PushErrorKind::InvalidWebPushEndpoint);
    }

    #[test]
    fn rejects_non_loopback_http_push_gateway_url() {
        let err = validate_push_gateway_url("http://push.example.com/api/v1/push/notify", true)
            .unwrap_err();
        assert_eq!(err.kind(), PushErrorKind::InvalidPushGatewayUrl);
    }

    #[test]
    fn allows_loopback_http_push_gateway_when_enabled() {
        validate_push_gateway_url("http://127.0.0.1:8080/api/v1/push/notify", true).unwrap();
        validate_push_gateway_url("http://localhost:8080/api/v1/push/notify", true).unwrap();
    }

    #[test]
    fn redacts_push_tokens_from_debug_output() {
        let request = build_register_device_request(
            &config(Some("android")),
            &prefs("https://push.example.com/api/v1/push/notify"),
        )
        .unwrap();
        let debug = format!("{request:?}");
        assert!(debug.contains("fcm:<redacted"));
        assert!(!debug.contains("very-secret-token"));

        let config_debug = format!("{:?}", config(Some("android")));
        assert!(config_debug.contains("fcm:<redacted"));
        assert!(!config_debug.contains("very-secret-token"));

        let unregister = build_unregister_device_request(
            &config(Some("android")),
            &prefs("https://push.example.com/api/v1/push/notify?debug=true"),
        )
        .unwrap();
        let unregister_debug = format!("{unregister:?}");
        assert!(!unregister_debug.contains("very-secret-token"));
        assert!(!unregister_debug.contains("debug=true"));
    }

    #[test]
    fn classifies_contrix_error_codes() {
        let envelope = ContrixErrorEnvelope {
            ok: false,
            error: ContrixError {
                code: "capability_denied".to_owned(),
                message: "denied".to_owned(),
                retry_after_ms: None,
                details: None,
            },
            request_id: Some("cx:req:test".to_owned()),
        };

        assert_eq!(
            classify_http_error(403, Some(&envelope)),
            PushErrorKind::CapabilityDenied
        );
    }

    #[test]
    fn builds_register_signing_context() {
        let request = build_register_device_request(
            &config(Some("android")),
            &prefs("https://push.example.com/api/v1/push/notify"),
        )
        .unwrap();

        let context = build_register_signing_context(
            "https://principal.example",
            &request,
            "2026-04-29T00:00:00Z",
            "https://principal.example",
        )
        .unwrap();

        assert_eq!(context.operation_id, crate::OPERATION_PUSH_REGISTER_DEVICE);
        assert_eq!(context.method, "POST");
        assert_eq!(context.path, REGISTER_DEVICE_PATH);
        assert_eq!(
            context.target_uri,
            "https://principal.example/api/v1/push/register-device"
        );
        assert_eq!(context.device_id, "did:web:alice.example#device-phone");
        assert!(context.content_digest.starts_with("sha-256=:"));
        assert!(context.content_digest.ends_with(':'));
    }

    #[test]
    fn builds_signing_context_with_actor_expiry_and_signature_headers() {
        let request = build_register_device_request(
            &config(Some("android")),
            &prefs("https://push.example.com/api/v1/push/notify"),
        )
        .unwrap();

        let context = build_register_signing_context_with_options(
            "https://principal.example",
            &request,
            PushRequestSigningOptions::new("2026-04-29T00:00:00Z", "https://principal.example")
                .with_actor_did("did:web:alice.example")
                .with_expires_at("2026-04-29T00:05:00Z")
                .with_origin("https://app.example")
                .with_origin_service_did("did:web:sync.example.com")
                .with_destination_service_did("did:web:principal.example")
                .with_nonce("idem-1")
                .with_idempotency_key("idem-1")
                .with_session_grant("coauth-grant-secret"),
        )
        .unwrap();

        assert_eq!(context.actor_did.as_deref(), Some("did:web:alice.example"));
        assert_eq!(context.expires_at.as_deref(), Some("2026-04-29T00:05:00Z"));

        let proof_body = context.canonical_proof_body().unwrap();
        assert_eq!(
            proof_body["operation_id"],
            crate::OPERATION_PUSH_REGISTER_DEVICE
        );
        assert_eq!(proof_body["actor_did"], "did:web:alice.example");
        assert_eq!(proof_body["expires_at"], "2026-04-29T00:05:00Z");
        assert_eq!(proof_body["origin"], "https://app.example");
        assert_eq!(proof_body["nonce"], "idem-1");

        let metadata_headers = context.signed_metadata_headers();
        assert!(
            metadata_headers
                .contains(&(CONTRIX_ACTOR_DID_HEADER, "did:web:alice.example".to_owned()))
        );
        assert!(
            metadata_headers
                .contains(&(CONTRIX_EXPIRES_AT_HEADER, "2026-04-29T00:05:00Z".to_owned()))
        );
        assert!(metadata_headers.contains(&(
            CONTRIX_ORIGIN_SERVICE_DID_HEADER,
            "did:web:sync.example.com".to_owned()
        )));
        assert!(metadata_headers.contains(&(
            CONTRIX_DESTINATION_SERVICE_DID_HEADER,
            "did:web:principal.example".to_owned()
        )));
        assert!(metadata_headers.contains(&(
            CONTRIX_SESSION_GRANT_HEADER,
            "coauth-grant-secret".to_owned()
        )));

        let signature_input = context.http_message_signature_input("sig1").unwrap();
        assert!(signature_input.contains("\"x-contrix-actor-did\""));
        assert!(signature_input.contains("\"x-contrix-expires-at\""));
        assert!(signature_input.contains("\"x-contrix-origin-service-did\""));
        assert!(signature_input.contains("\"x-contrix-destination-service-did\""));
        assert!(signature_input.contains("\"x-contrix-session-grant\""));

        let debug = format!("{context:?}");
        assert!(debug.contains("session_grant"));
        assert!(!debug.contains("coauth-grant-secret"));

        let signature_headers = context
            .http_message_signature_headers("sig1", "YWJjZA==")
            .unwrap();
        assert!(signature_headers.contains(&(SIGNATURE_INPUT_HEADER, signature_input)));
        assert!(signature_headers.contains(&(SIGNATURE_HEADER, "sig1=:YWJjZA==:".to_owned())));
    }

    #[test]
    fn rejects_invalid_signature_header_inputs() {
        let request = build_register_device_request(
            &config(Some("android")),
            &prefs("https://push.example.com/api/v1/push/notify"),
        )
        .unwrap();
        let context = build_register_signing_context(
            "https://principal.example",
            &request,
            "2026-04-29T00:00:00Z",
            "https://principal.example",
        )
        .unwrap();

        assert_eq!(
            context
                .http_message_signature_input("bad label")
                .unwrap_err()
                .kind(),
            PushErrorKind::InvalidHeader
        );
        assert_eq!(
            PushRequestSigningContext::http_message_signature_header("sig1", "bad:sig")
                .unwrap_err()
                .kind(),
            PushErrorKind::InvalidHeader
        );
    }

    #[test]
    fn signing_context_rejects_url_tokens() {
        let request = build_register_device_request(
            &config(Some("android")),
            &prefs("https://push.example.com/api/v1/push/notify"),
        )
        .unwrap();

        let err = build_register_signing_context(
            "https://principal.example?access_token=secret",
            &request,
            "2026-04-29T00:00:00Z",
            "https://principal.example",
        )
        .unwrap_err();

        assert_eq!(err.kind(), PushErrorKind::ForbiddenPushGatewayQueryParam);
    }
}

#[cfg(all(test, feature = "http"))]
mod http_tests {
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
    async fn register_retry_requires_idempotency_key() {
        let (base_url, requests) = spawn_mock_server(vec![MockResponse {
            status: "503 Service Unavailable",
            headers: vec![(RETRY_AFTER_HEADER, "0")],
            body: r#"{"ok":false,"error":{"code":"temporarily_unavailable","message":"try later"}}"#,
        }]);
        let mut config = config();
        config.idempotency_key = None;

        let err = ContrixPushClient::new(base_url)
            .with_retry_policy(PushRetryPolicy {
                max_retries: 1,
                initial_backoff: Duration::ZERO,
                max_backoff: Duration::ZERO,
                jitter: Duration::ZERO,
            })
            .register_device(&config, &prefs())
            .await
            .unwrap_err();

        assert_eq!(err.kind(), PushErrorKind::TemporarilyUnavailable);
        assert_eq!(requests.lock().unwrap().len(), 1);
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
