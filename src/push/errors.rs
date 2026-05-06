//! Push registration error types and HTTP status classification.

use std::fmt;
use std::time::{Duration, SystemTime};

use thiserror::Error;

use super::urls::{redact_url, redact_webpush_endpoint};
use super::wire::ContrixErrorEnvelope;

/// Stable high-level category for push registration failures.
///
/// Stability: `0.x`-stable. New variants are additive; matching against
/// the enum should always include a wildcard arm to forward-compat
/// against future error categories. Renaming or removing a variant
/// requires a SemVer bump.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
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
    /// HTTP 410 Gone — the push token (or registration) has been retired and
    /// callers should drop it locally rather than retry.
    Gone,
    SchemaViolation,
    NetworkTimeout,
    Network,
    InvalidResponse,
    HttpStatus,
}

impl PushErrorKind {
    /// Stable bit position used by retry-policy bitmasks. Hand-assigned
    /// so `#[non_exhaustive]` additions never silently reorder existing
    /// callers' masks.
    pub const fn ordinal(self) -> u8 {
        match self {
            Self::MissingField => 0,
            Self::InvalidPlatform => 1,
            Self::InvalidPushGatewayUrl => 2,
            Self::InvalidWebPushEndpoint => 3,
            Self::WebPushEndpointNotAllowed => 4,
            Self::ForbiddenPushGatewayQueryParam => 5,
            Self::InvalidHeader => 6,
            Self::Unauthenticated => 7,
            Self::CapabilityDenied => 8,
            Self::RateLimited => 9,
            Self::TemporarilyUnavailable => 10,
            Self::DuplicateConflict => 11,
            Self::NotFound => 12,
            Self::Gone => 13,
            Self::SchemaViolation => 14,
            Self::NetworkTimeout => 15,
            Self::Network => 16,
            Self::InvalidResponse => 17,
            Self::HttpStatus => 18,
        }
    }

    /// Map a Contrix `bridge/describe.failure_codes` string to a stable kind.
    ///
    /// Returns `None` when the code is not part of the contract, so callers can
    /// decide between treating it as `HttpStatus` or surfacing the raw code.
    pub fn from_failure_code(code: &str) -> Option<Self> {
        Some(match code {
            "unauthenticated" | "auth_expired" | "soft_logged_out" => Self::Unauthenticated,
            "capability_denied" => Self::CapabilityDenied,
            "rate_limited" => Self::RateLimited,
            "temporarily_unavailable" => Self::TemporarilyUnavailable,
            "duplicate_conflict" => Self::DuplicateConflict,
            "not_found" => Self::NotFound,
            "gone" | "registration_gone" | "push_token_gone" => Self::Gone,
            "schema_violation" | "bad_json" | "bad_query" | "missing_param" | "invalid_param" => {
                Self::SchemaViolation
            }
            _ => return None,
        })
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
    pub(super) fn is_retryable(&self) -> bool {
        matches!(
            self.kind(),
            PushErrorKind::RateLimited
                | PushErrorKind::TemporarilyUnavailable
                | PushErrorKind::NetworkTimeout
        )
    }
}

#[cfg(any(test, feature = "http"))]
pub(super) fn classify_http_error(
    status: u16,
    error: Option<&ContrixErrorEnvelope>,
) -> PushErrorKind {
    if let Some(code) = error.map(|envelope| envelope.error.code.as_str())
        && let Some(kind) = PushErrorKind::from_failure_code(code)
    {
        return kind;
    }

    match status {
        401 => PushErrorKind::Unauthenticated,
        403 => PushErrorKind::CapabilityDenied,
        404 => PushErrorKind::NotFound,
        409 => PushErrorKind::DuplicateConflict,
        410 => PushErrorKind::Gone,
        400 | 422 => PushErrorKind::SchemaViolation,
        429 => PushErrorKind::RateLimited,
        503 => PushErrorKind::TemporarilyUnavailable,
        _ => PushErrorKind::HttpStatus,
    }
}

pub(super) fn parse_retry_after(value: &str) -> Option<Duration> {
    if let Ok(seconds) = value.trim().parse::<u64>() {
        return Some(Duration::from_secs(seconds));
    }

    let retry_at = httpdate::parse_http_date(value).ok()?;
    let now = SystemTime::now();
    retry_at.duration_since(now).ok().or(Some(Duration::ZERO))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::push::wire::ContrixError;

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
    fn maps_410_gone_status() {
        assert_eq!(classify_http_error(410, None), PushErrorKind::Gone);
    }

    #[test]
    fn from_failure_code_covers_contract() {
        assert_eq!(
            PushErrorKind::from_failure_code("rate_limited"),
            Some(PushErrorKind::RateLimited)
        );
        assert_eq!(
            PushErrorKind::from_failure_code("registration_gone"),
            Some(PushErrorKind::Gone)
        );
        assert_eq!(PushErrorKind::from_failure_code("unknown_code"), None);
    }
}
