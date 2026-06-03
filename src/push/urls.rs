//! URL construction, validation, and redaction helpers.

use std::fmt::Write as _;
use std::net::IpAddr;

use url::Url;

use super::errors::PushRegistrationError;
use super::{PUSH_BRIDGE_DESCRIBE_PATH, PUSH_INTEGRATION_DESCRIBE_PATH};

/// Builds a normalized Cokret API URL.
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

/// Derive the gateway service base URL from a configured push notify endpoint.
pub fn push_gateway_service_base_url(
    push_gateway_url: &str,
) -> Result<String, PushRegistrationError> {
    require_non_empty("push_gateway", push_gateway_url)?;

    let mut url = Url::parse(push_gateway_url).map_err(|error| {
        PushRegistrationError::InvalidPushGatewayUrl {
            url: push_gateway_url.to_owned(),
            reason: error.to_string(),
        }
    })?;

    if !url.username().is_empty() || url.password().is_some() {
        return Err(PushRegistrationError::InvalidPushGatewayUrl {
            url: push_gateway_url.to_owned(),
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

    url.set_query(None);
    url.set_fragment(None);

    let mut path = url.path().trim_end_matches('/').to_owned();
    for suffix in [
        "/api/v1/push/bridge/describe",
        "/cokret/push/v1/bridge/describe",
        "/api/v1/push/notify",
        "/cokret/push/v1/notify",
        "/api/v1/push",
        "/cokret/push/v1",
    ] {
        if let Some(prefix) = path.strip_suffix(suffix) {
            path = prefix.to_owned();
            break;
        }
    }

    if path.is_empty() {
        url.set_path("/");
    } else {
        url.set_path(&path);
    }

    // Avoid the extra `to_owned()` allocation by truncating the
    // `String` in place after measuring the trailing-slash run.
    let mut s = url.to_string();
    let new_len = s.trim_end_matches('/').len();
    s.truncate(new_len);
    Ok(s)
}

/// Derive the active bridge-describe URL from a configured push gateway URL.
pub fn push_bridge_describe_url(push_gateway_url: &str) -> Result<String, PushRegistrationError> {
    Ok(contrix_api_url(
        &push_gateway_service_base_url(push_gateway_url)?,
        PUSH_BRIDGE_DESCRIBE_PATH,
    ))
}

/// Derive the active integration-describe URL from a configured push gateway URL.
pub fn push_integration_describe_url(
    push_gateway_url: &str,
) -> Result<String, PushRegistrationError> {
    Ok(contrix_api_url(
        &push_gateway_service_base_url(push_gateway_url)?,
        PUSH_INTEGRATION_DESCRIBE_PATH,
    ))
}

/// Validate a Cokret push gateway endpoint.
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

pub(super) fn try_contrix_api_url(
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
        // Use `write!` to avoid an intermediate `String` allocation that
        // `push_str(&port.to_string())` would produce.
        let _ = write!(origin, ":{port}");
    }
    Some(origin)
}

pub(super) fn redact_url(value: &str) -> String {
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

pub(super) fn redact_webpush_endpoint(value: &str) -> String {
    format!("<redacted-webpush-endpoint,len={}>", value.chars().count())
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

// -- Shared input validators ------------------------------------------------

pub(super) fn require_non_empty(
    name: &'static str,
    value: &str,
) -> Result<(), PushRegistrationError> {
    if non_empty(value).is_some() {
        Ok(())
    } else {
        Err(PushRegistrationError::MissingField(name))
    }
}

pub(super) fn require_optional_non_empty<'a>(
    name: &'static str,
    value: Option<&'a str>,
) -> Result<&'a str, PushRegistrationError> {
    value
        .and_then(non_empty)
        .ok_or(PushRegistrationError::MissingField(name))
}

pub(super) fn require_owned_non_empty(
    name: &'static str,
    value: String,
) -> Result<String, PushRegistrationError> {
    non_empty(&value)
        .map(str::to_owned)
        .ok_or(PushRegistrationError::MissingField(name))
}

pub(super) fn require_optional_owned_non_empty(
    name: &'static str,
    value: Option<String>,
) -> Result<Option<String>, PushRegistrationError> {
    value
        .map(|value| require_owned_non_empty(name, value))
        .transpose()
}

pub(super) fn non_empty(value: &str) -> Option<&str> {
    let value = value.trim();
    (!value.is_empty()).then_some(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::push::REGISTER_DEVICE_PATH;
    use crate::push::errors::PushErrorKind;

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
}
