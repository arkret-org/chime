use arkret_wire::{Problem, ServiceOperationId};
use serde::{Deserialize, Serialize};

use super::super::errors::{PushRegistrationError, classify_http_error};
use super::super::urls::try_station_api_url;
use super::super::{ARKRET_REQUEST_ID_HEADER, RETRY_AFTER_HEADER};
use super::core::ArkretPushClient;
use super::idempotency::generate_idempotency_key;

pub(super) const MAX_RESPONSE_BODY_BYTES: usize = 1024 * 1024;

async fn read_response_body(response: reqwest::Response) -> Result<String, PushRegistrationError> {
    if let Some(actual) = response.content_length()
        && actual > MAX_RESPONSE_BODY_BYTES as u64
    {
        return Err(PushRegistrationError::ResponseTooLarge {
            limit: MAX_RESPONSE_BODY_BYTES,
            actual: usize::try_from(actual).unwrap_or(usize::MAX),
        });
    }
    #[cfg(not(target_arch = "wasm32"))]
    let body = {
        let mut response = response;
        let mut body = Vec::with_capacity(
            response
                .content_length()
                .and_then(|length| usize::try_from(length).ok())
                .unwrap_or(0),
        );
        while let Some(chunk) = response.chunk().await? {
            let actual = body.len().saturating_add(chunk.len());
            if actual > MAX_RESPONSE_BODY_BYTES {
                return Err(PushRegistrationError::ResponseTooLarge {
                    limit: MAX_RESPONSE_BODY_BYTES,
                    actual,
                });
            }
            body.extend_from_slice(&chunk);
        }
        body
    };

    // reqwest's fetch-backed wasm response does not expose `chunk()`. The
    // browser has already buffered the body, so read it once and retain the
    // same post-read limit check used by the streaming native path.
    #[cfg(target_arch = "wasm32")]
    let body = {
        let body = response.bytes().await?;
        if body.len() > MAX_RESPONSE_BODY_BYTES {
            return Err(PushRegistrationError::ResponseTooLarge {
                limit: MAX_RESPONSE_BODY_BYTES,
                actual: body.len(),
            });
        }
        body
    };

    Ok(String::from_utf8_lossy(&body).into_owned())
}

/// HTTP response body plus Arkret response metadata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArkretHttpResponse<T> {
    pub body: T,
    pub request_id: Option<String>,
    pub retry_after: Option<String>,
}

#[cfg(not(target_arch = "wasm32"))]
pub(super) fn default_http_client() -> reqwest::Client {
    // Disable redirect-following: the push register/unregister/describe
    // calls are protocol-face POST/GET that never legitimately need a
    // client redirect. reqwest only strips the standard
    // Authorization/Cookie/Proxy-Authorization headers on a cross-host
    // redirect, NOT custom headers — so following a 3xx would re-send
    // the credential-bearing `x-arkret-session-grant` and HTTP Message
    // Signature headers to the redirect target. We fail-close on any
    // 3xx instead. Hosts injecting their own client via
    // `with_http_client` should apply the same policy.
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
}

#[cfg(target_arch = "wasm32")]
pub(super) fn default_http_client() -> reqwest::Client {
    reqwest::Client::new()
}

impl ArkretPushClient {
    pub(super) async fn post_json<T, R>(
        &self,
        path: &str,
        body: &T,
        idempotency_key: Option<&str>,
        request_id: Option<&str>,
    ) -> Result<ArkretHttpResponse<R>, PushRegistrationError>
    where
        T: Serialize + ?Sized,
        R: for<'de> Deserialize<'de>,
    {
        let idempotency_key = idempotency_key
            .map(str::to_owned)
            .unwrap_or_else(generate_idempotency_key);
        let idempotency_key = Some(idempotency_key.as_str());
        let url = try_station_api_url(&self.station_base_url, path)?;
        let body_bytes = arkret_canonical::canonical_json_bytes(body).map_err(|error| {
            PushRegistrationError::InvalidField {
                field: "body",
                reason: format!("request body is not canonical-JSON encodable: {error}"),
            }
        })?;
        let mut request = self
            .http
            .post(url)
            .header(reqwest::header::USER_AGENT, self.user_agent.as_str())
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body_bytes);

        if let Some(operation) = ServiceOperationId::from_http_request("POST", path) {
            request = request.header("Arkret-Operation", operation.as_str());
        }

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
                    name: ARKRET_REQUEST_ID_HEADER.to_owned(),
                }
            })?;
            request = request.header(ARKRET_REQUEST_ID_HEADER, request_id);
        }

        for (name, value) in &self.headers {
            request = request.header(name, value);
        }

        let response = request.send().await?;
        let status = response.status();
        let headers = response.headers().clone();
        let retry_after = header_value(&headers, RETRY_AFTER_HEADER);
        let request_id = header_value(&headers, ARKRET_REQUEST_ID_HEADER);
        let body = read_response_body(response).await?;

        if !status.is_success() {
            let error = serde_json::from_str::<Problem>(&body).ok().map(Box::new);
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

        let decoded = if status == reqwest::StatusCode::NO_CONTENT && body.is_empty() {
            serde_json::from_str("null")?
        } else {
            serde_json::from_str(&body)?
        };
        Ok(ArkretHttpResponse {
            body: decoded,
            request_id,
            retry_after,
        })
    }
}

pub(super) fn header_value(headers: &reqwest::header::HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}
