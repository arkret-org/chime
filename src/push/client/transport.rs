use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::super::errors::{PushRegistrationError, classify_http_error};
use super::super::urls::try_cokret_api_url;
use super::super::wire::CokretErrorEnvelope;
use super::super::{COKRET_REQUEST_ID_HEADER, RETRY_AFTER_HEADER};
use super::core::CokretPushClient;
use super::retry::{generate_idempotency_key, retry_jitter_seed, sleep_for};

/// HTTP response body plus Cokret response metadata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CokretHttpOutcome<T> {
    pub body: T,
    pub request_id: Option<String>,
    pub retry_after: Option<String>,
}

impl<T> CokretHttpOutcome<T> {
    pub fn map_body<U>(self, f: impl FnOnce(T) -> U) -> CokretHttpOutcome<U> {
        CokretHttpOutcome {
            body: f(self.body),
            request_id: self.request_id,
            retry_after: self.retry_after,
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub(super) fn default_http_client() -> reqwest::Client {
    // Disable redirect-following: the push register/unregister/describe
    // calls are protocol-face POST/GET that never legitimately need a
    // client redirect. reqwest only strips the standard
    // Authorization/Cookie/Proxy-Authorization headers on a cross-host
    // redirect, NOT custom headers — so following a 3xx would re-send
    // the credential-bearing `x-cokret-session-grant` and HTTP Message
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

impl CokretPushClient {
    pub(super) async fn post_json<T, R>(
        &self,
        path: &str,
        body: &T,
        idempotency_key: Option<&str>,
        request_id: Option<&str>,
    ) -> Result<CokretHttpOutcome<R>, PushRegistrationError>
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

    pub(super) async fn get_json<R>(
        &self,
        path: &str,
    ) -> Result<CokretHttpOutcome<R>, PushRegistrationError>
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
    ) -> Result<CokretHttpOutcome<R>, PushRegistrationError>
    where
        T: Serialize + ?Sized,
        R: for<'de> Deserialize<'de>,
    {
        let url = try_cokret_api_url(&self.service_base_url, path)?;
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
                    name: COKRET_REQUEST_ID_HEADER.to_owned(),
                }
            })?;
            request = request.header(COKRET_REQUEST_ID_HEADER, request_id);
        }

        for (name, value) in &self.headers {
            request = request.header(name, value);
        }

        let response = request.send().await?;
        let status = response.status();
        let headers = response.headers().clone();
        let retry_after = header_value(&headers, RETRY_AFTER_HEADER);
        let request_id = header_value(&headers, COKRET_REQUEST_ID_HEADER);
        let body = response.text().await?;

        if !status.is_success() {
            let error = serde_json::from_str::<CokretErrorEnvelope>(&body)
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

        Ok(CokretHttpOutcome {
            body: serde_json::from_str(&body)?,
            request_id,
            retry_after,
        })
    }

    async fn get_json_once<R>(
        &self,
        path: &str,
    ) -> Result<CokretHttpOutcome<R>, PushRegistrationError>
    where
        R: for<'de> Deserialize<'de>,
    {
        let url = try_cokret_api_url(&self.service_base_url, path)?;
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
                    name: COKRET_REQUEST_ID_HEADER.to_owned(),
                }
            })?;
            request = request.header(COKRET_REQUEST_ID_HEADER, request_id);
        }

        for (name, value) in &self.headers {
            request = request.header(name, value);
        }

        let response = request.send().await?;
        let status = response.status();
        let headers = response.headers().clone();
        let retry_after = header_value(&headers, RETRY_AFTER_HEADER);
        let request_id = header_value(&headers, COKRET_REQUEST_ID_HEADER);
        let body = response.text().await?;

        if !status.is_success() {
            let error = serde_json::from_str::<CokretErrorEnvelope>(&body)
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

        Ok(CokretHttpOutcome {
            body: serde_json::from_str(&body)?,
            request_id,
            retry_after,
        })
    }

    pub(super) fn backoff_delay(&self, retry_count: u32) -> Duration {
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
        let mut value = self.retry_jitter_seed.wrapping_add(attempt_seed)
            ^ ((retry_count as u64).wrapping_add(1) * 0x9E37_79B9_7F4A_7C15);
        value ^= value >> 30;
        value = value.wrapping_mul(0xBF58_476D_1CE4_E5B9);
        value ^= value >> 27;
        value = value.wrapping_mul(0x94D0_49BB_1331_11EB);
        value ^= value >> 31;
        Duration::from_nanos(value % (max_nanos.saturating_add(1)))
    }
}

pub(super) fn header_value(headers: &reqwest::header::HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}
