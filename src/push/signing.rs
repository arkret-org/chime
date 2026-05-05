//! HTTP Message Signature / DID-proof signing context construction.

use std::fmt;

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use super::errors::PushRegistrationError;
use super::urls::{
    redact_url, require_optional_owned_non_empty, require_owned_non_empty, try_contrix_api_url,
};
use super::{
    CONTENT_DIGEST_HEADER, CONTRIX_ACTOR_DID_HEADER, CONTRIX_AUDIENCE_HEADER,
    CONTRIX_CREATED_AT_HEADER, CONTRIX_DESTINATION_SERVICE_DID_HEADER, CONTRIX_DEVICE_ID_HEADER,
    CONTRIX_EXPIRES_AT_HEADER, CONTRIX_IDEMPOTENCY_KEY_HEADER, CONTRIX_NONCE_HEADER,
    CONTRIX_OPERATION_ID_HEADER, CONTRIX_ORIGIN_HEADER, CONTRIX_ORIGIN_SERVICE_DID_HEADER,
    CONTRIX_SESSION_GRANT_HEADER, SIGNATURE_HEADER, SIGNATURE_INPUT_HEADER,
};

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

pub(super) fn build_signing_context<T>(
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
    let valid = !signature.trim().is_empty()
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
