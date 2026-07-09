use std::fmt;

use arkret::Did;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::validation::validate_base64_field;
use crate::redact_push_key;

/// Active HPKE suite ids from `hpke-suite-registry.json`.
///
/// This is a narrow receiver-side allowlist for `EncryptedEnvelope.algorithm`.
/// Reserved registry rows are intentionally excluded until the spec marks them
/// active and the SDK exposes a generated registry view.
pub const SUPPORTED_ENCRYPTED_ENVELOPE_ALGORITHMS: &[&str] = &[
    "ak.hpke_x25519_aead_xchacha20poly1305.v1",
    "ak.hpke_x25519_aead_aes256gcm.v1",
    "ak.hpke_x25519_aead_chacha20poly1305.v1",
    "ak.hpke_p256_aead_aes256gcm.v1",
];

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct ChimePushNotifyOutcome {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    #[serde(default)]
    pub accepted: usize,
    #[serde(default)]
    pub rejected: Vec<RejectedPushToken>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub provider_retries: Vec<ProviderRetryHint>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub delivery_receipts: Vec<PushDeliveryReceipt>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderRetryHint {
    pub provider: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_after_ms: Option<u64>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushDeliveryReceipt {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_message_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub push_key_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_after_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
}

#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RejectedPushToken {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub push_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub push_key_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl fmt::Debug for RejectedPushToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RejectedPushToken")
            .field("push_key", &self.push_key.as_deref().map(redact_push_key))
            .field("push_key_hash", &self.push_key_hash)
            .field("app_id", &self.app_id)
            .field("reason", &self.reason)
            .finish()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EncryptedEnvelope {
    pub recipient: String,
    pub algorithm: String,
    pub ciphertext: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aad: Option<String>,
}

impl EncryptedEnvelope {
    pub fn new(
        recipient: impl Into<String>,
        algorithm: impl Into<String>,
        ciphertext: impl Into<String>,
    ) -> Result<Self, EncryptedEnvelopeError> {
        let envelope = Self {
            recipient: recipient.into(),
            algorithm: algorithm.into(),
            ciphertext: ciphertext.into(),
            nonce: None,
            key_id: None,
            aad: None,
        };
        envelope.validate()?;
        Ok(envelope)
    }

    pub fn with_nonce(mut self, nonce: impl Into<String>) -> Result<Self, EncryptedEnvelopeError> {
        let nonce = nonce.into();
        validate_base64_field("nonce", &nonce)?;
        self.nonce = Some(nonce);
        Ok(self)
    }

    pub fn with_key_id(mut self, key_id: impl Into<String>) -> Self {
        self.key_id = Some(key_id.into());
        self
    }

    pub fn with_aad(mut self, aad: impl Into<String>) -> Self {
        self.aad = Some(aad.into());
        self
    }

    pub fn validate(&self) -> Result<(), EncryptedEnvelopeError> {
        if self.recipient.trim().is_empty() {
            return Err(EncryptedEnvelopeError::MissingField { field: "recipient" });
        }
        // Round 4 (B5, spec a77b995) — DID regex sweep: route the
        // recipient through the SDK's tightened `Did::new` validator
        // (`^did:[a-z0-9]+:[^\s]+$`) instead of the previous
        // permissive `starts_with("did:")` shape. The pre-round-4 form
        // accepted method names with `.`/`-`/`_`/`:` which is now
        // wire-broken; reject them at the EncryptedEnvelope boundary
        // so chime can't be used to smuggle them past floria.
        if Did::new(self.recipient.clone()).is_err() {
            return Err(EncryptedEnvelopeError::InvalidRecipient {
                got: self.recipient.clone(),
            });
        }
        if self.algorithm.trim().is_empty() {
            return Err(EncryptedEnvelopeError::MissingField { field: "algorithm" });
        }
        if !SUPPORTED_ENCRYPTED_ENVELOPE_ALGORITHMS.contains(&self.algorithm.as_str()) {
            return Err(EncryptedEnvelopeError::UnsupportedAlgorithm {
                algorithm: self.algorithm.clone(),
            });
        }
        if self.ciphertext.trim().is_empty() {
            return Err(EncryptedEnvelopeError::MissingField {
                field: "ciphertext",
            });
        }
        validate_base64_field("ciphertext", &self.ciphertext)?;
        if let Some(nonce) = self.nonce.as_deref() {
            validate_base64_field("nonce", nonce)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum EncryptedEnvelopeError {
    #[error("encrypted envelope is missing required field `{field}`")]
    MissingField { field: &'static str },
    #[error("encrypted envelope recipient must be a DID, got `{got}`")]
    InvalidRecipient { got: String },
    #[error("encrypted envelope algorithm is not an active HPKE suite: `{algorithm}`")]
    UnsupportedAlgorithm { algorithm: String },
    #[error("encrypted envelope field `{field}` is not base64")]
    InvalidBase64 { field: &'static str },
}
