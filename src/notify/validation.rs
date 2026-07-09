use base64::Engine as _;
use base64::engine::general_purpose;
use arkret::blind_payload_sanitizer::{
    self as sdk_sanitizer, ALLOWED_PUSH_HINTS, is_forbidden_payload_key, is_valid_push_target_id,
};
use serde_json::{Map, Value};

use super::errors::PushNotifyPrivacyError;
use super::outcome::EncryptedEnvelopeError;

/// T1.1 — feed the `extra` map of a [`super::PushNotification`] through the
/// SDK sanitizer so the rule "no forbidden field anywhere, no `did:` / `ck:`
/// literal anywhere" stays unified across chime/floria.
///
/// We wrap the extras under a `notification` envelope so the SDK
/// sanitizer's wrapper-scan path runs (only forbidden-key + sensitive
/// literal checks, no allow-list — that lives in `validate_wire_model`).
pub(super) fn run_sdk_sanitizer_over_extra(
    extra: &Map<String, Value>,
) -> Result<(), PushNotifyPrivacyError> {
    if extra.is_empty() {
        return Ok(());
    }
    // Empty `notification` so we hit the "scan wrapper for forbidden
    // keys + literals, ignore wrapper's own allow-list" branch.
    let envelope = serde_json::json!({
        "notification": {
            "push_target_id": "ak:pseudonym:push:0000000000000000000000",
            "wakeup_kind": "message",
            "timing_profile_hint": "default",
        },
    });
    let mut envelope = envelope;
    if let Some(obj) = envelope.as_object_mut() {
        for (key, value) in extra {
            obj.insert(key.clone(), value.clone());
        }
    }
    sdk_sanitizer::sanitize_blind_payload(&envelope).map_err(PushNotifyPrivacyError::from)
}

pub(super) fn validate_push_hint_value(value: &str) -> Result<(), PushNotifyPrivacyError> {
    if value.to_ascii_lowercase().contains("did:") {
        return Err(PushNotifyPrivacyError::SensitiveField {
            field: "push_hint".to_owned(),
        });
    }

    if ALLOWED_PUSH_HINTS.contains(&value) || value == "l10n_key" {
        return Ok(());
    }

    Err(PushNotifyPrivacyError::InvalidFieldValue {
        field: "push_hint".to_owned(),
    })
}

pub(super) fn validate_push_target_id(value: &str) -> Result<(), PushNotifyPrivacyError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(PushNotifyPrivacyError::InvalidFieldValue {
            field: "push_target_id".to_owned(),
        });
    }

    let lower = trimmed.to_ascii_lowercase();
    if lower.contains("did:") {
        return Err(PushNotifyPrivacyError::SensitiveField {
            field: "push_target_id".to_owned(),
        });
    }

    if is_valid_push_target_id(trimmed) {
        return Ok(());
    }

    Err(PushNotifyPrivacyError::InvalidFieldValue {
        field: "push_target_id".to_owned(),
    })
}

pub(super) fn validate_push_route_token(
    field: &str,
    value: Option<&str>,
) -> Result<(), PushNotifyPrivacyError> {
    let Some(value) = value else {
        return Ok(());
    };
    let value = value.trim();
    if value.len() < 22
        || value.len() > 512
        || !value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '~' | '-'))
    {
        return Err(PushNotifyPrivacyError::InvalidFieldValue {
            field: field.to_owned(),
        });
    }
    Ok(())
}

pub(super) fn validate_required(field: &str, value: &str) -> Result<(), PushNotifyPrivacyError> {
    if value.trim().is_empty() {
        return Err(PushNotifyPrivacyError::MissingField {
            field: field.to_owned(),
        });
    }
    Ok(())
}

pub(super) fn validate_optional_non_empty(
    field: &str,
    value: Option<&str>,
) -> Result<(), PushNotifyPrivacyError> {
    if value.is_some_and(|raw| raw.trim().is_empty()) {
        return Err(PushNotifyPrivacyError::InvalidFieldValue {
            field: field.to_owned(),
        });
    }
    Ok(())
}

pub(super) fn validate_typed_id(
    field: &str,
    value: Option<&str>,
    prefix: &str,
) -> Result<(), PushNotifyPrivacyError> {
    let Some(value) = value else {
        return Ok(());
    };
    if value.trim().is_empty() || !value.starts_with(prefix) {
        return Err(PushNotifyPrivacyError::InvalidFieldValue {
            field: field.to_owned(),
        });
    }
    Ok(())
}

pub(super) fn validate_active_reference_extension(
    key: &str,
    value: &Value,
) -> Result<(), PushNotifyPrivacyError> {
    if matches!(key, "schema_id" | "kind") {
        return Err(PushNotifyPrivacyError::RemovedField {
            field: key.to_owned(),
        });
    }

    match key {
        "strand_id" => validate_extra_typed_string(key, value, "ak:strand:"),
        "message_id" => validate_extra_typed_string(key, value, "ak:message:"),
        "notification_projection_id" => {
            validate_extra_typed_string(key, value, "ak:notification_projection:")
        }
        _ => Ok(()),
    }
}

fn validate_extra_typed_string(
    key: &str,
    value: &Value,
    prefix: &str,
) -> Result<(), PushNotifyPrivacyError> {
    match value.as_str() {
        Some(raw) if raw.starts_with(prefix) => Ok(()),
        _ => Err(PushNotifyPrivacyError::InvalidFieldValue {
            field: key.to_owned(),
        }),
    }
}

/// Validate `notification.counts` under the `blind_wakeup` privacy baseline.
///
/// Per `discovery/push-notifications.md` §5.1 (normative), a plaintext
/// **absolute** unread count is an activity side-channel and MUST NOT
/// travel in a blind wakeup. `counts` MUST instead use one of:
///
/// 1. a coarse boolean `badge` (`true`/`false` — "has / has-no new content");
/// 2. an `unread_increment` delta (a number that conveys only the change, not the running total);
///    or
/// 3. a **bucketized** string such as `"1"` / `"2-5"` / `"6+"`.
///
/// chime can enforce the structural part of this rule: a bare `Number`
/// for any key other than the `*_increment` delta keys is a plaintext
/// absolute count and is rejected. The hysteresis / minimum-residency
/// requirement on bucket outputs depends on Realm policy bandwidth that
/// is not visible at the chime boundary and is enforced by the emitting
/// service (floria); see SPEC-CR follow-up.
///
/// `leaf_key` is the immediate object key the value was found under (the
/// last path segment), used to distinguish increment deltas from absolute
/// counts. The top-level `counts` object passes `None`.
pub(super) fn validate_counts(
    path: &str,
    leaf_key: Option<&str>,
    value: &Value,
) -> Result<(), PushNotifyPrivacyError> {
    match value {
        // Coarse boolean badge — never exposes an absolute magnitude.
        Value::Bool(_) => Ok(()),
        // A numeric value is only permitted for increment-delta keys.
        // Any other numeric key is a plaintext absolute count, which
        // §5.1 forbids under blind_wakeup.
        Value::Number(_) => match leaf_key {
            Some(key) if key == "unread_increment" || key.ends_with("_increment") => Ok(()),
            _ => Err(PushNotifyPrivacyError::SensitiveField {
                field: path.to_owned(),
            }),
        },
        // Bucketized string form (e.g. "1" / "2-5" / "6+"). We reject any
        // sensitive literal but otherwise treat the opaque bucket label as
        // acceptable; the policy-driven hysteresis/min-residency band is
        // enforced by the emitting service, not visible here.
        Value::String(raw) => {
            let lowered = raw.to_ascii_lowercase();
            if lowered.contains("did:") || lowered.contains(":did") {
                return Err(PushNotifyPrivacyError::SensitiveField {
                    field: path.to_owned(),
                });
            }
            Ok(())
        }
        Value::Object(map) => {
            for (key, nested) in map {
                validate_counts(&format!("{path}.{key}"), Some(key), nested)?;
            }
            Ok(())
        }
        _ => Err(PushNotifyPrivacyError::SensitiveField {
            field: path.to_owned(),
        }),
    }
}

pub(super) fn validate_extra_value(
    path: &str,
    value: &Value,
) -> Result<(), PushNotifyPrivacyError> {
    match value {
        Value::String(raw) => {
            if raw.to_ascii_lowercase().contains("did:") {
                return Err(PushNotifyPrivacyError::SensitiveField {
                    field: path.to_owned(),
                });
            }
            Ok(())
        }
        Value::Array(values) => {
            for (index, nested) in values.iter().enumerate() {
                validate_extra_value(&format!("{path}[{index}]"), nested)?;
            }
            Ok(())
        }
        Value::Object(map) => {
            for (key, nested) in map {
                let nested_path = format!("{path}.{key}");
                if is_sensitive_payload_key(key) {
                    return Err(PushNotifyPrivacyError::SensitiveField { field: nested_path });
                }
                validate_extra_value(&nested_path, nested)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

pub(super) fn validate_plaintext_extra_value(
    path: &str,
    value: &Value,
) -> Result<(), PushNotifyPrivacyError> {
    match value {
        Value::Array(values) => {
            for (index, nested) in values.iter().enumerate() {
                validate_plaintext_extra_value(&format!("{path}[{index}]"), nested)?;
            }
            Ok(())
        }
        Value::Object(map) => {
            for (key, nested) in map {
                let nested_path = format!("{path}.{key}");
                if is_never_allowed_payload_key(key) {
                    return Err(PushNotifyPrivacyError::SensitiveField { field: nested_path });
                }
                validate_plaintext_extra_value(&nested_path, nested)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

pub(super) fn is_sensitive_payload_key(key: &str) -> bool {
    if is_forbidden_payload_key(key) {
        return true;
    }

    // A blind wakeup is the strictest privacy mode: anything that is
    // never allowed even on a plaintext-visible service DID (encrypted
    // carriers such as `encrypted_payload` / `encrypted_metadata`, raw
    // `metadata` / `fields`, `track` / `track_name`, call-setup, …) is
    // a fortiori forbidden here. spec push-notifications.md §6.2:
    // "Sync Service MUST NOT 在推送中包含 `encrypted_content` /
    // `encrypted_metadata` / `encrypted_payload` 的任何部分".
    if is_never_allowed_payload_key(key) {
        return true;
    }

    matches!(
        key,
        // Local policy extension: SDK blocks `space_name` / `strand_name` /
        // `room_name`; chime also treats the v1 security-boundary display
        // label as sensitive until all downstream services agree on a
        // generic `*_name` rule.
        "realm_name"
            | "sender_actor_display_name"
            // CKP-0007 — Circle display label. The typed `circle_id` may
            // travel; the human-readable label must not. Circle membership
            // surfaces (`circle_members` / `circle_member_dids` /
            // `circle_member_actor_ids`) are covered by the shared
            // `is_never_allowed_payload_key` set above.
            | "circle_name"
            | "circle_display_name"
    )
}

pub(super) fn is_never_allowed_payload_key(key: &str) -> bool {
    matches!(
        key,
        "provider_payload"
            | "aps"
            | "content"
            | "content_body"
            | "content_msgtype"
            | "body"
            | "preview"
            | "summary"
            | "encrypted_payload"
            | "encrypted_content"
            | "encrypted_metadata"
            | "metadata"
            | "fields"
            | "track"
            | "track_name"
            | "ciphertext"
            | "sdp"
            | "candidate"
            | "ice"
            | "turn"
            | "call_setup"
            // CKP-0007 — Circle membership surfaces are never allowed
            // on any wakeup wire even for plaintext-visible service DIDs.
            | "circle_members"
            | "circle_member_dids"
            | "circle_member_actor_ids"
    )
}

pub(super) fn validate_base64_field(
    field: &'static str,
    value: &str,
) -> Result<(), EncryptedEnvelopeError> {
    let value = value.trim();
    if value.is_empty() {
        return Err(EncryptedEnvelopeError::MissingField { field });
    }

    if general_purpose::STANDARD.decode(value).is_ok()
        || general_purpose::URL_SAFE.decode(value).is_ok()
        || general_purpose::URL_SAFE_NO_PAD.decode(value).is_ok()
    {
        Ok(())
    } else {
        Err(EncryptedEnvelopeError::InvalidBase64 { field })
    }
}
