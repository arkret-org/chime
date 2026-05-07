//! Actor-private `cx.device.push_route` state event wire model.
//!
//! Spec: `contrix-spec/spec/v1/zh/crypto-media/device-lifecycle.md` §5a.2.
//! A device records its push routes — keyed by `(principal_id,
//! device_id, push_route)` — into the principal control stream so the
//! Sync Service can look up which pairwise pseudonym to use without
//! ever holding a `principal/device → push_target_id` reverse map.
//!
//! `chime` does not own private keys, control streams, or persistence.
//! This module only models the wire shape and the activation /
//! revocation state machine so consumers (yougen, soland) agree on
//! what a route is and how it rotates.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

#[cfg(feature = "notify")]
use crate::PushTargetId;

/// Logical channel identifier on a device.
///
/// Examples: `apns_main`, `fcm_voip`, `webpush_default`. The id is
/// opaque to the Sync Service and is only meaningful within the
/// originating device. Length and charset are constrained so callers
/// cannot smuggle DIDs or call setup material through this field.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct PushRouteId(String);

impl PushRouteId {
    /// Construct an id, validating against the route-id rules.
    pub fn new(value: impl Into<String>) -> Result<Self, PushRouteError> {
        let value = value.into();
        validate_push_route_id(&value)?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for PushRouteId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        Self::new(raw).map_err(serde::de::Error::custom)
    }
}

/// Capability advertised by a push route.
///
/// Sync Service consults these tags before fanning a wakeup to the
/// route — for example, only routes with `voip` may receive
/// `WakeupKind::IncomingCall`.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PushRouteCapability {
    /// Standard chat / mention wakeups.
    Chat,
    /// VoIP / call invite wakeups.
    Voip,
    /// Background sync / silent wakeups.
    Silent,
    /// Data-only wakeups (no user-visible alert).
    Data,
    /// Custom capability tag. Opaque, ≤32 chars, `[a-z0-9_]`.
    #[serde(untagged)]
    Custom(String),
}

/// Single `(push_route, push_target_id, …)` registration written by a
/// device into its actor-private control stream.
///
/// Stability: `0.x`-stable. Adding capability tags is additive; renaming
/// or removing fields requires a SemVer bump.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct PushRoute {
    /// Logical channel name on the device.
    pub route: PushRouteId,
    /// Per-route pairwise pseudonym. Required when the route is
    /// active; `None` is only legal when `revoked == true`.
    #[cfg(feature = "notify")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub push_target_id: Option<PushTargetId>,
    /// Same field as the `notify` feature variant, but stored as a raw
    /// string when the consumer does not pull in the gateway wire
    /// validators. Mutually exclusive with the typed form above.
    #[cfg(not(feature = "notify"))]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub push_target_id: Option<String>,
    /// DID of the push gateway that should receive notifications for
    /// this route. Sync Service uses this to pick the right HTTP
    /// destination per route.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub push_gateway_did: Option<String>,
    /// Optional public key (base64) the gateway / Sync Service should
    /// use to encrypt route-bound payloads. chime never holds the
    /// matching private key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encryption_key: Option<String>,
    /// Capability tags. Empty means "general purpose chat / mention".
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<PushRouteCapability>,
    /// `true` after the device has retired the route. Once this is
    /// `true`, the Sync Service MUST stop accepting the old
    /// `push_target_id`.
    #[serde(default, skip_serializing_if = "is_false")]
    pub revoked: bool,
    /// Free-form metadata the gateway / Sync Service may use; chime
    /// does not interpret these. Use it for things like
    /// `display_name`, `last_rotated_at`, …
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Value>,
}

#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_false(value: &bool) -> bool {
    !*value
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum PushRouteError {
    #[error("push_route id is missing or empty")]
    MissingRouteId,
    #[error("push_route id length must be 1..=64 chars, got {0}")]
    InvalidRouteIdLength(usize),
    #[error("push_route id contains illegal character `{0}`")]
    InvalidRouteIdCharacter(char),
    #[error("push_route is active but missing required field `{field}`")]
    ActiveRouteMissing { field: &'static str },
}

impl PushRoute {
    /// Construct an active route. Both `push_target_id` and
    /// `push_gateway_did` MUST be set when `revoked == false`.
    #[cfg(feature = "notify")]
    pub fn active(
        route: PushRouteId,
        push_target_id: PushTargetId,
        push_gateway_did: impl Into<String>,
    ) -> Self {
        Self {
            route,
            push_target_id: Some(push_target_id),
            push_gateway_did: Some(push_gateway_did.into()),
            encryption_key: None,
            capabilities: Vec::new(),
            revoked: false,
            metadata: None,
        }
    }

    /// Construct a revoked route record (`push_target_id` MAY be
    /// omitted; the Sync Service stops using whatever was previously
    /// recorded).
    pub fn revoked(route: PushRouteId) -> Self {
        Self {
            route,
            push_target_id: None,
            push_gateway_did: None,
            encryption_key: None,
            capabilities: Vec::new(),
            revoked: true,
            metadata: None,
        }
    }

    /// Validate active routes have the required fields.
    pub fn validate(&self) -> Result<(), PushRouteError> {
        if !self.revoked {
            if self.push_target_id.is_none() {
                return Err(PushRouteError::ActiveRouteMissing {
                    field: "push_target_id",
                });
            }
            if self.push_gateway_did.is_none() {
                return Err(PushRouteError::ActiveRouteMissing {
                    field: "push_gateway_did",
                });
            }
        }
        Ok(())
    }

    /// Whether the route advertises a given capability.
    pub fn supports(&self, capability: &PushRouteCapability) -> bool {
        self.capabilities.contains(capability)
    }
}

/// Validate the `route` id portion.
fn validate_push_route_id(value: &str) -> Result<(), PushRouteError> {
    if value.is_empty() {
        return Err(PushRouteError::MissingRouteId);
    }
    if !(1..=64).contains(&value.len()) {
        return Err(PushRouteError::InvalidRouteIdLength(value.len()));
    }
    if let Some(ch) = value
        .chars()
        .find(|c| !(c.is_ascii_alphanumeric() || matches!(c, '_' | '-')))
    {
        return Err(PushRouteError::InvalidRouteIdCharacter(ch));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_id_accepts_alphanumeric_and_separators() {
        PushRouteId::new("apns_main").unwrap();
        PushRouteId::new("fcm-voip").unwrap();
        PushRouteId::new("webpush_default").unwrap();
    }

    #[test]
    fn route_id_rejects_dot_or_colon_or_space() {
        assert!(matches!(
            PushRouteId::new("apns.main").unwrap_err(),
            PushRouteError::InvalidRouteIdCharacter('.')
        ));
        assert!(matches!(
            PushRouteId::new("apns:main").unwrap_err(),
            PushRouteError::InvalidRouteIdCharacter(':')
        ));
        assert!(matches!(
            PushRouteId::new("apns main").unwrap_err(),
            PushRouteError::InvalidRouteIdCharacter(' ')
        ));
    }

    #[test]
    fn route_id_rejects_empty() {
        assert!(matches!(
            PushRouteId::new("").unwrap_err(),
            PushRouteError::MissingRouteId
        ));
    }

    #[test]
    #[cfg(feature = "notify")]
    fn active_route_requires_target_id_and_gateway_did() {
        let pseudo = PushTargetId::new("cx:pseudonym:push:01HYZ8Z000000000000000").unwrap();
        let route = PushRoute::active(
            PushRouteId::new("apns_main").unwrap(),
            pseudo,
            "did:web:gateway.example",
        );
        route.validate().unwrap();

        let mut bad = route.clone();
        bad.push_target_id = None;
        let err = bad.validate().unwrap_err();
        assert!(matches!(
            err,
            PushRouteError::ActiveRouteMissing {
                field: "push_target_id"
            }
        ));

        let mut bad = route.clone();
        bad.push_gateway_did = None;
        let err = bad.validate().unwrap_err();
        assert!(matches!(
            err,
            PushRouteError::ActiveRouteMissing {
                field: "push_gateway_did"
            }
        ));
    }

    #[test]
    fn revoked_route_does_not_require_target_id() {
        let route = PushRoute::revoked(PushRouteId::new("apns_main").unwrap());
        route.validate().unwrap();
    }

    #[test]
    #[cfg(feature = "notify")]
    fn route_round_trips_through_json_with_capabilities() {
        let pseudo = PushTargetId::new("cx:pseudonym:push:01HYZ8Z000000000000000").unwrap();
        let mut route = PushRoute::active(
            PushRouteId::new("fcm_voip").unwrap(),
            pseudo,
            "did:web:gateway.example",
        );
        route
            .capabilities
            .push(PushRouteCapability::Voip);
        route
            .capabilities
            .push(PushRouteCapability::Custom("alarm".to_owned()));

        let json = serde_json::to_string(&route).unwrap();
        let loaded: PushRoute = serde_json::from_str(&json).unwrap();
        loaded.validate().unwrap();
        assert!(loaded.supports(&PushRouteCapability::Voip));
        assert!(loaded.supports(&PushRouteCapability::Custom("alarm".to_owned())));
    }

    #[test]
    fn route_rejects_unknown_fields() {
        let bad = serde_json::from_str::<PushRoute>(
            r#"{"route": "apns_main", "extra_unknown": true}"#,
        );
        assert!(bad.is_err());
    }
}
