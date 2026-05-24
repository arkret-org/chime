//! Actor-private `cx.device.push_route` state event wire model.
//!
//! Spec: `contrix-spec/spec/v1/zh/crypto-media/device-lifecycle.md` §5a.2
//! and the registry entry for `cx.device.push_route` introduced in
//! commit 0a5ab85 (2026-05-19), which made the cell_subject a composite
//! `(recipient_service_did, principal_id, device_id, push_route)`. The
//! prior wire shape only carried `(principal, device, route)`; the
//! `recipient_service_did` discriminator scopes the registration to the
//! current Principal Server's service DID and is part of the cell key,
//! so a device's push route on Principal Server A is invisible to
//! Principal Server B even when the same DID, device, and route
//! identifiers are reused.
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

/// Service DID of a recipient Principal Server, used as the first
/// component of the `cx.device.push_route` composite cell_subject
/// `(recipient_service_did, principal_id, device_id, push_route)`.
///
/// This is a non-empty `String` newtype rather than a free-form
/// `impl Into<String>` parameter so the type system rules out the
/// "active route with no recipient" footgun that motivated T4.1.
/// Callers that genuinely cannot supply a service DID at construction
/// time (e.g. cold-start fixtures before service discovery has run)
/// can use [`PushRoute::stub_unauthenticated`] to mint a placeholder
/// route that is explicit about being unwriteable until rebound.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct ServiceDid(String);

impl ServiceDid {
    /// Construct a service DID. Empty / whitespace-only inputs are
    /// rejected up front so an "active" route can never end up with a
    /// blank recipient_service_did even when the caller forgot to
    /// thread one through.
    pub fn new(value: impl Into<String>) -> Result<Self, PushRouteError> {
        let value = value.into();
        if value.trim().is_empty() {
            return Err(PushRouteError::EmptyServiceDid);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Move the inner String out. Used by serde and by callers that
    /// need the raw form to pass to non-typed APIs (e.g. existing
    /// `Option<String>` storage downstream of chime).
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl<'de> Deserialize<'de> for ServiceDid {
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
/// Stability: `1.0`-stable. Adding capability tags is additive; renaming
/// or removing fields requires a major SemVer bump.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct PushRoute {
    /// Service DID of the recipient Principal Server this binding is
    /// scoped to. Part of the composite cell_subject; MUST NOT leak to
    /// other Principal Servers even when the same actor uses them.
    /// Spec 0a5ab85.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recipient_service_did: Option<String>,
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
    /// T4.1: active routes MUST carry a non-empty `recipient_service_did`
    /// because it is the first leg of the cell_subject quadruple.
    /// `ActiveRouteMissing { field: "recipient_service_did" }` covers
    /// the omission case; this variant covers the
    /// "explicitly-supplied-but-blank" case so we never silently accept
    /// a service DID of `""` from JSON or from a buggy caller.
    #[error("recipient_service_did must not be empty")]
    EmptyServiceDid,
    /// T4.1: the cell_subject contract pins
    /// `(recipient_service_did, principal_id, device_id, push_route)`,
    /// so `revoke()` MUST preserve those four components. If a caller
    /// hands us a route with no `recipient_service_did` and asks us to
    /// revoke it, we can't honour that contract without inventing one;
    /// surfacing this variant makes the precondition explicit instead
    /// of silently writing a revoke into the wrong cell.
    #[error("cannot revoke a route that has no recipient_service_did")]
    RevokeMissingServiceDid,
}

/// Alias kept for the wording used in T4.1's task description so
/// downstream call sites and docs can reference
/// `PushRouteValidationError::MissingField` even though the concrete
/// error type stays `PushRouteError`. The two names refer to the same
/// type; the alias documents the intent ("this error came out of
/// `validate()`") without forking the type hierarchy.
pub type PushRouteValidationError = PushRouteError;

impl PushRoute {
    /// Construct an active route scoped to a recipient Principal
    /// Server.
    ///
    /// T4.1 (2026-05-20): `recipient_service_did` is now mandatory and
    /// typed as [`ServiceDid`]. The previous signature
    /// `active(route, push_target_id, push_gateway_did)` allowed
    /// construction of active routes with `recipient_service_did:
    /// None`, which violated the `cx.device.push_route` cell_subject
    /// contract `(recipient_service_did, principal_id, device_id,
    /// push_route)`. Callers that genuinely need a placeholder before
    /// service discovery has run should use
    /// [`PushRoute::stub_unauthenticated`].
    #[cfg(feature = "notify")]
    pub fn active(
        recipient_service_did: ServiceDid,
        route: PushRouteId,
        push_target_id: PushTargetId,
        push_gateway_did: impl Into<String>,
    ) -> Self {
        Self {
            recipient_service_did: Some(recipient_service_did.into_inner()),
            route,
            push_target_id: Some(push_target_id),
            push_gateway_did: Some(push_gateway_did.into()),
            encryption_key: None,
            capabilities: Vec::new(),
            revoked: false,
            metadata: None,
        }
    }

    /// Backwards-compatibility shim for callers that still spell out
    /// `active_with_recipient`. Identical to [`PushRoute::active`]
    /// after T4.1 — the recipient_service_did is required by both
    /// constructors. Will be removed in the next breaking release.
    #[cfg(feature = "notify")]
    #[deprecated(
        since = "0.1.0",
        note = "`active` now requires `recipient_service_did`; call `PushRoute::active` directly"
    )]
    pub fn active_with_recipient(
        recipient_service_did: ServiceDid,
        route: PushRouteId,
        push_target_id: PushTargetId,
        push_gateway_did: impl Into<String>,
    ) -> Self {
        Self::active(
            recipient_service_did,
            route,
            push_target_id,
            push_gateway_did,
        )
    }

    /// Mint a placeholder route that is not yet bound to a recipient
    /// Principal Server. Useful for cold-start fixtures and unit
    /// tests that assert how the SDK reacts to an unauthenticated /
    /// pre-discovery route. The returned value is intentionally
    /// invalid: [`PushRoute::validate`] will reject it with
    /// `ActiveRouteMissing { field: "recipient_service_did" }`, which
    /// is the entire point — callers can pin the negative path
    /// without hand-rolling a malformed struct literal.
    #[cfg(feature = "notify")]
    pub fn stub_unauthenticated(
        route: PushRouteId,
        push_target_id: PushTargetId,
        push_gateway_did: impl Into<String>,
    ) -> Self {
        Self {
            recipient_service_did: None,
            route,
            push_target_id: Some(push_target_id),
            push_gateway_did: Some(push_gateway_did.into()),
            encryption_key: None,
            capabilities: Vec::new(),
            revoked: false,
            metadata: None,
        }
    }

    /// Construct a revoked route record for a known
    /// `(recipient_service_did, route)` pair.
    ///
    /// T4.1: the cell_subject quadruple
    /// `(recipient_service_did, principal_id, device_id, push_route)`
    /// MUST stay the same across active and revoked writes, otherwise
    /// the revoke lands in a different cell than the activation and
    /// the Sync Service keeps using the retired pseudonym. The other
    /// two legs (`principal_id`, `device_id`) are out of scope for
    /// this struct, but we own the first and the last leg, so we
    /// require both here.
    pub fn revoked(recipient_service_did: ServiceDid, route: PushRouteId) -> Self {
        Self {
            recipient_service_did: Some(recipient_service_did.into_inner()),
            route,
            push_target_id: None,
            push_gateway_did: None,
            encryption_key: None,
            capabilities: Vec::new(),
            revoked: true,
            metadata: None,
        }
    }

    /// Transform an active route into its revoked counterpart while
    /// preserving the `(recipient_service_did, push_route)` portion of
    /// the cell_subject. The remaining `(principal_id, device_id)` legs
    /// are not stored on this struct, so the caller is responsible for
    /// keeping them stable across the active → revoked transition.
    ///
    /// T4.1: returns [`PushRouteError::RevokeMissingServiceDid`] if
    /// the input route somehow has no recipient_service_did (which
    /// can only happen via [`PushRoute::stub_unauthenticated`] or a
    /// deserialized legacy record), so a buggy revoke can never land
    /// in the wrong cell.
    pub fn revoke(mut self) -> Result<Self, PushRouteError> {
        if self
            .recipient_service_did
            .as_deref()
            .map(str::trim)
            .map(str::is_empty)
            .unwrap_or(true)
        {
            return Err(PushRouteError::RevokeMissingServiceDid);
        }
        self.revoked = true;
        // The retired pseudonym MUST stop being honoured by the Sync
        // Service. We clear it here so a downstream caller cannot
        // accidentally re-emit it on the active channel.
        #[cfg(feature = "notify")]
        {
            self.push_target_id = None;
        }
        #[cfg(not(feature = "notify"))]
        {
            self.push_target_id = None;
        }
        self.push_gateway_did = None;
        self.encryption_key = None;
        Ok(self)
    }

    /// Validate the wire shape.
    ///
    /// T4.1: active routes MUST carry all three of
    /// `recipient_service_did` (non-empty), `push_target_id`, and
    /// `push_gateway_did`. Revoked routes only require
    /// `recipient_service_did` so the revocation lands in the same
    /// cell as the activation.
    pub fn validate(&self) -> Result<(), PushRouteValidationError> {
        let service_did_present = match self.recipient_service_did.as_deref() {
            None => false,
            Some(value) if value.trim().is_empty() => {
                return Err(PushRouteError::EmptyServiceDid);
            }
            Some(_) => true,
        };

        if !self.revoked {
            if !service_did_present {
                return Err(PushRouteError::ActiveRouteMissing {
                    field: "recipient_service_did",
                });
            }
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
        } else if !service_did_present {
            // Revoked record without a recipient_service_did would
            // land in the wrong cell — reject it for the same reason
            // active records do.
            return Err(PushRouteError::ActiveRouteMissing {
                field: "recipient_service_did",
            });
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
    fn active_route_requires_service_did_target_id_and_gateway_did() {
        let pseudo = PushTargetId::new("cx:pseudonym:push:01HYZ8Z000000000000000").unwrap();
        let service_did = ServiceDid::new("did:web:principal.example").unwrap();
        let route = PushRoute::active(
            service_did,
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

        let mut bad = route.clone();
        bad.recipient_service_did = None;
        let err = bad.validate().unwrap_err();
        assert!(matches!(
            err,
            PushRouteError::ActiveRouteMissing {
                field: "recipient_service_did"
            }
        ));
    }

    #[test]
    #[cfg(feature = "notify")]
    fn stub_unauthenticated_fails_validation_with_missing_service_did() {
        // T4.1 negative test: the stub helper exists specifically so
        // tests can assert that an unbound route can't escape
        // `validate()`.
        let pseudo = PushTargetId::new("cx:pseudonym:push:01HYZ8Z000000000000000").unwrap();
        let route = PushRoute::stub_unauthenticated(
            PushRouteId::new("apns_main").unwrap(),
            pseudo,
            "did:web:gateway.example",
        );
        let err = route.validate().unwrap_err();
        assert!(matches!(
            err,
            PushRouteError::ActiveRouteMissing {
                field: "recipient_service_did"
            }
        ));
    }

    #[test]
    fn revoked_route_still_requires_service_did() {
        let route = PushRoute::revoked(
            ServiceDid::new("did:web:principal.example").unwrap(),
            PushRouteId::new("apns_main").unwrap(),
        );
        route.validate().unwrap();
    }

    #[test]
    fn revoked_route_with_blank_service_did_is_rejected() {
        // Round-trip path: a legacy persisted record with an empty
        // recipient_service_did must not pass validation, otherwise a
        // downstream caller could write the revoke into a default
        // ("") cell.
        let json = r#"{"recipient_service_did": "", "route": "apns_main", "revoked": true}"#;
        let route: PushRoute = serde_json::from_str(json).unwrap();
        let err = route.validate().unwrap_err();
        assert!(matches!(err, PushRouteError::EmptyServiceDid));
    }

    #[test]
    fn empty_service_did_is_rejected_at_newtype() {
        assert!(matches!(
            ServiceDid::new("").unwrap_err(),
            PushRouteError::EmptyServiceDid
        ));
        assert!(matches!(
            ServiceDid::new("   ").unwrap_err(),
            PushRouteError::EmptyServiceDid
        ));
    }

    #[test]
    #[cfg(feature = "notify")]
    fn revoke_helper_preserves_cell_subject_identity() {
        let pseudo = PushTargetId::new("cx:pseudonym:push:01HYZ8Z000000000000000").unwrap();
        let service_did = ServiceDid::new("did:web:principal.example").unwrap();
        let route_id = PushRouteId::new("apns_main").unwrap();
        let active = PushRoute::active(
            service_did.clone(),
            route_id.clone(),
            pseudo,
            "did:web:gateway.example",
        );

        let revoked = active.clone().revoke().unwrap();
        // (recipient_service_did, push_route) leg of the cell_subject
        // must be byte-identical between active and revoked records.
        assert_eq!(revoked.recipient_service_did, active.recipient_service_did);
        assert_eq!(revoked.route, active.route);
        assert!(revoked.revoked);
        assert!(revoked.push_target_id.is_none());
        assert!(revoked.push_gateway_did.is_none());
        revoked.validate().unwrap();
    }

    #[test]
    #[cfg(feature = "notify")]
    fn revoke_helper_refuses_unauthenticated_stub() {
        // The cell_subject preservation guarantee would be a lie if
        // we let a stub revoke itself into the default ("") cell.
        let pseudo = PushTargetId::new("cx:pseudonym:push:01HYZ8Z000000000000000").unwrap();
        let stub = PushRoute::stub_unauthenticated(
            PushRouteId::new("apns_main").unwrap(),
            pseudo,
            "did:web:gateway.example",
        );
        let err = stub.revoke().unwrap_err();
        assert!(matches!(err, PushRouteError::RevokeMissingServiceDid));
    }

    #[test]
    #[cfg(feature = "notify")]
    fn route_round_trips_through_json_with_capabilities() {
        let pseudo = PushTargetId::new("cx:pseudonym:push:01HYZ8Z000000000000000").unwrap();
        let service_did = ServiceDid::new("did:web:principal.example").unwrap();
        let mut route = PushRoute::active(
            service_did,
            PushRouteId::new("fcm_voip").unwrap(),
            pseudo,
            "did:web:gateway.example",
        );
        route.capabilities.push(PushRouteCapability::Voip);
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
        let bad =
            serde_json::from_str::<PushRoute>(r#"{"route": "apns_main", "extra_unknown": true}"#);
        assert!(bad.is_err());
    }
}
