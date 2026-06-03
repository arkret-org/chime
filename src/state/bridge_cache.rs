//! Local cache of `bridge/describe` contract digests for drift detection.
//!
//! The cache is advisory — `evaluate` returns a verdict the caller can use
//! to emit warnings, force a re-fetch, or invalidate dependent state. The SDK
//! itself never blocks requests on a digest mismatch.

use std::fmt::Write as _;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::PushBridgeDescribeResponse;

/// A.5 #3 — error surface for `BridgeContractCache` construction / drift
/// evaluation.
///
/// Previously `BridgeContractCache::from_response` swallowed serialise
/// failures via `unwrap_or_default()`, which silently produced a cache
/// entry whose digest was the SHA-256 of an empty byte slice. That is
/// fail-open: a subsequent `evaluate` of the SAME response would still
/// flip to `Drifted` (because the fresh digest is now over real bytes),
/// but a `from_response` taken on the drift side at the wrong moment
/// could compare `digest("")` against itself and report `Unchanged` on
/// totally different contracts. The current contract is fail-closed —
/// every digest computation MUST succeed, and the only way the
/// underlying `serde_json::to_vec` can fail in practice is a struct
/// containing a non-string map key or a `f64` NaN, neither of which the
/// `PushBridgeDescribeResponse` schema allows. Surfacing the error
/// nonetheless guards against future schema additions.
#[derive(Debug, Error)]
pub enum CacheError {
    /// Serialising the bridge/describe response to canonical JSON failed.
    /// The digest cannot be computed; the cache entry MUST NOT be
    /// constructed.
    #[error("bridge/describe response failed to serialise for cache digest: {0}")]
    Serialize(#[from] serde_json::Error),
}

/// Locally cached fingerprint of the most recent `bridge/describe` response.
///
/// Comparing a freshly fetched response against the cache detects contract
/// drift such as renamed fields, removed providers, or rotated rate-limit
/// scopes — situations where the gateway's wire shape moved without the SDK
/// being upgraded.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct BridgeContractCache {
    /// Hex-encoded SHA-256 of the canonical JSON of the cached response.
    pub digest: String,
    /// Contract identifier from the cached response (e.g. `"ck.push.bridge.v1"`).
    pub contract: String,
    /// Version string from the cached response.
    pub version: String,
    /// RFC 3339 timestamp of when this cache entry was first observed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_at: Option<String>,
}

impl BridgeContractCache {
    /// Compute a fresh cache entry from a bridge describe response.
    ///
    /// A.5 #3 — fail-closed: when the underlying serialisation fails the
    /// constructor returns `Err(CacheError::Serialize)` rather than
    /// silently building a cache entry whose digest is over an empty
    /// byte slice.
    pub fn from_response(
        response: &PushBridgeDescribeResponse,
        observed_at: Option<&str>,
    ) -> Result<Self, CacheError> {
        Ok(Self {
            digest: compute_digest(response)?,
            contract: response.contract.clone(),
            version: response.version.clone(),
            observed_at: observed_at.map(str::to_owned),
        })
    }

    /// Compare a fresh response against this cache and return a drift verdict.
    ///
    /// A.5 #3 — also fail-closed: a serialisation failure of the fresh
    /// response prevents an honest comparison, so the call surfaces the
    /// error rather than reporting `Unchanged` or `Drifted` based on an
    /// empty-input digest.
    pub fn evaluate(
        &self,
        fresh: &PushBridgeDescribeResponse,
    ) -> Result<BridgeContractDriftVerdict, CacheError> {
        let fresh_digest = compute_digest(fresh)?;
        Ok(if self.digest == fresh_digest {
            BridgeContractDriftVerdict::Unchanged
        } else {
            BridgeContractDriftVerdict::Drifted {
                cached_digest: self.digest.clone(),
                fresh_digest,
                cached_contract: self.contract.clone(),
                fresh_contract: fresh.contract.clone(),
                cached_version: self.version.clone(),
                fresh_version: fresh.version.clone(),
            }
        })
    }
}

/// Outcome of comparing a cached bridge contract to a fresh fetch.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum BridgeContractDriftVerdict {
    /// The cached digest matches the fresh response — the contract is stable.
    Unchanged,
    /// The fresh response differs from the cached digest.
    ///
    /// Carries both digests plus contract + version metadata so callers can
    /// decide whether the change is a SemVer-compatible additive update or a
    /// breaking drift that warrants alerting / fail-closed handling.
    Drifted {
        cached_digest: String,
        fresh_digest: String,
        cached_contract: String,
        fresh_contract: String,
        cached_version: String,
        fresh_version: String,
    },
}

impl BridgeContractDriftVerdict {
    /// Whether this verdict represents a drift (`true`) or a stable cache (`false`).
    pub fn is_drift(&self) -> bool {
        matches!(self, Self::Drifted { .. })
    }

    /// Whether the contract identifier changed across the cache boundary
    /// (i.e. the contract string no longer matches the expected
    /// `ck.push.bridge.v1`). Such a contract change is always a strong signal
    /// that downstream state should be invalidated.
    pub fn contract_changed(&self) -> bool {
        match self {
            Self::Unchanged => false,
            Self::Drifted {
                cached_contract,
                fresh_contract,
                ..
            } => cached_contract != fresh_contract,
        }
    }
}

fn compute_digest(response: &PushBridgeDescribeResponse) -> Result<String, CacheError> {
    let json = serde_json::to_vec(response)?;
    let digest = Sha256::digest(&json);
    let mut output = String::with_capacity(digest.len() * 2);
    for byte in digest {
        let _ = write!(output, "{byte:02x}");
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn baseline_response() -> PushBridgeDescribeResponse {
        PushBridgeDescribeResponse {
            contract: "ck.push.bridge.v1".to_owned(),
            version: "1.0.0".to_owned(),
            api_base_path: "/_cokret/edge/push".to_owned(),
            ..Default::default()
        }
    }

    #[test]
    fn digest_is_stable_for_identical_responses() {
        let response = baseline_response();
        let a = compute_digest(&response).unwrap();
        let b = compute_digest(&response).unwrap();
        assert_eq!(a, b);
        assert_eq!(a.len(), 64);
    }

    #[test]
    fn cache_evaluates_unchanged_when_digest_matches() {
        let response = baseline_response();
        let cache =
            BridgeContractCache::from_response(&response, Some("2026-05-06T00:00:00Z")).unwrap();
        assert_eq!(
            cache.evaluate(&response).unwrap(),
            BridgeContractDriftVerdict::Unchanged
        );
        assert!(!cache.evaluate(&response).unwrap().is_drift());
    }

    #[test]
    fn cache_detects_version_only_drift() {
        let cache = BridgeContractCache::from_response(&baseline_response(), None).unwrap();
        let mut fresh = baseline_response();
        fresh.version = "1.1.0".to_owned();

        let verdict = cache.evaluate(&fresh).unwrap();
        assert!(verdict.is_drift());
        assert!(
            !verdict.contract_changed(),
            "version-only drift should not flip contract"
        );

        match verdict {
            BridgeContractDriftVerdict::Drifted {
                cached_version,
                fresh_version,
                ..
            } => {
                assert_eq!(cached_version, "1.0.0");
                assert_eq!(fresh_version, "1.1.0");
            }
            other => panic!("expected drift, got {other:?}"),
        }
    }

    #[test]
    fn cache_detects_contract_drift() {
        let cache = BridgeContractCache::from_response(&baseline_response(), None).unwrap();
        let mut fresh = baseline_response();
        fresh.contract = "ck.push.bridge.unknown-drift-test".to_owned();

        let verdict = cache.evaluate(&fresh).unwrap();
        assert!(verdict.is_drift());
        assert!(verdict.contract_changed());
    }

    #[test]
    fn cache_round_trips_through_json() {
        let cache =
            BridgeContractCache::from_response(&baseline_response(), Some("2026-05-06T00:00:00Z"))
                .unwrap();
        let json = serde_json::to_string(&cache).unwrap();
        let loaded: BridgeContractCache = serde_json::from_str(&json).unwrap();
        assert_eq!(loaded, cache);
    }
}
