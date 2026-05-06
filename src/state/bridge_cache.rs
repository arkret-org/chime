//! Local cache of `bridge/describe` contract digests for drift detection.
//!
//! The cache is advisory — `evaluate` returns a verdict the caller can use
//! to emit warnings, force a re-fetch, or invalidate dependent state. The SDK
//! itself never blocks requests on a digest mismatch.

use std::fmt::Write as _;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::PushBridgeDescribeResponse;

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
    /// Contract identifier from the cached response (e.g. `"cx.push.bridge.v1"`).
    pub contract: String,
    /// Version string from the cached response.
    pub version: String,
    /// RFC 3339 timestamp of when this cache entry was first observed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_at: Option<String>,
}

impl BridgeContractCache {
    /// Compute a fresh cache entry from a bridge describe response.
    pub fn from_response(response: &PushBridgeDescribeResponse, observed_at: Option<&str>) -> Self {
        Self {
            digest: compute_digest(response),
            contract: response.contract.clone(),
            version: response.version.clone(),
            observed_at: observed_at.map(str::to_owned),
        }
    }

    /// Compare a fresh response against this cache and return a drift verdict.
    pub fn evaluate(&self, fresh: &PushBridgeDescribeResponse) -> BridgeContractDriftVerdict {
        let fresh_digest = compute_digest(fresh);
        if self.digest == fresh_digest {
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
        }
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
    /// (e.g. `cx.push.bridge.v1` → `cx.push.bridge.v2`). Major-version drift
    /// is always a strong signal that downstream state should be invalidated.
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

fn compute_digest(response: &PushBridgeDescribeResponse) -> String {
    let json = serde_json::to_vec(response).unwrap_or_default();
    let digest = Sha256::digest(&json);
    let mut output = String::with_capacity(digest.len() * 2);
    for byte in digest {
        let _ = write!(output, "{byte:02x}");
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    fn baseline_response() -> PushBridgeDescribeResponse {
        PushBridgeDescribeResponse {
            contract: "cx.push.bridge.v1".to_owned(),
            version: "1.0.0".to_owned(),
            api_base_path: "/api/v1".to_owned(),
            ..Default::default()
        }
    }

    #[test]
    fn digest_is_stable_for_identical_responses() {
        let response = baseline_response();
        let a = compute_digest(&response);
        let b = compute_digest(&response);
        assert_eq!(a, b);
        assert_eq!(a.len(), 64);
    }

    #[test]
    fn cache_evaluates_unchanged_when_digest_matches() {
        let response = baseline_response();
        let cache = BridgeContractCache::from_response(&response, Some("2026-05-06T00:00:00Z"));
        assert_eq!(
            cache.evaluate(&response),
            BridgeContractDriftVerdict::Unchanged
        );
        assert!(!cache.evaluate(&response).is_drift());
    }

    #[test]
    fn cache_detects_version_only_drift() {
        let cache = BridgeContractCache::from_response(&baseline_response(), None);
        let mut fresh = baseline_response();
        fresh.version = "1.1.0".to_owned();

        let verdict = cache.evaluate(&fresh);
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
        let cache = BridgeContractCache::from_response(&baseline_response(), None);
        let mut fresh = baseline_response();
        fresh.contract = "cx.push.bridge.v2".to_owned();

        let verdict = cache.evaluate(&fresh);
        assert!(verdict.is_drift());
        assert!(verdict.contract_changed());
    }

    #[test]
    fn cache_round_trips_through_json() {
        let cache =
            BridgeContractCache::from_response(&baseline_response(), Some("2026-05-06T00:00:00Z"));
        let json = serde_json::to_string(&cache).unwrap();
        let loaded: BridgeContractCache = serde_json::from_str(&json).unwrap();
        assert_eq!(loaded, cache);
    }
}
