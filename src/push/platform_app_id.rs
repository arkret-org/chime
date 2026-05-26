//! Platform → `app_id` resolution for push registration.
//!
//! Round 2 (post-improve) — extracted as a typed trait so the bugle /
//! domestic-Android resolver can plug in later without touching the
//! `registration` module. The default implementation only handles the
//! cross-platform `Android` / `Ios` mappings; `Web` / `Desktop` fall
//! back to `app_id` and other platforms error out so callers see the
//! missing branch instead of silently sending the wrong identifier.
//!
//! TODO(round-3): build the `chime::bugle` module that supplies a
//! `BugleAppIdResolver` selecting `domestic_app_id` for the curated
//! Chinese-OEM provider matrix (Huawei / Xiaomi / OPPO / Vivo /
//! Meizu / ColorOS). Until then, callers wanting bugle semantics MUST
//! implement [`PlatformAppIdResolver`] themselves.

use super::errors::PushRegistrationError;
use super::wire::PushPlatform;

/// Resolver contract turning a `(platform, app_id, domestic_app_id)`
/// triple into the canonical `app_id` string the push gateway expects
/// in the wire envelope.
///
/// Implementations MUST be deterministic — the same inputs always
/// produce the same `Result`, with no I/O. They MAY return
/// `PushRegistrationError::MissingField("app_id")` when neither
/// candidate satisfies the platform's requirements.
pub trait PlatformAppIdResolver {
    /// Resolve the wire-form `app_id` for `platform`.
    ///
    /// - `app_id` is the canonical store / bundle / package identifier
    ///   the host app already advertises to the gateway.
    /// - `domestic_app_id` is the optional China-specific identifier
    ///   used when routing through Bugle's Huawei / Xiaomi / OPPO etc.
    ///   provider matrix.
    ///
    /// Returns the resolved id on success or a typed
    /// [`PushRegistrationError`] when the inputs don't satisfy the
    /// platform's resolution rules.
    fn resolve_app_id(
        &self,
        platform: PushPlatform,
        app_id: Option<&str>,
        domestic_app_id: Option<&str>,
    ) -> Result<String, PushRegistrationError>;
}

/// Default `PlatformAppIdResolver` implementation.
///
/// - `Android` / `Ios` → require `app_id`; reject `domestic_app_id`
///   alone because routing through Bugle requires the round-3 bugle
///   resolver (see TODO at the top of the module).
/// - `Web` / `Desktop` → fall back to `app_id` when present; treat the
///   field as required (the gateway needs *some* identifier even for
///   webpush so it can scope subscriptions per origin).
///
/// Returns `PushRegistrationError::MissingField("app_id")` whenever no
/// usable identifier is available.
#[derive(Clone, Copy, Debug, Default)]
pub struct DefaultPlatformAppIdResolver;

impl PlatformAppIdResolver for DefaultPlatformAppIdResolver {
    fn resolve_app_id(
        &self,
        platform: PushPlatform,
        app_id: Option<&str>,
        _domestic_app_id: Option<&str>,
    ) -> Result<String, PushRegistrationError> {
        match platform {
            PushPlatform::Android | PushPlatform::Ios => app_id
                .filter(|value| !value.trim().is_empty())
                .map(str::to_owned)
                .ok_or(PushRegistrationError::MissingField("app_id")),
            PushPlatform::Web | PushPlatform::Desktop => app_id
                .filter(|value| !value.trim().is_empty())
                .map(str::to_owned)
                .ok_or(PushRegistrationError::MissingField("app_id")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::push::errors::PushErrorKind;

    #[test]
    fn default_resolver_returns_app_id_for_android_and_ios() {
        let r = DefaultPlatformAppIdResolver;
        assert_eq!(
            r.resolve_app_id(PushPlatform::Android, Some("com.example.app"), None)
                .unwrap(),
            "com.example.app",
        );
        assert_eq!(
            r.resolve_app_id(PushPlatform::Ios, Some("com.example.ios"), None)
                .unwrap(),
            "com.example.ios",
        );
    }

    #[test]
    fn default_resolver_returns_app_id_for_web_and_desktop() {
        let r = DefaultPlatformAppIdResolver;
        assert_eq!(
            r.resolve_app_id(PushPlatform::Web, Some("https://app.example"), None)
                .unwrap(),
            "https://app.example",
        );
        assert_eq!(
            r.resolve_app_id(PushPlatform::Desktop, Some("desktop.example"), None)
                .unwrap(),
            "desktop.example",
        );
    }

    #[test]
    fn default_resolver_rejects_missing_app_id() {
        let r = DefaultPlatformAppIdResolver;
        for platform in [
            PushPlatform::Android,
            PushPlatform::Ios,
            PushPlatform::Web,
            PushPlatform::Desktop,
        ] {
            let err = r.resolve_app_id(platform, None, Some("bugle.id")).unwrap_err();
            assert_eq!(err.kind(), PushErrorKind::MissingField);
        }
    }

    #[test]
    fn default_resolver_rejects_whitespace_app_id() {
        let r = DefaultPlatformAppIdResolver;
        let err = r
            .resolve_app_id(PushPlatform::Android, Some("   "), None)
            .unwrap_err();
        assert_eq!(err.kind(), PushErrorKind::MissingField);
    }
}
