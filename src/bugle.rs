//! Bugle-specific helpers for domestic Chinese Android push routes.
//!
//! Bugle routes Android registrations through domestic OEM providers
//! such as Huawei, Xiaomi, OPPO, vivo, HONOR, HarmonyOS, or a JPush
//! aggregate. The SDK still keeps provider-specific token acquisition
//! in the host application; this module only resolves the application
//! id that should be placed in chime's register-device wire body.

use crate::{PlatformAppIdResolver, PushPlatform, PushRegistrationError};

fn non_empty(value: Option<&str>) -> Option<&str> {
    value.and_then(|candidate| {
        let trimmed = candidate.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed)
        }
    })
}

/// Minimal app-id resolver for Bugle domestic-OEM registrations.
///
/// For Android, `domestic_app_id` wins because OEM provider consoles
/// often assign an identifier that differs from the global package id.
/// When it is absent, the resolver falls back to `app_id` so existing
/// FCM-only Android integrations can opt into Bugle incrementally.
/// Other platforms use `app_id` only.
#[derive(Clone, Copy, Debug, Default)]
pub struct BugleAppIdResolver;

impl PlatformAppIdResolver for BugleAppIdResolver {
    fn resolve_app_id(
        &self,
        platform: PushPlatform,
        app_id: Option<&str>,
        domestic_app_id: Option<&str>,
    ) -> Result<String, PushRegistrationError> {
        let resolved = match platform {
            PushPlatform::Android => non_empty(domestic_app_id).or_else(|| non_empty(app_id)),
            PushPlatform::Ios | PushPlatform::Web | PushPlatform::Desktop => non_empty(app_id),
        };

        resolved
            .map(str::to_owned)
            .ok_or(PushRegistrationError::MissingField("app_id"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PushErrorKind;

    #[test]
    fn bugle_android_prefers_domestic_app_id() {
        let resolver = BugleAppIdResolver;
        let resolved = resolver
            .resolve_app_id(
                PushPlatform::Android,
                Some("app.example.android"),
                Some("app.example.android.cn"),
            )
            .unwrap();

        assert_eq!(resolved, "app.example.android.cn");
    }

    #[test]
    fn bugle_android_falls_back_to_base_app_id() {
        let resolver = BugleAppIdResolver;
        let resolved = resolver
            .resolve_app_id(PushPlatform::Android, Some("app.example.android"), None)
            .unwrap();

        assert_eq!(resolved, "app.example.android");
    }

    #[test]
    fn bugle_non_android_requires_base_app_id() {
        let resolver = BugleAppIdResolver;
        let err = resolver
            .resolve_app_id(PushPlatform::Ios, None, Some("app.example.android.cn"))
            .unwrap_err();

        assert_eq!(err.kind(), PushErrorKind::MissingField);
    }
}
