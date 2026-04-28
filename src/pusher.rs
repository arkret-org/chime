//! Pusher registration and unregistration with a Matrix homeserver.
//!
//! Requires the `matrix` crate feature.

use matrix_sdk::Client;
use thiserror::Error;

use crate::PushPreferences;

/// Configuration for pusher registration that the host app must provide.
pub struct PusherConfig<'a> {
    /// The device push token (FCM registration token or APNs device token).
    pub token: &'a str,
    /// Platform identifier: `"android"` or `"ios"`.
    pub platform: &'a str,
    /// The base Android app ID (e.g. `"app.robrix.android"`).
    pub android_app_id: &'a str,
    /// The domestic Android app ID for Bugle (e.g. `"app.robrix.android.cn"`).
    pub domestic_android_app_id: &'a str,
    /// iOS app ID (e.g. `"app.robrix.ios"`).
    pub ios_app_id: &'a str,
    /// Display name for the pusher app.
    pub app_display_name: &'a str,
    /// Display name for the device.
    pub device_display_name: &'a str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PushPlatform {
    Android,
    Ios,
}

impl TryFrom<&str> for PushPlatform {
    type Error = PusherRegistrationError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "android" => Ok(Self::Android),
            "ios" => Ok(Self::Ios),
            other => Err(PusherRegistrationError::InvalidPlatform(other.to_owned())),
        }
    }
}

#[derive(Debug, Error)]
pub enum PusherRegistrationError {
    #[error("unsupported push platform: {0}")]
    InvalidPlatform(String),
    #[error(transparent)]
    Matrix(#[from] matrix_sdk::Error),
}

fn active_app_id<'a>(
    platform: PushPlatform,
    config: &'a PusherConfig<'a>,
    prefs: &'a PushPreferences,
) -> &'a str {
    match platform {
        PushPlatform::Ios => config.ios_app_id,
        PushPlatform::Android => {
            prefs.android_app_id(config.android_app_id, config.domestic_android_app_id)
        }
    }
}

fn app_ids_to_remove<'a>(
    platform: PushPlatform,
    config: &'a PusherConfig<'a>,
    prefs: &'a PushPreferences,
) -> Vec<&'a str> {
    match platform {
        PushPlatform::Ios => vec![config.ios_app_id],
        PushPlatform::Android => {
            let active =
                prefs.android_app_id(config.android_app_id, config.domestic_android_app_id);
            if config.android_app_id == config.domestic_android_app_id {
                vec![active]
            } else if active == config.android_app_id {
                vec![config.android_app_id, config.domestic_android_app_id]
            } else {
                vec![config.domestic_android_app_id, config.android_app_id]
            }
        }
    }
}

/// Register a pusher with the Matrix homeserver.
///
/// This tells the homeserver to forward push notifications to the gateway
/// specified in `prefs` whenever this device should receive a notification.
pub async fn register_pusher(
    client: &Client,
    config: &PusherConfig<'_>,
    prefs: &PushPreferences,
) -> Result<(), PusherRegistrationError> {
    use matrix_sdk::ruma::api::client::push::{PusherIds, PusherInit, PusherKind};
    use matrix_sdk::ruma::push::HttpPusherData;

    let platform = PushPlatform::try_from(config.platform)?;

    if !prefs.enabled {
        tracing::info!(
            platform = config.platform,
            "Push disabled; unregistering any existing pusher"
        );
        unregister_pusher(client, config, prefs).await?;
        return Ok(());
    }

    let app_id = active_app_id(platform, config, prefs);

    let pusher_ids = PusherIds::new(config.token.to_owned(), app_id.to_owned());
    let http_data = HttpPusherData::new(prefs.gateway_url.clone());
    let pusher_init = PusherInit {
        ids: pusher_ids,
        kind: PusherKind::Http(http_data),
        app_display_name: config.app_display_name.to_owned(),
        device_display_name: config.device_display_name.to_owned(),
        profile_tag: None,
        lang: "en".to_owned(),
    };

    client.pusher().set(pusher_init.into()).await?;
    tracing::info!(
        platform = config.platform,
        gateway = prefs.gateway_type.display_name(),
        "Pusher registered",
    );
    Ok(())
}

/// Unregister the pusher from the Matrix homeserver.
pub async fn unregister_pusher(
    client: &Client,
    config: &PusherConfig<'_>,
    prefs: &PushPreferences,
) -> Result<(), PusherRegistrationError> {
    use matrix_sdk::ruma::api::client::push::PusherIds;

    let platform = PushPlatform::try_from(config.platform)?;

    for app_id in app_ids_to_remove(platform, config, prefs) {
        let pusher_ids = PusherIds::new(config.token.to_owned(), app_id.to_owned());
        client.pusher().delete(pusher_ids).await?;
    }

    tracing::info!(platform = config.platform, "Pusher unregistered");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{PushGatewayType, PushPreferences};

    fn config<'a>(platform: &'a str) -> PusherConfig<'a> {
        PusherConfig {
            token: "token",
            platform,
            android_app_id: "app.example.android",
            domestic_android_app_id: "app.example.android.cn",
            ios_app_id: "app.example.ios",
            app_display_name: "App",
            device_display_name: "Device",
        }
    }

    #[test]
    fn rejects_unknown_platform() {
        let err = PushPlatform::try_from("web").unwrap_err();
        assert!(matches!(err, PusherRegistrationError::InvalidPlatform(value) if value == "web"));
    }

    #[test]
    fn unregister_android_removes_both_possible_app_ids() {
        let prefs = PushPreferences {
            enabled: true,
            gateway_type: PushGatewayType::Bugle,
            ..Default::default()
        };

        assert_eq!(
            app_ids_to_remove(PushPlatform::Android, &config("android"), &prefs),
            vec!["app.example.android.cn", "app.example.android"]
        );
    }

    #[test]
    fn unregister_ios_only_removes_ios_app_id() {
        let prefs = PushPreferences::default();
        assert_eq!(
            app_ids_to_remove(PushPlatform::Ios, &config("ios"), &prefs),
            vec!["app.example.ios"]
        );
    }
}
