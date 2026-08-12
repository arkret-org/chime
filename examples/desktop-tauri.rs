//! Tauri-style desktop client integration sample.
//!
//! Shows how a desktop host application (Tauri, Electron, native Cocoa
//! shell, Win32 Toast bridge, ...) wires `chime` into its push surface:
//! it builds a `PushRegisterDeviceRequestBody` for the platform push
//! token the host shell has just received (here a WebPush endpoint URL,
//! but the same call site shape works for FCM / APNs / OEM tokens).
//!
//! The example does NOT perform any network I/O -- it is deliberately
//! `--no-run`-friendly so `cargo check --examples` and
//! `cargo build --examples` stay fast in CI. The host application is
//! expected to own:
//!
//! - the actual reqwest / Tauri command bridge to the gateway,
//! - signature verification on inbound frames (see `SECURITY.md`),
//! - the platform-specific code that displays the resulting toast.
//!
//! Run with: `cargo run --example desktop-tauri`.

use chime::{
    GatewayBinding, PushDeviceConfig, PushGatewayType, PushPreferences,
    build_register_device_request,
};

/// Registers the desktop shell's WebPush endpoint with a Arkret push
/// gateway. The host owns the actual HTTP call; `chime` only builds
/// the validated request body.
fn register_desktop_device() -> Result<(), Box<dyn std::error::Error>> {
    // Tauri-style: the host shell has subscribed to a browser
    // WebPush endpoint and now needs to hand the resulting token
    // to Arkret.
    let config = PushDeviceConfig {
        principal_id: Some("did:web:alice.example"),
        device_id: "did:web:alice.example#tauri-desktop",
        // In a real Tauri integration this is the
        // `PushSubscription.endpoint` returned by the embedded
        // browser engine.
        push_key: Some("webpush:https://fcm.googleapis.com/wp/AAA-fake-endpoint-aaaaaaaa"),
        platform: Some("desktop"),
        app_id: Some("im.arkret.desktop"),
        domestic_app_id: None,
        registration_id: None,
        display_name: Some("Alice -- Tauri Desktop"),
        idempotency_key: Some("register-tauri-desktop-v1"),
        request_id: None,
        proof: None,
    };

    let binding = GatewayBinding::new(
        PushGatewayType::Standard,
        "https://push.example.com/_arkret/edge/push/notify",
    );

    let prefs = PushPreferences {
        enabled: true,
        // Tauri desktops typically only emit HTTPS endpoints, so
        // the loopback opt-in stays off.
        ..Default::default()
    };

    let request = build_register_device_request(&config, &binding, &prefs)?;
    println!(
        "[desktop-tauri] built register-device for {}",
        request.device_id
    );
    // The host shell hands `request` to its outbound HTTP layer
    // (e.g. Tauri command + reqwest). The chime contract ends here.
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    register_desktop_device()
}
