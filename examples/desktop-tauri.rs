//! Tauri-style desktop client integration sample.
//!
//! Shows how a desktop host application (Tauri, Electron, native Cocoa
//! shell, Win32 Toast bridge, …) wires `chime` into its push surface:
//!
//! 1. Build a `PushRegisterDeviceRequestBody` for the platform push token the host shell has just
//!    received (here a WebPush endpoint URL, but the same call site shape works for FCM / APNs /
//!    OEM tokens).
//! 2. Decode an inbound `ak.edge.push.command.notify` payload that the local platform bridge has
//!    handed off, validate it against the blind-wakeup policy, and surface the result to the UI
//!    layer.
//!
//! The example does NOT perform any network I/O — it is deliberately
//! `--no-run`-friendly so `cargo check --examples` and
//! `cargo build --examples` stay fast in CI. The host application is
//! expected to own:
//!
//! - the actual reqwest / Tauri command bridge to the gateway,
//! - signature verification on inbound frames (see `SECURITY.md`),
//! - the platform-specific code that displays the resulting toast.
//!
//! Run with: `cargo run --example desktop-tauri --features notify`.

#[cfg(feature = "notify")]
mod inner {
    use chime::{
        GatewayBinding, PushDeviceConfig, PushGatewayType, PushNotifyEnvelopeExt,
        PushNotifyPolicyContext, PushNotifyRequestBody, PushPreferences,
        build_register_device_request,
    };

    /// Registers the desktop shell's WebPush endpoint with a Arkret push
    /// gateway. The host owns the actual HTTP call; `chime` only builds
    /// the validated request body.
    pub fn register_desktop_device() -> Result<(), Box<dyn std::error::Error>> {
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
            display_name: Some("Alice — Tauri Desktop"),
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

    /// Processes one inbound `ak.edge.push.command.notify` payload that the host
    /// shell's platform bridge has just received.
    pub fn process_inbound_notify(raw_payload: &str) -> Result<(), Box<dyn std::error::Error>> {
        // 1. Deserialise the wire payload into the typed request body. `deny_unknown_fields`
        //    rejects any forbidden top-level extras.
        let request: PushNotifyRequestBody = serde_json::from_str(raw_payload)?;

        // 2. Validate against the blind-wakeup privacy policy. Desktop shells never appear on the
        //    plaintext-visible service DID allowlist, so `blind_wakeup_only` is the right context.
        let policy = PushNotifyPolicyContext::blind_wakeup_only();
        request.assert_payload_safe(&policy, None)?;

        // 3. The payload is now safe to hand to the UI layer. The example just logs the wakeup kind
        //    so the file stays runnable without a real UI dependency.
        let kind = request
            .notification
            .wakeup_kind
            .as_ref()
            .map(|k| k.as_str().to_owned())
            .unwrap_or_else(|| "<missing>".to_owned());
        println!("[desktop-tauri] safe wakeup, kind={kind}");
        Ok(())
    }

    pub fn run() -> Result<(), Box<dyn std::error::Error>> {
        register_desktop_device()?;

        // Synthetic blind-wakeup payload, shaped like what floria's
        // notify route would emit. A real desktop bridge gets this
        // from APNs / WebPush / OEM provider after the host shell
        // decodes the platform-specific envelope.
        let raw_payload = r#"{
            "notification": {
                "wakeup_kind": "message",
                "push_target_id": "ak:pseudonym:push:abcdefghijklmnopqrstuv",
                "devices": [{
                    "device_id": "ak:device:01904100-0000-7000-8000-000000000010",
                    "push_key": "webpush:https://fcm.googleapis.com/wp/AAA-fake-endpoint-aaaaaaaa",
                    "app_id": "im.arkret.desktop"
                }]
            }
        }"#;
        process_inbound_notify(raw_payload)?;
        Ok(())
    }
}

#[cfg(feature = "notify")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    inner::run()
}

#[cfg(not(feature = "notify"))]
fn main() {
    eprintln!("example requires --features notify");
}
