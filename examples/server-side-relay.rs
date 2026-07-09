//! Server-side push relay sample.
//!
//! Models the slice of code a backend service (inkson, an SRE-owned
//! fan-out proxy, an on-prem connector) runs when it receives a
//! `ck.edge.push.command.notify` frame from floria and wants to forward it onto an
//! internal queue (Kafka topic, Redis stream, MQ exchange, …) for
//! per-device delivery.
//!
//! Responsibilities demonstrated here:
//!
//! 1. Decode the inbound frame into `ChimePushNotifyEnvelope`.
//! 2. Run `assert_payload_safe` in `blind_wakeup_only` mode — relays NEVER assume plaintext
//!    visibility.
//! 3. Track replay nonces with `NonceTracker` so a duplicated frame cannot be re-fanned out. The
//!    relay's nonce window is decoupled from any downstream device's window (see `SECURITY.md`). In
//!    production, persist these nonces in a shared store; the example's in-memory tracker is
//!    process-local only.
//! 4. Hand the validated frame to a stand-in "queue" function. In production this is the host
//!    application's broker client; the example just prints to stdout to stay dependency-free.
//!
//! Run with: `cargo run --example server-side-relay --features notify`.

#[cfg(feature = "notify")]
mod inner {
    use std::time::Duration;

    use chime::{ChimePushNotifyEnvelope, NonceTracker, PushNotifyPolicyContext};

    /// Stand-in for the host application's internal queue (Kafka,
    /// NATS, …). Real implementations push the validated frame as the
    /// payload of the per-device topic.
    fn enqueue_for_fanout(frame: &ChimePushNotifyEnvelope) {
        let target = frame
            .notification
            .push_target_id
            .as_ref()
            .map(|t| t.as_str())
            .unwrap_or("<missing>");
        println!("[relay] enqueued frame for push_target_id={target}");
    }

    pub fn run() -> Result<(), Box<dyn std::error::Error>> {
        // 5-minute replay window — matches the recommended inbound
        // value from `SECURITY.md`. The relay tracks nonces keyed by
        // the upstream (origin) service so a single misbehaving floria
        // shard does not poison other origins' windows. Production
        // relays should back this with Redis or another persistent
        // shared store before accepting traffic across restarts or
        // multiple workers.
        let mut nonces = NonceTracker::new(Duration::from_secs(5 * 60));

        let policy = PushNotifyPolicyContext::blind_wakeup_only();

        // Two synthetic inbound frames sharing the same nonce — the
        // second one MUST be rejected as a replay.
        let raw_frames = [
            (
                "did:web:floria-shard-a.example",
                "nonce-aaaaaaaaaaaa",
                r#"{
                    "notification": {
                        "wakeup_kind": "message",
                        "push_target_id": "ak:pseudonym:push:abcdefghijklmnopqrstuv",
                        "devices": [{
                            "device_id": "ak:device:01904100-0000-7000-8000-000000000010",
                            "push_key": "fcm:opaque-token",
                            "app_id": "app.example"
                        }]
                    }
                }"#,
            ),
            (
                "did:web:floria-shard-a.example",
                "nonce-aaaaaaaaaaaa",
                r#"{
                    "notification": {
                        "wakeup_kind": "message",
                        "push_target_id": "ak:pseudonym:push:abcdefghijklmnopqrstuv",
                        "devices": [{
                            "device_id": "ak:device:01904100-0000-7000-8000-000000000010",
                            "push_key": "fcm:opaque-token",
                            "app_id": "app.example"
                        }]
                    }
                }"#,
            ),
        ];

        for (origin_did, nonce, raw) in raw_frames {
            let frame: ChimePushNotifyEnvelope = serde_json::from_str(raw)?;
            frame.assert_payload_safe(&policy, None)?;

            match nonces.observe(origin_did, nonce) {
                Ok(()) => enqueue_for_fanout(&frame),
                Err(err) => {
                    // Production relays page on this — it means
                    // either an upstream signing bug or an active
                    // replay attempt.
                    eprintln!("[relay] dropped replay frame from {origin_did}: {err}");
                }
            }
        }

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
