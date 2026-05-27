//! Server-side push relay sample.
//!
//! Models the slice of code a backend service (yougen, an SRE-owned
//! fan-out proxy, an on-prem connector) runs when it receives a
//! `cx.push.notify` frame from floria and wants to forward it onto an
//! internal queue (Kafka topic, Redis stream, MQ exchange, …) for
//! per-device delivery.
//!
//! Responsibilities demonstrated here:
//!
//! 1. Decode the inbound frame into `PushNotifyReqBody`.
//! 2. Run `assert_payload_safe` in `blind_wakeup_only` mode — relays
//!    NEVER assume plaintext visibility.
//! 3. Track replay nonces with `NonceTracker` so a duplicated frame
//!    cannot be re-fanned out. The relay's nonce window is decoupled
//!    from any downstream device's window (see `SECURITY.md`).
//! 4. Hand the validated frame to a stand-in "queue" function. In
//!    production this is the host application's broker client; the
//!    example just prints to stdout to stay dependency-free.
//!
//! Run with: `cargo run --example server-side-relay --features notify`.

#[cfg(feature = "notify")]
mod inner {
    use std::time::Duration;

    use chime::{NonceTracker, PushNotifyPolicyContext, PushNotifyReqBody};

    /// Stand-in for the host application's internal queue (Kafka,
    /// NATS, …). Real implementations push the validated frame as the
    /// payload of the per-device topic.
    fn enqueue_for_fanout(frame: &PushNotifyReqBody) {
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
        // shard does not poison other origins' windows.
        let mut nonces = NonceTracker::new(Duration::from_secs(5 * 60));

        let policy = PushNotifyPolicyContext::blind_wakeup_only();

        // Two synthetic inbound frames sharing the same nonce — the
        // second one MUST be rejected as a replay.
        let raw_frames = [
            (
                "did:web:floria-shard-a.example",
                "nonce-aaaaaaaaaaaa",
                r#"{
                    "operation_id": "cx.push.notify",
                    "destination_service_did": "did:web:yougen.example",
                    "notification": {
                        "wakeup_kind": "message",
                        "push_target_id": "cx:pseudonym:push:abcdefghijklmnopqrstuv",
                        "event_id": "cx:event:01JS0KE000000000000000001"
                    }
                }"#,
            ),
            (
                "did:web:floria-shard-a.example",
                "nonce-aaaaaaaaaaaa",
                r#"{
                    "operation_id": "cx.push.notify",
                    "destination_service_did": "did:web:yougen.example",
                    "notification": {
                        "wakeup_kind": "message",
                        "push_target_id": "cx:pseudonym:push:abcdefghijklmnopqrstuv",
                        "event_id": "cx:event:01JS0KE000000000000000001"
                    }
                }"#,
            ),
        ];

        for (origin_did, nonce, raw) in raw_frames {
            let frame: PushNotifyReqBody = serde_json::from_str(raw)?;
            frame.assert_payload_safe(&policy)?;

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
