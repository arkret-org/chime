//! Live floria integration tests for chime.
//!
//! By default these tests skip when a floria binary is unavailable —
//! local developers without a sibling `floria` checkout still get a
//! green run. CI MUST set `CHIME_INTEGRATION_REQUIRED=1` (and supply
//! `FLORIA_BIN=/path/to/floria` or a built sibling checkout) so a
//! missing binary becomes a hard test failure instead of a silent
//! green. See `tests/_helpers/floria_spawn.rs::require_floria_or_skip`.

#![cfg(all(feature = "http", feature = "notify"))]

use std::time::Duration;

use chime::{
    CokretPushClient, PushNotifyOutcome, PushRetryPolicy, push_bridge_describe_url,
    push_integration_describe_url,
};
use serde_json::{Value, json};

#[path = "_helpers/floria_spawn.rs"]
mod floria_spawn;

use floria_spawn::{SpawnedFloria, require_floria_or_skip};

const APP_ID: &str = "chime.live.placeholder";
const ORIGIN_DID: &str = "did:web:chime.live.test";

fn client_for(handle: &SpawnedFloria) -> CokretPushClient {
    CokretPushClient::new(handle.base_url.clone())
        .with_required_session_grant(false)
        .with_timeout(Duration::from_secs(5))
        .with_retry_policy(PushRetryPolicy::conservative())
}

fn notify_payload(idempotency_key: &str) -> Value {
    json!({
        "operation_id": chime::OPERATION_PUSH_NOTIFY,
        "idempotency_key": idempotency_key,
        "origin_service_did": ORIGIN_DID,
        "notification": {
            "event_id": "ck:event:01JS0EV000000000000000000",
            "message_id": "ck:message:01JS0MSG0000000000000000",
            "flow_id": "ck:flow:01JS0FLOW000000000000000",
            "realm_id": "ck:realm:01JS0SP000000000000000000",
            "push_target_id": "ck:pseudonym:push:01HYZ8Z000000000000000",
            "wakeup_kind": "message",
            "push_hint": "new_message",
            "devices": [{
                "app_id": APP_ID,
                "push_key": "chime-live-token-01"
            }]
        }
    })
}

#[tokio::test(flavor = "multi_thread")]
async fn bridge_describe_round_trips_against_live_floria() {
    let Some(floria) =
        require_floria_or_skip("bridge_describe_round_trips_against_live_floria").await
    else {
        return;
    };

    let client = client_for(&floria);
    let response = client
        .bridge_describe()
        .await
        .expect("bridge_describe deserializes against live floria");

    assert_eq!(response.contract, "ck.push.bridge.describe");
    assert_eq!(response.notify.notify_path, "/_cokret/edge/push/notify");
    assert_eq!(response.notify.operation_id, chime::OPERATION_PUSH_NOTIFY);
    assert!(
        response
            .gateway
            .supported_providers
            .iter()
            .any(|provider| provider == APP_ID),
        "live floria should advertise the rendered placeholder app: {:?}",
        response.gateway.supported_providers
    );

    let derived = push_bridge_describe_url(&floria.url("/_cokret/edge/push/notify"))
        .expect("push_bridge_describe_url accepts the loopback gateway URL");
    assert_eq!(derived, floria.url("/_cokret/edge/push/bridge/describe"));
}

#[tokio::test(flavor = "multi_thread")]
async fn integration_view_combines_describe_endpoints() {
    let Some(floria) = require_floria_or_skip("integration_view_combines_describe_endpoints").await
    else {
        return;
    };

    let client = client_for(&floria);
    let view = client
        .integration_view()
        .await
        .expect("integration_view round-trips against live floria");

    let bridge_describe_present = view
        .manifest
        .surfaces
        .iter()
        .any(|surface| surface.path == "/_cokret/edge/push/bridge/describe");
    assert!(
        bridge_describe_present,
        "integration manifest should advertise bridge/describe surface: {:?}",
        view.manifest.surfaces
    );
    assert_eq!(
        view.bridge.notify.operation_id,
        chime::OPERATION_PUSH_NOTIFY
    );

    let derived = push_integration_describe_url(&floria.url("/_cokret/edge/push/notify"))
        .expect("push_integration_describe_url accepts the loopback gateway URL");
    assert_eq!(derived, floria.url("/_cokret/edge/integration/describe"));
}

#[tokio::test(flavor = "multi_thread")]
async fn push_notify_delivery_receipt_round_trips_into_chime_wire_types() {
    let Some(floria) =
        require_floria_or_skip("push_notify_delivery_receipt_round_trips_into_chime_wire_types")
            .await
    else {
        return;
    };

    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("reqwest client builds");
    let response = http
        .post(floria.url("/_cokret/edge/push/notify"))
        .json(&notify_payload("chime-live-notify-001"))
        .send()
        .await
        .expect("notify POST reaches floria");
    assert!(
        response.status().is_success(),
        "notify request returned {:?}",
        response.status()
    );

    let raw = response
        .text()
        .await
        .expect("notify response body is readable");
    let parsed: PushNotifyOutcome = serde_json::from_str(&raw)
        .unwrap_or_else(|err| panic!("chime PushNotifyOutcome failed to decode {raw}: {err}"));
    assert!(
        parsed
            .request_id
            .as_deref()
            .is_some_and(|id| !id.is_empty()),
        "floria response should carry a non-empty request_id: {parsed:?}"
    );
    assert_eq!(
        parsed.accepted + parsed.rejected.len(),
        1,
        "exactly one device should be either accepted or rejected: {parsed:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn repeated_notify_advances_floria_request_id() {
    let Some(floria) = require_floria_or_skip("repeated_notify_advances_floria_request_id").await
    else {
        return;
    };

    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("reqwest client builds");
    let first_raw = http
        .post(floria.url("/_cokret/edge/push/notify"))
        .json(&notify_payload("chime-live-rotation-A"))
        .send()
        .await
        .expect("first notify POST reaches floria")
        .text()
        .await
        .expect("first notify body readable");
    let first: PushNotifyOutcome =
        serde_json::from_str(&first_raw).expect("first PushNotifyOutcome decodes");

    let second_raw = http
        .post(floria.url("/_cokret/edge/push/notify"))
        .json(&notify_payload("chime-live-rotation-B"))
        .send()
        .await
        .expect("second notify POST reaches floria")
        .text()
        .await
        .expect("second notify body readable");
    let second: PushNotifyOutcome =
        serde_json::from_str(&second_raw).expect("second PushNotifyOutcome decodes");

    assert!(
        first.request_id.is_some() && second.request_id.is_some(),
        "both notify calls should carry request_ids: {first:?} / {second:?}"
    );
    assert_ne!(
        first.request_id, second.request_id,
        "distinct idempotency keys should produce distinct request_ids: {first:?} / {second:?}"
    );
}
