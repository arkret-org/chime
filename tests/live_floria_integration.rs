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
    ArkretPushClient, PushRetryPolicy, floria_push_bridge_describe_url,
    floria_push_integration_describe_url,
};
use serde_json::{Value, json};

#[path = "_helpers/floria_spawn.rs"]
mod floria_spawn;

use floria_spawn::{SpawnedFloria, require_floria_or_skip};

const APP_ID: &str = "chime.live.placeholder";
const ORIGIN_DID: &str = "did:web:chime.live.test";

fn client_for(handle: &SpawnedFloria) -> ArkretPushClient {
    ArkretPushClient::new(handle.base_url.clone())
        .with_required_session_grant(false)
        .with_timeout(Duration::from_secs(5))
        .with_retry_policy(PushRetryPolicy::conservative())
}

fn notify_payload(idempotency_key: &str) -> Value {
    json!({
        "operation_id": arkret::ServiceOperationId::EDGE_PUSH_COMMAND_NOTIFY,
        "idempotency_key": idempotency_key,
        "origin_service_id": ORIGIN_DID,
        "notification": {
            "event_id": "ak:event:01JS0EV000000000000000000",
            "message_id": "ak:message:01JS0MSG0000000000000000",
            "strand_id": "ak:strand:019640f9-8000-7000-8000-000000000000",
            "realm_id": "ak:realm:01JS0SP000000000000000000",
            "push_target_id": "ak:pseudonym:push:01HYZ8Z000000000000000",
            "wakeup_kind": "message",
            "timing_profile_hint": "default",
            "push_hint": "new_message",
            "devices": [{
                "device_id": "ak:device:01904100-0000-7000-8000-000000000010",
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
        .floria_bridge_describe()
        .await
        .expect("floria_bridge_describe deserializes against live floria");

    assert_eq!(response.contract, "ak.push.bridge.describe");
    assert_eq!(response.notify.notify_path, "/_arkret/edge/push/notify");
    assert_eq!(
        response.notify.operation_id,
        arkret::ServiceOperationId::EDGE_PUSH_COMMAND_NOTIFY
    );
    assert!(
        response
            .gateway
            .supported_providers
            .iter()
            .any(|provider| provider == APP_ID),
        "live floria should advertise the rendered placeholder app: {:?}",
        response.gateway.supported_providers
    );

    let derived = floria_push_bridge_describe_url(&floria.url("/_arkret/edge/push/notify"))
        .expect("floria_push_bridge_describe_url accepts the loopback gateway URL");
    assert_eq!(derived, floria.url("/_floria/push/bridge/describe"));
}

#[tokio::test(flavor = "multi_thread")]
async fn integration_view_combines_describe_endpoints() {
    let Some(floria) = require_floria_or_skip("integration_view_combines_describe_endpoints").await
    else {
        return;
    };

    let client = client_for(&floria);
    let view = client
        .floria_integration_view()
        .await
        .expect("floria_integration_view round-trips against live floria");

    let bridge_describe_present = view
        .manifest
        .surfaces
        .iter()
        .any(|surface| surface.path == "/_floria/push/bridge/describe");
    assert!(
        bridge_describe_present,
        "integration manifest should advertise bridge/describe surface: {:?}",
        view.manifest.surfaces
    );
    assert_eq!(
        view.bridge.notify.operation_id,
        arkret::ServiceOperationId::EDGE_PUSH_COMMAND_NOTIFY
    );

    let derived = floria_push_integration_describe_url(&floria.url("/_arkret/edge/push/notify"))
        .expect("floria_push_integration_describe_url accepts the loopback gateway URL");
    assert_eq!(derived, floria.url("/_floria/integration/describe"));
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
        .post(floria.url("/_arkret/edge/push/notify"))
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
    let parsed: arkret::PushNotifyOutcome = serde_json::from_str(&raw)
        .unwrap_or_else(|err| panic!("canonical PushNotifyOutcome failed to decode {raw}: {err}"));
    assert!(
        parsed.rejected.len() <= 1,
        "unexpected rejection count: {parsed:?}"
    );
}
