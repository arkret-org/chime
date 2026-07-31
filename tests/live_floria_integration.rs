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

/// Canonical `ak.edge.push.command.notify` body.
///
/// Built from the SDK strong type rather than ad-hoc JSON so the test can
/// never drift from the wire model. Per `push-notifications.md` §5.1 the
/// body carries *only* `{notification, event_kind?, reason_code?,
/// audit_envelope?}`: `operation_id` is determined by the URL path, and
/// the idempotency key and the source service DID ride the
/// `Idempotency-Key` / `Source-Service-ID` transport headers. Identifying
/// fields (`event_id`, `message_id`, `strand_id`, `realm_id`, …) MUST NOT
/// appear under the default `ak.profile.push_gateway.blind_wakeup.v1`
/// profile, which is the profile an anonymous caller gets.
fn notify_body() -> arkret::PushNotifyRequestBody {
    arkret::PushNotifyRequestBody {
        notification: arkret::PushNotificationEnvelope {
            push_target_id: Some("ak:pseudonym:push:01HYZ8Z000000000000000".to_owned()),
            wakeup_kind: Some("message".to_owned()),
            timing_profile_hint: Some(arkret::PushTimingProfileHint::Default),
            push_hint: Some("new_message".to_owned()),
            devices: vec![arkret::PushDeviceRoute {
                device_id: arkret::DeviceId::new(
                    "ak:device:01904100-0000-7000-8000-000000000010".to_owned(),
                )
                .expect("device id is canonical"),
                push_key: Some("chime-live-token-01".to_owned()),
                app_id: Some(APP_ID.to_owned()),
                platform: None,
                target_route_token: None,
                visible_notification_opt_in: false,
            }],
            ..Default::default()
        },
        event_kind: None,
        reason_code: None,
        audit_envelope: None,
    }
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
        ServiceOperationId::EDGE_PUSH_COMMAND_NOTIFY
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
        ServiceOperationId::EDGE_PUSH_COMMAND_NOTIFY
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
    let body = notify_body();
    let response = http
        .post(floria.url("/_arkret/edge/push/notify"))
        .header("Idempotency-Key", "chime-live-notify-001")
        .header("Source-Service-ID", ORIGIN_DID)
        .json(&body)
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

    // `push_notify_outcome` is closed: rejections are expanded into one
    // `rejected` entry per input device, never a second response shape, and
    // `outcomes[]` is conserved against `notification.devices[]`.
    assert_eq!(
        parsed.push_target_id,
        "ak:pseudonym:push:01HYZ8Z000000000000000"
    );
    assert_eq!(
        parsed.outcomes.len(),
        body.notification.devices.len(),
        "outcomes[] must be conserved against notification.devices[]: {parsed:?}"
    );
    let rejected = parsed
        .outcomes
        .iter()
        .filter(|outcome| outcome.gateway_status == arkret::PushNotifyGatewayStatus::Rejected)
        .count();
    assert!(rejected <= 1, "unexpected rejection count: {parsed:?}");
}
