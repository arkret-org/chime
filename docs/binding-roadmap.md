# chime FFI / cross-platform binding roadmap

`chime` v1 ships a Rust-only API surface. Cross-language bindings are
explicitly **out of scope for the 1.0 line**; this document captures
the intended shapes so the API can evolve toward them without
backward-incompatible churn.

All four bindings below are tagged **future work**. None of them
appear in the current `Cargo.toml`, in CI, or on docs.rs. Do not file
issues asking when one will ship until the corresponding section is
promoted out of this roadmap.

## Why bindings are out of scope today

- The Rust API surface still moves at every spec round. Stabilising a
  parallel ABI now would either freeze chime in place or force every
  language binding to chase the spec — neither is acceptable.
- The host-app responsibilities documented in `SECURITY.md` (inbound
  signature verification, `EncryptedEnvelope` nonce checks,
  stale-timestamp enforcement) need a binding-language story before
  the binding ships. The default in a foreign language is "the
  binding does it for me", which silently inverts the boundary.
- `NonceTracker`, `PushPreferencesStore`, and `BridgeContractCache`
  all need binding-language equivalents for storage. The Rust API
  takes traits; a binding API has to pick a concrete shape per
  language. We will defer that until at least two production host
  applications request it.

## Intended bindings

### 1. C header (`chime.h`) — extern "C" surface

**Status:** future work.
**Audience:** native desktop hosts (Win32, Cocoa, Linux native) that
cannot pull a Rust toolchain into their build pipeline; embedded /
IoT relays that need a small static-link footprint.

**Shape (illustrative, not stable):**

```c
/* Build a register-device request body. The caller owns `out_json`
 * and must free it with `chime_string_free`. */
chime_status chime_build_register_device_request(
    const chime_push_device_config* config,
    const chime_gateway_binding*    binding,
    const chime_push_preferences*   prefs,
    char**                          out_json);

/* Validate an inbound notify frame against the blind-wakeup policy.
 * `payload_json` is borrowed; the function returns one of the
 * `chime_status` codes that map 1:1 to `PushNotifyPrivacyError`. */
chime_status chime_assert_payload_safe(
    const char*                          payload_json,
    const chime_push_notify_policy_ctx*  policy);

void chime_string_free(char* s);
```

The header would be generated via `cbindgen` from a separate
`chime-ffi` crate so the core crate stays free of `extern "C"`
attributes.

### 2. WASM npm package (`@arkret/chime`)

**Status:** future work.
**Audience:** browser-side web hosts and Electron renderers that need
the privacy validators in JavaScript without round-tripping to the
Rust process.

**Shape (illustrative, not stable):**

```ts
import { buildRegisterDeviceRequest, assertPayloadSafe,
         PushGatewayType, PushNotifyPolicyMode } from "@arkret/chime";

const request = buildRegisterDeviceRequest({
    config: { deviceId: "did:web:alice.example#web", /* … */ },
    binding: { gatewayType: PushGatewayType.Standard, pushGateway: "https://…" },
    prefs: { enabled: true },
});

assertPayloadSafe(payloadJson, { mode: PushNotifyPolicyMode.BlindWakeupOnly });
```

Build path: `wasm-pack build --target bundler` on a `chime-wasm`
crate that re-exports the same validators via `wasm-bindgen`. The
package would publish both `bundler` and `nodejs` targets.

### 3. JNI binding (`im.arkret.chime`) — Android / JVM

**Status:** future work.
**Audience:** Android host applications that need to validate inbound
FCM / OEM frames inside the platform receiver process before
handing the result to Kotlin/Java UI code.

**Shape (illustrative, not stable):**

```kotlin
package im.arkret.chime

object Chime {
    @JvmStatic
    external fun buildRegisterDeviceRequest(configJson: String,
                                            bindingJson: String,
                                            prefsJson: String): String

    @JvmStatic
    @Throws(PushNotifyPrivacyException::class)
    external fun assertPayloadSafe(payloadJson: String, policyJson: String)
}
```

Build path: `cargo-ndk` (or `cross`) producing per-ABI `.so` files
shipped inside an AAR. Per-ABI cross-compilation is mandatory because
OEM-route hosts (Huawei / Xiaomi / OPPO) still ship 32-bit devices.

### 4. Swift binding (`Chime.framework`) — iOS / macOS

**Status:** future work.
**Audience:** iOS / iPadOS / macOS host applications that need the
validators inside the APNs Notification Service Extension, where
spinning up a Rust runtime is allowed but invoking a Rust binary is
not.

**Shape (illustrative, not stable):**

```swift
import Chime

let request = try Chime.buildRegisterDeviceRequest(
    config: .init(deviceId: "did:web:alice.example#ios", /* … */),
    binding: .init(gatewayType: .standard,
                   pushGateway: "https://push.example.com/_arkret/edge/push/notify"),
    prefs: .init(enabled: true))

try Chime.assertPayloadSafe(payloadJson, policy: .blindWakeupOnly)
```

Build path: `cargo-swift` (or hand-rolled `swift-bridge`) producing an
XCFramework with `arm64-apple-ios`, `arm64-apple-ios-sim`,
`arm64-apple-darwin`, and `x86_64-apple-darwin` slices.

## Tracking

When work on any of these bindings starts in earnest, the
corresponding section above MUST be lifted out of this roadmap into
its own document under `docs/bindings/<name>.md`, and the entry here
replaced with a stub link. The "future work" label is the contract
that until that lift happens, no public API is committed.
