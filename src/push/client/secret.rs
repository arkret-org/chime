use std::fmt;

use zeroize::Zeroize;

/// A.5 #2 — minimal `SecretString` wrapper for credential material the
/// HTTP client must hold in memory (bearer tokens today; the surface is
/// designed so we can extend it to other secrets later).
///
/// Semantics:
/// - `Clone` is intentionally supported so the surrounding `ArkretPushClient` can remain `Clone`.
///   Each clone owns its own zeroed-on-drop allocation.
/// - `Debug` returns the literal string `"<redacted>"`; the inner `String` is never formatted.
/// - `Drop` zeroes the underlying allocation via the `zeroize` crate so a `ArkretPushClient` going
///   out of scope does not leave the token sitting in the freed heap region.
///
/// We do NOT implement `Display`, `PartialEq`, or `Serialize` on this
/// type — callers explicitly call [`Self::expose`] only at the very
/// moment they hand the secret to a reqwest header.
pub(super) struct SecretString(String);

impl SecretString {
    pub(super) fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Borrow the underlying secret. Callers MUST NOT clone the returned
    /// `&str` into a long-lived owned `String` outside of the request
    /// builder, and MUST NOT format it through `Debug`/`Display`.
    pub(super) fn expose(&self) -> &str {
        self.0.as_str()
    }
}

impl Clone for SecretString {
    fn clone(&self) -> Self {
        // Allocate a fresh String so each `ArkretPushClient` clone gets
        // its own zeroed-on-drop buffer.
        Self(self.0.clone())
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

impl Drop for SecretString {
    fn drop(&mut self) {
        // `String::zeroize` wipes the allocation before it is freed.
        self.0.zeroize();
    }
}
