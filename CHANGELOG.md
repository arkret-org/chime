# Changelog

## [Unreleased]

### Changed

- Align the active protocol target to `arkret-spec @ 5d66aeb`.
- Verify media token exchange outcomes through the SDK media-service
  verifier before returning a chime token marker.
- Move default push discovery to the protocol `/_arkret/describe`
  surface; floria product-local describe endpoints are explicit adapter
  methods.

### Fixed

- Keep CI, documentation, and examples aligned with MSRV 1.96.
- Build examples in CI with the `notify` feature.
