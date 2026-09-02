# Changelog

All notable changes to JFP Box are documented here.

## [0.1.1] - 2026-09-02

### Fixed

- Bound each registered `GATEWAY_POLICY_ID` to its only permitted
  `NETWORK_MODE`.
- Reject contradictory known policy/mode pairs with
  `ERR_POLICY_MODE_MISMATCH`.
- Added regression coverage for every invalid policy/mode combination.

## [0.1.0] - 2026-09-02

### Added

- JFP Box v0.1 manifest parser and policy validator.
- Offline, model-only, research, and restricted-network profile checks.
- Registered gateway, gateway-policy, typed tool-binding, and resource-limit
  validation.
- Human-readable and stable JSON `plan` output.
- Exact-byte SHA-256 manifest binding and RFC 3339 UTC report timestamps.
- Golden example manifests and adversarial validator tests.

### Security model

- Mandatory default-deny direct networking.
- Untrusted evidence classification and patch-only output intent.
- No live runner, filesystem sandbox, gateway, or model access in v0.1.
