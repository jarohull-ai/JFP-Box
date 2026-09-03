# Changelog

All notable changes to JFP Box are documented here.

## [0.4.1] - 2026-09-03

### Fixed

- Corrected the JSON contract regression test to match validator version 0.4.0.
- Restored a fully green GitHub Actions workflow after the v0.4.0 release.

## [0.4.0] - 2026-09-03

### Added

- Property-based tests covering arbitrary UTF-8 and byte input.
- A libFuzzer harness for parser robustness testing.
- A large-input regression test and reproducible security-testing scope.

### Security

- RustSec audit completed with no known vulnerabilities in the locked dependency graph.
- Extended fuzz run completed without crashes, panics, or hangs.

## [0.3.1] - 2026-09-02

### Changed

- Added complete crates.io and docs.rs package metadata for library discovery.

## [0.3.0] - 2026-09-02

### Added

- Enforced rustdocs for every public library item, with executable examples for
  parsing, validation, hashing, and JSON report generation.
- Criterion baseline benchmarks for parsing, policy validation, and JSON report
  generation.
- CI checks that API documentation and benchmark code compile successfully.

## [0.2.1] - 2026-09-02

### Fixed

- Made the SHA-256 block iteration compatible with the current Clippy lint set
  used by GitHub Actions.

## [0.2.0] - 2026-09-02

### Added

- Reusable Rust library API for manifest parsing, policy validation, SHA-256
  binding, timestamps, and JSON report generation.
- External integration coverage proving the public library API independently of
  the CLI.

### Changed

- Reduced the CLI to argument parsing, file I/O, presentation, and exit-code
  handling; policy logic remains in the library.

## [0.1.2] - 2026-09-02

### Fixed

- Reject optional declarations without an active v0.1 consumer with
  `ERR_ORPHANED_FIELD`.
- Return the exact orphaned field name in machine-readable error output.
- Reject runner-only controls until a trusted runner can enforce them.

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
