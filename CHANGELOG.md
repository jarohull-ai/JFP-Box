# Changelog

All notable changes to JFP Box are documented here.

## [0.5.1] - 2026-10-17

### Fixed & Hardened (Security Hardening Release)
- **Hardened Tool-Call Interceptor (`ToolGate`):**
  - **Whitespace & Lexical Normalization:** Collapses unicode whitespace, tabs, and multiline characters into single canonical tokens prior to pattern inspection, neutralizing whitespace bypasses (e.g. `curl\thttp://...`, `rm  -rf /`).
  - **Exact Tool Binding Matching:** Replaced raw string substring checks with structured list parsing, preventing unassigned tool names (`MO`, `SEARC`) from matching valid tools (`MODEL_GENERATE`, `SEARCH`).
  - **Expanded Destructive Command Engine:** Intercepts `rm -rf .`, recursive deletion targeting `*`, `.`, or `~`, disk formatting (`mkfs.ext4`, `wipefs`), raw block writes (`dd of=/dev/sd*`), and device redirections (`> /dev/sd*`).
  - **Script Socket Defense:** Detects script-based socket connections (`import socket`, `socket.socket`, `tcpsocket`, `net.dial`) under `DIRECT_NETWORK:DENY`.
  - **Empirical Red-Team Audit Score:** Hardened from 3/8 to **10/10 PASS**.

## [0.5.0] - 2026-10-17

### Added
- **Developer-First Modernization:** Following requests to simplify adoption, standard **YAML** and **JSON** are now first-class policy formats alongside legacy `.jfp` manifests, backed by automatic format detection.
- **Python SDK Bindings (`jfp-box` via PyO3):** High-speed Rust policy evaluation and tool interception directly inside Python for LangChain, CrewAI, AutoGen, and LlamaIndex agents.
- **MCP Security Proxy (`jfp-box mcp-proxy`):** Transparent Zero-Trust stdio gateway for the Model Context Protocol (MCP), screening JSON-RPC `tools/call` invocations and preventing unauthorized agent actions.
- **Executive Summaries & Human Explanations (`jfp-box explain` / `--explain`):** Plain-English risk assessment (Low, Medium, High, Critical), active security guardrails, financial budget caps, and business risk explanations for non-technical leadership and developers.
- **Manifest Converter (`jfp-box convert`):** Bidirectional translation between YAML, JSON, and legacy JFP formats.
- **Runtime Tool Interceptor & MCP Firewall (`jfp-box check-tool`):** Real-time inspection of agent tool calls and commands, blocking destructive shell execution (`rm -rf`, fork bombs), unauthorized secret access (`.env`, `.ssh`), and direct network bypasses (`curl`, reverse shells).
- Exported new public library modules: `explain`, `mcp`, `tool_gate`, and `universal`.

## [0.4.2] - 2026-09-03

### Added

- Added `cargo audit` to the main Rust CI quality gate.
- Added an automated weekly parser-fuzzing workflow, also available on demand.

### Changed

- Minimized the checked-in fuzzing corpus while retaining merged coverage.
- Updated `SECURITY_TESTING.md` with the reproducible audit and fuzzing scope.

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
