# JFP Box Security Testing

This document records the security-testing scope for the policy validator.

## Scope

Covered:

- manifest parsing and duplicate/unknown-field handling;
- policy and mode consistency validation;
- resource-limit validation;
- JSON error/report generation;
- parser robustness against arbitrary UTF-8, arbitrary bytes, and large input;
- Rust dependency advisories reported by RustSec.

Not covered:

- kernel or filesystem isolation;
- network gateway enforcement;
- process lifecycle enforcement;
- the future trusted runner (`viper-boxd`);
- correctness of external model or research services.

## Reproducible checks

```bash
cargo fmt --all -- --check
cargo test --locked
cargo clippy --all-targets --all-features -- -D warnings
cargo audit
cargo +nightly fuzz run manifest -- -runs=10000 -max_len=4096
```

The short baseline fuzz run completed with 10,000 executions, no crashes,
no panics, no hangs, and 186 coverage counters. This is an initial smoke test,
not a formal security guarantee. Longer runs should be performed before a
stable 1.0 release.

## Security boundary

JFP Box is a policy validator. A `PLAN_ACCEPTED` result means only that the
manifest is internally consistent with the v0.1 policy rules. It does not prove
that a runtime, gateway, or operating system will enforce those rules.
