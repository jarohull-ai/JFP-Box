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
cargo +nightly fuzz run manifest -- -max_total_time=300 -max_len=16384
```

The extended local fuzz run completed 1,415,642 executions with no crashes,
panics, or hangs and reached 232 coverage counters. The checked-in corpus was
minimized from 547 to 416 inputs while retaining the merged coverage set.
These are reproducible smoke-test results, not a formal security guarantee.
Longer runs and independent review remain appropriate before a stable 1.0
release.

## Security boundary

JFP Box is a policy validator. A `PLAN_ACCEPTED` result means only that the
manifest is internally consistent with the v0.1 policy rules. It does not prove
that a runtime, gateway, or operating system will enforce those rules.
