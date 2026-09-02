# Contributing to JFP Box

Thank you for helping make policy validation for agent tasks more predictable.

## Before proposing a change

1. Read [SPECIFICATION.md](SPECIFICATION.md); it is the public contract.
2. Keep v0.1 policy-first: no process execution, mounts, network calls, model
   calls, or workspace writes belong in this repository.
3. Add tests for every behavioural change, especially negative and adversarial
   cases.
4. Run `cargo fmt -- --check` and `cargo test`.

## Compatibility

Do not silently change accepted manifests, JSON field names, `ERR_*` codes, or
exit codes. Contract changes need a documented version change. A new runtime,
gateway, or patch applier belongs in an independent module or repository.

## Security reports

Follow [SECURITY.md](SECURITY.md). Never include a working exploit or sensitive
environment data in a public issue or pull request.
