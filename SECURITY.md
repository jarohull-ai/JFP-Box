# Security policy

## Scope

JFP Box v0.1 validates policy manifests. It does not execute tasks or provide a
kernel security boundary. Its security-sensitive surface includes manifest
parsing, validation, JSON output, integrity hashing, and policy decisions.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability, sandbox escape,
policy bypass, or proof of concept.

After the GitHub repository is published, use GitHub's private security
advisory/reporting flow for the repository. If that channel is unavailable,
contact [venom.evo@protonmail.com](mailto:venom.evo@protonmail.com) without
sharing exploit details publicly.

Please include affected version, a minimal reproduction, impact, and any safe
mitigation you identified. We will acknowledge a report and coordinate a fix
before public disclosure where feasible.

## Security boundaries

`PLAN_ACCEPTED` means the manifest is internally consistent with v0.1 policy.
It does **not** mean a task is isolated, safe to execute, or safe against
hostile code. A future trusted runner, OS sandbox backend, gateway, and patch
applier must be evaluated and deployed as separate security boundaries.
