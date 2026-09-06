# JFP Ecosystem Overview

Status: working document  
Last reviewed: 2026-09-06  
Scope: documentation of project relationships only

## Purpose

The JFP ecosystem separates policy validation, runtime enforcement, and UI/agent
integration into distinct Rust projects. The project names stay unchanged:

- `jfp-box`
- `viper-boxd`
- `jfp-box-agent`

The separation is deliberate. A `PLAN_ACCEPTED` policy is not the same thing as
runtime containment. The validator decides whether a manifest is internally
consistent; the runtime must still enforce the accepted policy with operating
system controls; the adapter only exposes the combined flow to an ACP client.

## Project hierarchy

```text
AionUi / ACP-compatible client
    │
    ▼
jfp-box-agent
    │  ACP/stdio adapter
    │
    ├── jfp-box
    │     policy parsing and validation
    │     output: PLAN_ACCEPTED / PLAN_REJECTED
    │
    └── viper-boxd
          trusted runtime/backend layer
          helper IPC, systemd user units, cgroups, gateway mediation,
          lineage, admission control, observability and audit output
```

## Components

| Project | Current version | Current status | Responsibility | Explicit non-goal |
| --- | --- | --- | --- | --- |
| `jfp-box` | `0.4.1` | stable policy validator, pre-1.0 API | Validate JFP manifests and produce deterministic plan results | Runtime sandboxing or process execution |
| `viper-boxd` | `0.1.0-alpha.1` | alpha / experimental | Enforce accepted policies through controlled runtime primitives and helper IPC | Arbitrary agent execution before audit |
| `jfp-box-agent` | `0.1.0-alpha.1` | alpha / experimental | Present JFP Box and viper-boxd as one ACP agent-facing interface | General chat model or command runner |

## Execution flow

1. A client sends a task to `jfp-box-agent`.
2. The adapter extracts a JFP manifest from the request.
3. `jfp-box` validates the manifest.
4. If validation returns `PLAN_REJECTED`, execution stops and the adapter
   returns the rejection report.
5. If validation returns `PLAN_ACCEPTED`, the adapter calls `viper-boxd`.
6. `viper-boxd` maps logical policy fields to trusted local runtime
   configuration.
7. The helper runs only the controlled backend flow currently implemented for
   alpha testing.
8. Audit output links the validation and runtime stages through trace IDs and
   lineage records.

## Security boundary model

The ecosystem is fail-closed by design:

- Agents do not provide host paths, systemd properties, ports, provider
  credentials, raw gateway sockets, or arbitrary commands.
- Policy inheritance must preserve or narrow parent capabilities.
- Runtime enforcement belongs to `viper-boxd` and its helper, not to AionUi and
  not to the visual workspace alone.
- GitHub-hosted CI may be unable to enforce all systemd user-unit sandbox
  properties. Real release-gating boundary probes require a host where the
  systemd canary confirms enforcement.

## Publication status

- `jfp-box` is published as the reusable validator crate.
- `viper-boxd` is private during alpha development.
- `jfp-box-agent` remains local until dependency cleanup, fresh-build checks,
  and release hygiene are complete.

Do not present the alpha runtime or adapter as audited sandbox software.
