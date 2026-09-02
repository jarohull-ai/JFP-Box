# JFP Box Specification v0.1

## 1. Scope and threat model

JFP Box is a declarative policy and audit layer for AI-agent tasks. It is not a kernel sandbox and does not replace an operating-system security boundary.

v0.1 reduces the impact of P1 agent mistakes and P2 untrusted content through default-deny tools, typed gateways, bounded resources, evidence labeling, and structured output. P3 hostile-code containment is a future responsibility of a trusted runner and its OS sandbox backend.

## 2. Lifecycle

`BOX_SPAWN_REQUEST` is converted by a trusted backend into a JFP manifest. `jfp-box plan` parses the manifest, validates policy consistency, and prints either `PLAN_ACCEPTED` or `PLAN_REJECTED`. It never starts a process, mounts a filesystem, opens a network connection, or changes a workspace.

The command accepts `jfp-box plan [--format human|json] <manifest.jfp>`. The
default is human-readable output. `--format json` is the stable machine
interface for a future runner or UI.

Only a future trusted runner may consider an accepted plan for execution.

## 3. Required fields

```text
F:SPEC_VERSION:0.1;
F:TASK_ID:<task_id>;
F:BOX_ID:<box_id>;
F:AUDIT_TRACE_ID:<trace_id>;
F:NETWORK_MODE:<mode>;
F:DIRECT_NETWORK:DENY;
F:ALLOWED_GATEWAYS:[...];
F:TOOL_BINDINGS:[...];
F:EVIDENCE_CLASS:UNTRUSTED;
F:OUTPUT_SCHEMA:<schema_id>;
F:GATEWAY_POLICY_ID:<registered_policy_id>;
F:WRITE_MODE:PATCH_ONLY;
```

Unknown fields are rejected in v0.1. An agent never supplies host paths, gateway addresses, credentials, sandbox arguments, or elevated capabilities.

## 4. Network and evidence policy

`DIRECT_NETWORK:DENY` is mandatory. A Box may communicate only with registered entries in `ALLOWED_GATEWAYS`, through a matching entry in `TOOL_BINDINGS`.

| Mode | Gateways and tools |
| --- | --- |
| `OFFLINE_STRICT` | Empty lists only. No model and no network. |
| `MODEL_ONLY` | Registered `MODEL:` gateway and `MODEL_GENERATE` only. |
| `RESEARCH` | Registered `MODEL:` and `RESEARCH:` gateways with `MODEL_GENERATE`, `SEARCH`, and `FETCH`. |
| `NETWORK_RESTRICTED` | One or more registered typed gateways, for example `API:` and `API_CALL`. |

Research output is always `UNTRUSTED` evidence. A future Research Gateway must preserve an evidence identifier, canonical URL, fetch time, HTTP status, content type, content hash, and sanitized text. Evidence remains untrusted even when an agent reports corroboration.

## 5. Filesystem and output policy

A future live Box writes only to `/scratch`. It returns a patch manifest and structured result. A separate deterministic Patch Applier, outside the Box, is the only component permitted to apply approved changes to `/work`.

## 6. Resource, identity, and audit policy

Model tasks require `MAX_MODEL_TOKENS` and `MODEL_COST_BUDGET_USD`. Research tasks also require bounded request, fetch, evidence, redirect, domain, and content-type fields. Optional future runner controls include `MAX_ACTIVE_BOXES`, `BOX_TTL_MAX`, `BOX_TOKEN_BUDGET`, and `UI_CONFIRM_REQUIRED`.

`GATEWAY_POLICY_ID` identifies the immutable gateway policy. `AUDIT_TRACE_ID` links validation, gateway, evidence, and runner events for a task.

## 7. Validation result

The validator returns stable `ERR_*` codes. A rejected plan is never executable. An accepted plan expresses policy consistency only; it is not proof that an OS sandbox is present.

In JSON mode, standard output contains exactly one object with this shape:

```json
{
  "validator_version": "0.3.1",
  "manifest_spec_version": "0.1",
  "plan_status": "PLAN_ACCEPTED",
  "errors": [],
  "audit_trace_id": "…",
  "manifest_sha256": "…",
  "generated_at": "2026-09-02T08:20:00Z"
}
```

`validator_version` is the full SemVer version of the executable.
`manifest_spec_version` is the independent version declared by
`SPEC_VERSION`. `manifest_sha256` is SHA-256 of the exact input file bytes,
without parsing or normalisation. `generated_at` is an RFC 3339 UTC timestamp.
`errors` is always an array; every item has `code`, `field` (a field name or
`null`), and `message`.

Each registered `GATEWAY_POLICY_ID` is bound to exactly one `NETWORK_MODE` in
v0.1. A known policy paired with another valid mode is rejected with
`ERR_POLICY_MODE_MISMATCH`.

Every optional field must have an active v0.1 consumer. Model limits require a
`MODEL_GENERATE` binding, research limits require `NETWORK_MODE:RESEARCH`, and
runner-only controls are rejected until a trusted runner can enforce them. A
field without an active consumer is rejected with `ERR_ORPHANED_FIELD`; the
JSON error item's `field` identifies the exact declaration.

Exit codes are stable: `0` for `PLAN_ACCEPTED`, `1` for `PLAN_REJECTED`
(including syntax or UTF-8 input errors), and `2` for command-line, file I/O,
or internal tool errors.
