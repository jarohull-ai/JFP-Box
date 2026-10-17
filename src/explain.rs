// Copyright (c) 2026 jarohull-ai. All rights reserved.
// Licensed under the PolyForm Noncommercial License 1.0.0 or Commercial License.

//! Executive summaries and human-first explanations for AI agent task policies.

use super::{Manifest, Violation};
use serde::{Deserialize, Serialize};

/// Risk level classification for the evaluated task policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RiskLevel {
    /// Safe, hermetic task (e.g. offline execution or local read-only model).
    Low,
    /// Controlled external research or API access with untrusted evidence classification.
    Medium,
    /// Elevated capabilities or active policy violations detected.
    High,
    /// Critical safety violation (e.g. direct unmonitored network or direct workspace write).
    Critical,
}

impl std::fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RiskLevel::Low => write!(f, "🟢 LOW RISK"),
            RiskLevel::Medium => write!(f, "🟡 MEDIUM RISK"),
            RiskLevel::High => write!(f, "🟠 HIGH RISK"),
            RiskLevel::Critical => write!(f, "🔴 CRITICAL RISK"),
        }
    }
}

/// Human-understandable breakdown of a policy violation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HumanViolation {
    /// Technical error code (e.g. ERR_DIRECT_NETWORK).
    pub code: String,
    /// Associated manifest field if applicable.
    pub field: Option<String>,
    /// Human-friendly title of the violation.
    pub title: String,
    /// Plain-English explanation of why the action was rejected.
    pub plain_reason: String,
    /// Real-world business or security risk avoided by this block.
    pub business_impact: String,
}

/// Comprehensive human-centric audit and executive evaluation of a task policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyExplanation {
    /// Task identifier.
    pub task_id: String,
    /// Box/Agent instance identifier.
    pub box_id: String,
    /// Trace ID for distributed logging and compliance.
    pub audit_trace_id: String,
    /// Active network profile.
    pub network_mode: String,
    /// PLAN_ACCEPTED or PLAN_REJECTED.
    pub status: String,
    /// Overall security risk classification.
    pub risk_level: RiskLevel,
    /// Executive summary suitable for leadership and non-technical stakeholders.
    pub executive_summary: String,
    /// Active Zero-Trust security controls enforced on this task.
    pub security_guardrails: Vec<String>,
    /// Enforced budget and resource caps.
    pub resource_caps: Vec<String>,
    /// List of human-understandable violation details.
    pub human_violations: Vec<HumanViolation>,
}

/// Engine for generating human-centric explanations of AI task policies.
pub struct PolicyExplainer;

impl PolicyExplainer {
    /// Generates a comprehensive human-centric explanation for a manifest and its validation findings.
    pub fn explain(manifest: &Manifest, violations: &[Violation]) -> PolicyExplanation {
        let task_id = manifest
            .get("TASK_ID")
            .unwrap_or("UNKNOWN_TASK")
            .to_string();
        let box_id = manifest.get("BOX_ID").unwrap_or("UNKNOWN_BOX").to_string();
        let trace_id = manifest
            .get("AUDIT_TRACE_ID")
            .unwrap_or("UNTRACKED")
            .to_string();
        let network_mode = manifest
            .get("NETWORK_MODE")
            .unwrap_or("UNDEFINED")
            .to_string();

        let is_accepted = violations.is_empty();
        let status = if is_accepted {
            "PLAN_ACCEPTED".to_string()
        } else {
            "PLAN_REJECTED".to_string()
        };

        // Determine Risk Level
        let risk_level = if !is_accepted {
            let has_critical = violations.iter().any(|v| {
                matches!(
                    v.code(),
                    "ERR_DIRECT_NETWORK" | "ERR_WRITE_MODE" | "ERR_UNREGISTERED_GATEWAY"
                )
            });
            if has_critical {
                RiskLevel::Critical
            } else {
                RiskLevel::High
            }
        } else {
            match network_mode.as_str() {
                "OFFLINE_STRICT" => RiskLevel::Low,
                "MODEL_ONLY" => RiskLevel::Low,
                "RESEARCH" => RiskLevel::Medium,
                "NETWORK_RESTRICTED" => RiskLevel::Medium,
                _ => RiskLevel::High,
            }
        };

        // Executive Summary for C-level & managers
        let executive_summary = if is_accepted {
            match network_mode.as_str() {
                "OFFLINE_STRICT" => format!(
                    "Task '{}' is completely air-gapped and safe to run. The agent has zero network access and cannot modify production code directly.",
                    task_id
                ),
                "MODEL_ONLY" => format!(
                    "Task '{}' is confined to approved AI models only. No external web browsing or raw network access is permitted.",
                    task_id
                ),
                "RESEARCH" => format!(
                    "Task '{}' collects external web research through a monitored read-only gateway. All collected data is strictly quarantined as UNTRUSTED to prevent prompt injection.",
                    task_id
                ),
                _ => format!(
                    "Task '{}' is authorized under restricted typed gateway policies with hard budget caps.",
                    task_id
                ),
            }
        } else {
            format!(
                "Task '{}' was BLOCKED by the Zero-Trust policy gate due to {} safety violation(s). The agent cannot be spawned until these issues are resolved.",
                task_id,
                violations.len()
            )
        };

        // Active Security Guardrails
        let mut security_guardrails = Vec::new();
        if manifest.get("DIRECT_NETWORK") == Some("DENY") {
            security_guardrails.push(
                "✅ Direct raw network access is permanently DENIED (Zero-Trust)".to_string(),
            );
        }
        if manifest.get("WRITE_MODE") == Some("PATCH_ONLY") {
            security_guardrails.push(
                "✅ Code changes restricted to /scratch patches only (no direct overwrite)"
                    .to_string(),
            );
        }
        if manifest.get("EVIDENCE_CLASS") == Some("UNTRUSTED") {
            security_guardrails.push(
                "✅ External data tagged as UNTRUSTED (Anti-Prompt-Injection quarantine)"
                    .to_string(),
            );
        }

        // Active Resource Caps
        let mut resource_caps = Vec::new();
        if let Some(tokens) = manifest.get("MAX_MODEL_TOKENS") {
            resource_caps.push(format!("Model Token Cap: {} tokens", tokens));
        }
        if let Some(cost) = manifest.get("MODEL_COST_BUDGET_USD") {
            resource_caps.push(format!("Hard Financial Budget: ${} USD", cost));
        }
        if let Some(reqs) = manifest.get("MAX_RESEARCH_REQUESTS") {
            resource_caps.push(format!("Max Web Requests: {}", reqs));
        }
        if let Some(fetch) = manifest.get("MAX_FETCH_BYTES") {
            resource_caps.push(format!("Max Single Download: {}", fetch));
        }
        if let Some(evidence) = manifest.get("MAX_TOTAL_EVIDENCE_BYTES") {
            resource_caps.push(format!("Max Total Storage: {}", evidence));
        }

        // Human Violations
        let human_violations = violations.iter().map(Self::explain_violation).collect();

        PolicyExplanation {
            task_id,
            box_id,
            audit_trace_id: trace_id,
            network_mode,
            status,
            risk_level,
            executive_summary,
            security_guardrails,
            resource_caps,
            human_violations,
        }
    }

    fn explain_violation(v: &Violation) -> HumanViolation {
        let (title, reason, impact) = match v.code() {
            "ERR_DIRECT_NETWORK" => (
                "Direct Raw Internet Access Forbidden",
                "The task requested direct socket/network access. In enterprise AI systems, agents must never make direct outbound TCP/UDP connections.",
                "Prevents data exfiltration, secret leakage to attackers, and unmonitored command-and-control calls."
            ),
            "ERR_WRITE_MODE" => (
                "Direct Filesystem Overwrite Denied",
                "The task does not enforce WRITE_MODE:PATCH_ONLY. Agents are not allowed to directly mutate production workspaces.",
                "Prevents accidental or malicious codebase deletion, ransomware behavior, or unreviewed file overwrites."
            ),
            "ERR_EVIDENCE_CLASS" => (
                "External Content Quarantine Missing",
                "Web data must be classified as EVIDENCE_CLASS:UNTRUSTED. External websites can contain malicious prompt injections.",
                "Protects downstream LLMs from being hijacked by malicious instructions hidden in websites or documents."
            ),
            "ERR_OFFLINE_HAS_GATEWAYS" => (
                "Gateway Conflict in Offline Mode",
                "Task is designated as OFFLINE_STRICT, but requested active external gateways or model connections.",
                "Enforces strict air-gapped isolation for confidential or sovereign workloads."
            ),
            "ERR_UNKNOWN_GATEWAY" => (
                "Unregistered or Untyped Gateway",
                "The agent requested an external gateway that is not registered in the trusted whitelist.",
                "Blocks connection to unauthorized LLM endpoints or unmonitored web APIs."
            ),
            "ERR_UNSUPPORTED_TOOL" => (
                "Unauthorized Tool Binding",
                "The requested tool is not compatible with the designated network profile (e.g. bash shell tools in research tasks).",
                "Enforces principle of least privilege, preventing tool-use privilege escalation."
            ),
            "ERR_EVIDENCE_LIMIT_CONFLICT" => (
                "Storage Limit Inconsistency",
                "The single-request fetch limit is greater than the total allowable evidence storage for the task.",
                "Prevents disk space exhaustion and memory leaks during automated data collection."
            ),
            _ => (
                "Policy Inconsistency",
                v.message(),
                "Ensures strict compliance with declarative organizational safety constraints."
            ),
        };

        HumanViolation {
            code: v.code().to_string(),
            field: v.field().map(str::to_string),
            title: title.to_string(),
            plain_reason: reason.to_string(),
            business_impact: impact.to_string(),
        }
    }

    /// Renders a beautiful visual report in text for CLI output.
    pub fn render_human(explanation: &PolicyExplanation) -> String {
        let mut out = String::new();
        out.push_str("\n🛡️  AI AGENT POLICY GATE AUDIT REPORT\n");
        out.push_str(
            "================================================================================\n",
        );
        out.push_str(&format!("📌 Task ID:        {}\n", explanation.task_id));
        out.push_str(&format!("📦 Box ID:         {}\n", explanation.box_id));
        out.push_str(&format!(
            "🌐 Network Mode:   {}\n",
            explanation.network_mode
        ));
        out.push_str(&format!("🎯 Decision:       {}\n", explanation.status));
        out.push_str(&format!("⚖️  Risk Level:     {}\n", explanation.risk_level));
        out.push_str(&format!(
            "🔍 Audit Trace ID: {}\n",
            explanation.audit_trace_id
        ));
        out.push_str(
            "--------------------------------------------------------------------------------\n",
        );
        out.push_str(&format!(
            "👔 Executive Summary:\n   {}\n",
            explanation.executive_summary
        ));
        out.push_str(
            "--------------------------------------------------------------------------------\n",
        );

        if !explanation.security_guardrails.is_empty() {
            out.push_str("🛡️  Active Security Guardrails:\n");
            for g in &explanation.security_guardrails {
                out.push_str(&format!("   {}\n", g));
            }
        }

        if !explanation.resource_caps.is_empty() {
            out.push_str("\n💰 Resource & Financial Caps:\n");
            for c in &explanation.resource_caps {
                out.push_str(&format!("   • {}\n", c));
            }
        }

        if !explanation.human_violations.is_empty() {
            out.push_str("\n🚨 Policy Violations Explained:\n");
            for (i, v) in explanation.human_violations.iter().enumerate() {
                out.push_str(&format!("   #{}: [{}] {}\n", i + 1, v.code, v.title));
                out.push_str(&format!("      👉 Why blocked: {}\n", v.plain_reason));
                out.push_str(&format!("      💥 Risk avoided: {}\n", v.business_impact));
            }
        }

        out.push_str(
            "================================================================================\n",
        );
        out
    }

    /// Renders report formatted as Markdown.
    pub fn render_markdown(explanation: &PolicyExplanation) -> String {
        let mut md = String::new();
        md.push_str("# 🛡️ AI Agent Security & Policy Audit\n\n");
        md.push_str(&format!("- **Task ID:** `{}`\n", explanation.task_id));
        md.push_str(&format!("- **Status:** **`{}`**\n", explanation.status));
        md.push_str(&format!("- **Risk Level:** {}\n", explanation.risk_level));
        md.push_str(&format!(
            "- **Audit Trace ID:** `{}`\n\n",
            explanation.audit_trace_id
        ));
        md.push_str("## Executive Summary\n");
        md.push_str(&format!("{}\n\n", explanation.executive_summary));

        if !explanation.security_guardrails.is_empty() {
            md.push_str("## Active Security Guardrails\n");
            for g in &explanation.security_guardrails {
                md.push_str(&format!("- {}\n", g));
            }
            md.push('\n');
        }

        if !explanation.human_violations.is_empty() {
            md.push_str("## Violations & Business Risks\n");
            for v in &explanation.human_violations {
                md.push_str(&format!("### ❌ [{}] {}\n", v.code, v.title));
                md.push_str(&format!("- **Reason:** {}\n", v.plain_reason));
                md.push_str(&format!("- **Business Risk:** {}\n\n", v.business_impact));
            }
        }

        md
    }
}
