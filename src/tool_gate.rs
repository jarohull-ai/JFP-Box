// Copyright (c) 2026 jarohull-ai. All rights reserved.
// Licensed under the PolyForm Noncommercial License 1.0.0 or Commercial License.

//! Runtime tool-call safety interceptor and MCP firewall gate.

use super::Manifest;
use serde::{Deserialize, Serialize};

/// Result decision for an intercepted tool call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ToolDecision {
    /// Tool call conforms to policy constraints.
    Allowed,
    /// Tool call was blocked due to a policy violation or safety rule.
    Blocked,
}

impl std::fmt::Display for ToolDecision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ToolDecision::Allowed => write!(f, "✅ ALLOWED"),
            ToolDecision::Blocked => write!(f, "❌ BLOCKED"),
        }
    }
}

/// Evaluation result for a proposed tool call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCheckResult {
    /// Name of the intercepted tool.
    pub tool_name: String,
    /// Allowed or Blocked verdict.
    pub decision: ToolDecision,
    /// Risk severity score from 0 (safe) to 100 (critical threat).
    pub risk_score: u8,
    /// Human-understandable rationale for the decision.
    pub reason: String,
    /// Rule or policy section triggering this decision.
    pub policy_reference: String,
}

/// Runtime tool-call safety interceptor and MCP firewall gate.
pub struct ToolGate;

impl ToolGate {
    /// Evaluates a proposed tool call against an active manifest policy.
    pub fn evaluate(manifest: &Manifest, tool_name: &str, argument: &str) -> ToolCheckResult {
        let tool_clean = tool_name.trim();
        let arg_clean = argument.trim();

        // 1. Check if tool is bound in TOOL_BINDINGS
        let bindings = manifest.get("TOOL_BINDINGS").unwrap_or("[]");
        let tool_is_bound = bindings.contains(tool_clean);

        if !tool_is_bound && !bindings.contains(&format!("{}->", tool_clean)) {
            return ToolCheckResult {
                tool_name: tool_clean.to_string(),
                decision: ToolDecision::Blocked,
                risk_score: 85,
                reason: format!(
                    "Tool '{}' is not registered in task TOOL_BINDINGS: {}",
                    tool_clean, bindings
                ),
                policy_reference: "POLICY:TOOL_BINDINGS_STRICT".to_string(),
            };
        }

        // 2. Direct Network Denial Check
        if manifest.get("DIRECT_NETWORK") == Some("DENY") {
            let network_binaries = [
                "curl ", "wget ", "nc ", "ncat ", "socat ", "ssh ", "telnet ", "scp ",
            ];
            for bin in network_binaries {
                if arg_clean.contains(bin) {
                    return ToolCheckResult {
                        tool_name: tool_clean.to_string(),
                        decision: ToolDecision::Blocked,
                        risk_score: 95,
                        reason: format!(
                            "Command attempts direct network tool '{}', which violates DIRECT_NETWORK:DENY",
                            bin.trim()
                        ),
                        policy_reference: "POLICY:DIRECT_NETWORK_DENY".to_string(),
                    };
                }
            }

            if arg_clean.contains("/dev/tcp/") || arg_clean.contains("/dev/udp/") {
                return ToolCheckResult {
                    tool_name: tool_clean.to_string(),
                    decision: ToolDecision::Blocked,
                    risk_score: 100,
                    reason: "Reverse shell socket redirection (/dev/tcp/) detected".to_string(),
                    policy_reference: "POLICY:REVERSE_SHELL_GUARD".to_string(),
                };
            }
        }

        // 3. Destructive Filesystem Command Check
        let destructive_patterns = [
            "rm -rf /",
            "rm -rf *",
            "mkfs",
            "dd if=",
            ":(){ :|:& };:",
            "wipefs",
            "> /dev/sda",
        ];
        for pattern in destructive_patterns {
            if arg_clean.contains(pattern) {
                return ToolCheckResult {
                    tool_name: tool_clean.to_string(),
                    decision: ToolDecision::Blocked,
                    risk_score: 100,
                    reason: format!(
                        "Destructive command pattern '{}' detected. Immediate safety block.",
                        pattern
                    ),
                    policy_reference: "POLICY:DESTRUCTIVE_EXECUTION_GUARD".to_string(),
                };
            }
        }

        // 4. Sensitive Secret Access Check
        let sensitive_paths = [
            "/etc/shadow",
            "/etc/passwd",
            ".ssh/id_",
            ".aws/credentials",
            ".kube/config",
            ".env",
        ];
        for path in sensitive_paths {
            if arg_clean.contains(path) {
                return ToolCheckResult {
                    tool_name: tool_clean.to_string(),
                    decision: ToolDecision::Blocked,
                    risk_score: 90,
                    reason: format!(
                        "Unauthorized attempt to access sensitive secret or system file: '{}'",
                        path
                    ),
                    policy_reference: "POLICY:SECRET_EXFILTRATION_GUARD".to_string(),
                };
            }
        }

        // 5. URL Scheme Verification for Web Tools (FETCH / SEARCH)
        if (tool_clean.eq_ignore_ascii_case("FETCH") || tool_clean.eq_ignore_ascii_case("SEARCH"))
            && (arg_clean.starts_with("file://") || arg_clean.starts_with("gopher://"))
        {
            return ToolCheckResult {
                tool_name: tool_clean.to_string(),
                decision: ToolDecision::Blocked,
                risk_score: 80,
                reason:
                    "Unsupported or insecure protocol (file://, gopher://) in web research tool"
                        .to_string(),
                policy_reference: "POLICY:URL_SCHEME_VALIDATION".to_string(),
            };
        }

        // Tool call approved
        ToolCheckResult {
            tool_name: tool_clean.to_string(),
            decision: ToolDecision::Allowed,
            risk_score: 10,
            reason: "Tool call conforms to Zero-Trust policy constraints".to_string(),
            policy_reference: "POLICY:CONFORMANCE_PASSED".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse_manifest;

    #[test]
    fn test_blocks_destructive_commands() {
        let manifest = parse_manifest(include_str!("../examples/research.jfp")).unwrap();
        let result = ToolGate::evaluate(&manifest, "SEARCH", "rm -rf /");
        assert_eq!(result.decision, ToolDecision::Blocked);
        assert!(result.reason.contains("Destructive command"));
    }

    #[test]
    fn test_blocks_unauthorized_tools() {
        let manifest = parse_manifest(include_str!("../examples/research.jfp")).unwrap();
        let result = ToolGate::evaluate(&manifest, "BASH_EXECUTE", "ls -la");
        assert_eq!(result.decision, ToolDecision::Blocked);
        assert!(result.reason.contains("not registered"));
    }

    #[test]
    fn test_blocks_network_bypass_when_direct_network_denied() {
        let manifest = parse_manifest(include_str!("../examples/research.jfp")).unwrap();
        let result = ToolGate::evaluate(&manifest, "SEARCH", "curl http://malicious.com");
        assert_eq!(result.decision, ToolDecision::Blocked);
        assert!(result.reason.contains("DIRECT_NETWORK:DENY"));
    }

    #[test]
    fn test_allows_valid_research_tool() {
        let manifest = parse_manifest(include_str!("../examples/research.jfp")).unwrap();
        let result = ToolGate::evaluate(&manifest, "SEARCH", "rust web frameworks benchmark");
        assert_eq!(result.decision, ToolDecision::Allowed);
    }
}
