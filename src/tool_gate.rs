// Copyright (c) 2026 jarohull-ai. All rights reserved.
// Licensed under the PolyForm Noncommercial License 1.0.0 or Commercial License.

//! Hardened runtime tool-call safety interceptor and MCP firewall gate.
//!
//! Provides defense-in-depth inspection of proposed agent commands and tool invocations,
//! with strict lexical tokenization, whitespace normalization, destructive execution
//! detection, network bypass mitigation, socket interception, and exact-match tool bindings.

use super::Manifest;
use serde::{Deserialize, Serialize};

/// Result decision for an intercepted tool call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ToolDecision {
    /// Tool call conforms strictly to policy constraints.
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
    /// Normalizes a command string by collapsing all unicode/ASCII whitespace
    /// (including tabs, newlines, carriage returns) into single spaces and lowercasing.
    pub fn normalize_command(input: &str) -> String {
        input
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
            .to_lowercase()
    }

    /// Tokenizes input into discrete shell words/tokens.
    pub fn tokenize_command(input: &str) -> Vec<String> {
        input
            .split_whitespace()
            .map(|s| s.to_lowercase())
            .collect()
    }

    /// Evaluates a proposed tool call against an active manifest policy.
    pub fn evaluate(manifest: &Manifest, tool_name: &str, argument: &str) -> ToolCheckResult {
        let tool_clean = tool_name.trim();
        let raw_arg = argument.trim();
        let norm_arg = Self::normalize_command(raw_arg);
        let tokens = Self::tokenize_command(raw_arg);

        // =========================================================================
        // 1. Destructive Filesystem and System Sabotage Check (Risk Score: 100)
        // =========================================================================

        // rm variations: "rm -rf /", "rm -rf .", "rm -r -f /", "rm --recursive --force /", "rm -rf *"
        let is_rm_destructive = {
            let has_rm = tokens.iter().any(|t| t == "rm" || t.ends_with("/rm"));
            let has_recursive = tokens.iter().any(|t| {
                t.contains('r') && t.starts_with('-') || t == "--recursive"
            });
            let has_force = tokens.iter().any(|t| {
                t.contains('f') && t.starts_with('-') || t == "--force"
            });
            let targets_critical = tokens.iter().any(|t| {
                *t == "/" || *t == "/*" || *t == "." || *t == ".*" || *t == "*" || *t == "~"
            });

            has_rm && (has_recursive || has_force) && targets_critical
        };

        if is_rm_destructive
            || norm_arg.contains("rm -rf /")
            || norm_arg.contains("rm -rf .")
            || norm_arg.contains("rm -rf *")
            || norm_arg.contains("rm -r -f /")
            || norm_arg.contains("rm -r -f .")
            || norm_arg.contains("rm -fr /")
            || norm_arg.contains("rm -fr .")
        {
            return ToolCheckResult {
                tool_name: tool_clean.to_string(),
                decision: ToolDecision::Blocked,
                risk_score: 100,
                reason: "Destructive filesystem recursive deletion pattern detected.".to_string(),
                policy_reference: "POLICY:DESTRUCTIVE_EXECUTION_GUARD".to_string(),
            };
        }

        // Low-level disk wipe, raw disk override, and filesystem destruction
        if norm_arg.contains("mkfs")
            || norm_arg.contains("wipefs")
            || norm_arg.contains("dd if=")
            || norm_arg.contains("dd of=/dev/")
            || norm_arg.contains("dd of = /dev/")
            || norm_arg.contains("> /dev/sd")
            || norm_arg.contains("> /dev/nvme")
            || norm_arg.contains(">/dev/sd")
            || norm_arg.contains(":(){ :|:& };:")
            || norm_arg.contains("chmod -r 777 /")
            || norm_arg.contains("chmod -r 000 /")
        {
            return ToolCheckResult {
                tool_name: tool_clean.to_string(),
                decision: ToolDecision::Blocked,
                risk_score: 100,
                reason: "Destructive device manipulation or fork-bomb pattern detected.".to_string(),
                policy_reference: "POLICY:DESTRUCTIVE_EXECUTION_GUARD".to_string(),
            };
        }

        // =========================================================================
        // 2. Direct Network Denial Check (Priority 2, Risk Score: 95-100)
        // =========================================================================
        if manifest.get("DIRECT_NETWORK") == Some("DENY") {
            // Check direct socket redirections (/dev/tcp, /dev/udp)
            if raw_arg.contains("/dev/tcp/")
                || raw_arg.contains("/dev/udp/")
                || norm_arg.contains("/dev/tcp/")
                || norm_arg.contains("/dev/udp/")
            {
                return ToolCheckResult {
                    tool_name: tool_clean.to_string(),
                    decision: ToolDecision::Blocked,
                    risk_score: 100,
                    reason: "Reverse shell socket redirection (/dev/tcp/) detected.".to_string(),
                    policy_reference: "POLICY:REVERSE_SHELL_GUARD".to_string(),
                };
            }

            // Check script-based socket connections (e.g. python -c "import socket", perl socket, ruby socket)
            if norm_arg.contains("import socket")
                || norm_arg.contains("socket.socket")
                || norm_arg.contains("io::socket")
                || norm_arg.contains("tcpsocket")
                || norm_arg.contains("net.dial")
            {
                return ToolCheckResult {
                    tool_name: tool_clean.to_string(),
                    decision: ToolDecision::Blocked,
                    risk_score: 100,
                    reason: "Script socket creation attempt detected under DIRECT_NETWORK:DENY.".to_string(),
                    policy_reference: "POLICY:SCRIPT_SOCKET_GUARD".to_string(),
                };
            }

            // Check network utilities by exact token match or path suffix
            let network_bins = [
                "curl", "wget", "nc", "netcat", "ncat", "socat", "ssh", "scp", "sftp", "telnet",
                "ftp", "rsync", "tftp", "nmap",
            ];

            for token in &tokens {
                let bin_name = token.rsplit('/').next().unwrap_or(token);
                if network_bins.contains(&bin_name) {
                    return ToolCheckResult {
                        tool_name: tool_clean.to_string(),
                        decision: ToolDecision::Blocked,
                        risk_score: 95,
                        reason: format!(
                            "Command attempts network tool '{}', which violates DIRECT_NETWORK:DENY",
                            bin_name
                        ),
                        policy_reference: "POLICY:DIRECT_NETWORK_DENY".to_string(),
                    };
                }
            }
        }

        // =========================================================================
        // 3. Sensitive Secret & Host Credential Access Check (Risk Score: 90)
        // =========================================================================
        let sensitive_targets = [
            "/etc/shadow",
            "/etc/passwd",
            ".ssh/id_",
            ".ssh/known_hosts",
            ".aws/credentials",
            ".aws/config",
            ".kube/config",
            ".env",
            "id_rsa",
            "id_ed25519",
        ];

        for target in sensitive_targets {
            if raw_arg.contains(target) || norm_arg.contains(target) {
                return ToolCheckResult {
                    tool_name: tool_clean.to_string(),
                    decision: ToolDecision::Blocked,
                    risk_score: 90,
                    reason: format!(
                        "Unauthorized attempt to access sensitive secret or credential: '{}'",
                        target
                    ),
                    policy_reference: "POLICY:SECRET_EXFILTRATION_GUARD".to_string(),
                };
            }
        }

        // =========================================================================
        // 4. URL Scheme Verification for Web Research Tools (FETCH / SEARCH)
        // =========================================================================
        if (tool_clean.eq_ignore_ascii_case("FETCH") || tool_clean.eq_ignore_ascii_case("SEARCH"))
            && (norm_arg.starts_with("file://")
                || norm_arg.starts_with("gopher://")
                || norm_arg.starts_with("php://")
                || norm_arg.starts_with("data://"))
        {
            return ToolCheckResult {
                tool_name: tool_clean.to_string(),
                decision: ToolDecision::Blocked,
                risk_score: 85,
                reason: "Insecure or local protocol scheme detected in web research tool"
                    .to_string(),
                policy_reference: "POLICY:URL_SCHEME_VALIDATION".to_string(),
            };
        }

        // =========================================================================
        // 5. Strict Structural TOOL_BINDINGS Check (Exact Match)
        // =========================================================================
        // We parse TOOL_BINDINGS as an exact list. Each entry is "TOOL_NAME->GATEWAY".
        // Partial substring matches (like 'MO' matching 'MODEL_GENERATE') are strictly REJECTED.
        let allowed_tools: Vec<String> = match manifest.list("TOOL_BINDINGS") {
            Ok(bindings) => bindings
                .into_iter()
                .filter_map(|binding| {
                    binding
                        .split_once("->")
                        .map(|(tool, _)| tool.trim().to_string())
                        .or_else(|| {
                            let trimmed = binding.trim();
                            if !trimmed.is_empty() {
                                Some(trimmed.to_string())
                            } else {
                                None
                            }
                        })
                })
                .collect(),
            Err(_) => Vec::new(),
        };

        let is_exactly_bound = allowed_tools
            .iter()
            .any(|t| t.eq_ignore_ascii_case(tool_clean));

        if !is_exactly_bound {
            return ToolCheckResult {
                tool_name: tool_clean.to_string(),
                decision: ToolDecision::Blocked,
                risk_score: 85,
                reason: format!(
                    "Tool '{}' is not registered in task TOOL_BINDINGS allowlist: [{}]",
                    tool_clean,
                    allowed_tools.join(", ")
                ),
                policy_reference: "POLICY:TOOL_BINDINGS_STRICT".to_string(),
            };
        }

        // =========================================================================
        // 6. Conformance Approved
        // =========================================================================
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
    fn test_audit_suite_8_of_8() {
        let manifest = parse_manifest(include_str!("../examples/research.jfp")).unwrap();

        // 1. rm -rf .
        let r1 = ToolGate::evaluate(&manifest, "SEARCH", "rm -rf .");
        assert_eq!(r1.decision, ToolDecision::Blocked, "rm -rf . must be blocked");

        // 2. rm -rf / with double space
        let r2 = ToolGate::evaluate(&manifest, "SEARCH", "rm  -rf /");
        assert_eq!(r2.decision, ToolDecision::Blocked, "rm  -rf / must be blocked");

        // 3. curl with tab
        let r3 = ToolGate::evaluate(&manifest, "SEARCH", "curl\thttp://evil.com");
        assert_eq!(r3.decision, ToolDecision::Blocked, "curl with tab must be blocked");

        // 4. dd of=/dev/sda
        let r4 = ToolGate::evaluate(&manifest, "SEARCH", "dd of=/dev/sda");
        assert_eq!(r4.decision, ToolDecision::Blocked, "dd of=/dev/sda must be blocked");

        // 5. cat .env
        let r5 = ToolGate::evaluate(&manifest, "SEARCH", "cat .env");
        assert_eq!(r5.decision, ToolDecision::Blocked, "cat .env must be blocked");

        // 6. wget http://x
        let r6 = ToolGate::evaluate(&manifest, "SEARCH", "wget http://x");
        assert_eq!(r6.decision, ToolDecision::Blocked, "wget http://x must be blocked");

        // 7. mkfs.ext4 /dev/sdb1
        let r7 = ToolGate::evaluate(&manifest, "SEARCH", "mkfs.ext4 /dev/sdb1");
        assert_eq!(r7.decision, ToolDecision::Blocked, "mkfs.ext4 must be blocked");

        // 8. python3 -c 'import socket'
        let r8 = ToolGate::evaluate(&manifest, "SEARCH", "python3 -c 'import socket'");
        assert_eq!(r8.decision, ToolDecision::Blocked, "python socket must be blocked");
    }

    #[test]
    fn test_exact_tool_binding_rejection() {
        let manifest = parse_manifest(include_str!("../examples/research.jfp")).unwrap();

        // In research.jfp: MODEL_GENERATE, SEARCH, FETCH are registered.
        // Partial substrings MUST be rejected!
        let r_mo = ToolGate::evaluate(&manifest, "MO", "echo hello");
        assert_eq!(r_mo.decision, ToolDecision::Blocked);
        assert!(r_mo.reason.contains("not registered in task TOOL_BINDINGS allowlist"));

        let r_searc = ToolGate::evaluate(&manifest, "SEARC", "echo hello");
        assert_eq!(r_searc.decision, ToolDecision::Blocked);
        assert!(r_searc.reason.contains("not registered in task TOOL_BINDINGS allowlist"));

        // Exact match must be accepted
        let r_valid = ToolGate::evaluate(&manifest, "SEARCH", "Rust Zero Trust");
        assert_eq!(r_valid.decision, ToolDecision::Allowed);
    }
}
