// Copyright (c) 2026 jarohull-ai. All rights reserved.
// Licensed under the PolyForm Noncommercial License 1.0.0 or Commercial License.

//! Model Context Protocol (MCP) JSON-RPC Security Guard and Interceptor.
//!
//! Provides automated inspection of incoming MCP `tools/call` JSON-RPC messages
//! against active JFP Zero-Trust policies.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{Manifest, ToolDecision, ToolGate};

/// Standard JSON-RPC 2.0 Request envelope for MCP.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    /// JSON-RPC protocol version (must be "2.0").
    pub jsonrpc: String,
    /// Request identifier.
    #[serde(default)]
    pub id: Option<Value>,
    /// Remote method name (e.g. "tools/call", "tools/list", "initialize").
    pub method: String,
    /// Optional parameter payload.
    #[serde(default)]
    pub params: Option<Value>,
}

/// Standard JSON-RPC 2.0 Response envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcResponse {
    /// JSON-RPC version.
    pub jsonrpc: String,
    /// Request ID matching the incoming call.
    pub id: Option<Value>,
    /// Result payload if successful.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    /// Error payload if call failed or was blocked.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

/// Standard JSON-RPC 2.0 Error payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcError {
    /// Standard error code (e.g. -32600, -32000 for security violations).
    pub code: i32,
    /// Human-readable error message.
    pub message: String,
    /// Structured audit details.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

/// Security Gateway engine for Model Context Protocol interactions.
pub struct McpGateway;

impl McpGateway {
    /// Inspects an incoming JSON-RPC payload line.
    ///
    /// If the message is a `tools/call`, it verifies the requested tool and arguments
    /// against the provided policy manifest:
    /// - If blocked, it returns `Ok(Some(blocked_response))` with error code -32000.
    /// - If allowed or non-intercepted (e.g. `initialize`, `ping`), returns `Ok(None)`.
    /// - If invalid JSON, returns a standard parse error response.
    pub fn intercept(manifest: &Manifest, line: &str) -> Result<Option<JsonRpcResponse>, String> {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            return Ok(None);
        }

        let request: JsonRpcRequest = match serde_json::from_str(trimmed) {
            Ok(req) => req,
            Err(e) => {
                return Ok(Some(JsonRpcResponse {
                    jsonrpc: "2.0".to_string(),
                    id: None,
                    result: None,
                    error: Some(JsonRpcError {
                        code: -32700,
                        message: format!("Parse error: {}", e),
                        data: None,
                    }),
                }));
            }
        };

        if request.method == "tools/call" {
            if let Some(params) = request.params {
                let tool_name = params
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown_tool");

                let arg_summary = if let Some(args) = params.get("arguments") {
                    if let Some(cmd) = args.get("command").and_then(Value::as_str) {
                        cmd.to_string()
                    } else if let Some(query) = args.get("query").and_then(Value::as_str) {
                        query.to_string()
                    } else if let Some(url) = args.get("url").and_then(Value::as_str) {
                        url.to_string()
                    } else if let Some(path) = args.get("path").and_then(Value::as_str) {
                        path.to_string()
                    } else {
                        args.to_string()
                    }
                } else {
                    String::new()
                };

                let verdict = ToolGate::evaluate(manifest, tool_name, &arg_summary);

                if verdict.decision == ToolDecision::Blocked {
                    let error_data = serde_json::json!({
                        "security_gate": "JFP-Box Zero-Trust",
                        "verdict": "BLOCKED",
                        "risk_score": verdict.risk_score,
                        "policy_reference": verdict.policy_reference,
                        "reason": verdict.reason,
                    });

                    return Ok(Some(JsonRpcResponse {
                        jsonrpc: "2.0".to_string(),
                        id: request.id,
                        result: None,
                        error: Some(JsonRpcError {
                            code: -32000,
                            message: format!("JFP-Box Security Block: {}", verdict.reason),
                            data: Some(error_data),
                        }),
                    }));
                }
            }
        }

        // Allowed or informational message
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse_auto_manifest;

    #[test]
    fn test_mcp_gateway_blocks_destructive_call() {
        let policy_yaml = r#"
task_id: TEST_MCP_001
box_id: BOX_001
audit_trace_id: TRACE_001
network_mode: OFFLINE_STRICT
direct_network: DENY
allowed_gateways: []
tool_bindings: []
evidence_class: UNTRUSTED
output_schema: jfp-box.result.v0.1
gateway_policy_id: OFFLINE_V1
write_mode: PATCH_ONLY
"#;
        let manifest = parse_auto_manifest(policy_yaml).unwrap();

        let malicious_rpc = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"bash","arguments":{"command":"rm -rf /"}}}"#;
        let intercept_res = McpGateway::intercept(&manifest, malicious_rpc).unwrap();

        assert!(intercept_res.is_some());
        let resp = intercept_res.unwrap();
        assert!(resp.error.is_some());
        let err = resp.error.unwrap();
        assert_eq!(err.code, -32000);
        assert!(err.message.contains("Destructive"));
    }

    #[test]
    fn test_mcp_gateway_allows_benign_call() {
        let policy_yaml = r#"
task_id: TEST_MCP_002
box_id: BOX_002
audit_trace_id: TRACE_002
network_mode: RESEARCH
direct_network: DENY
allowed_gateways: [MODEL:VIPER_LOCAL_OLLAMA_V1, RESEARCH:PUBLIC_WEB_READONLY_V1]
tool_bindings: [MODEL_GENERATE->MODEL:VIPER_LOCAL_OLLAMA_V1, SEARCH->RESEARCH:PUBLIC_WEB_READONLY_V1, FETCH->RESEARCH:PUBLIC_WEB_READONLY_V1]
evidence_class: UNTRUSTED
output_schema: jfp-box.result.v0.1
gateway_policy_id: OSINT_PUBLIC_WEB_V1
write_mode: PATCH_ONLY
max_model_tokens: 100000
model_cost_budget_usd: 1.00
max_research_requests: 10
max_fetch_bytes: 1M
max_total_evidence_bytes: 5M
max_redirects: 3
max_domains: 5
allowed_content_types: [text/html]
"#;
        let manifest = parse_auto_manifest(policy_yaml).unwrap();

        let safe_rpc = r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"SEARCH","arguments":{"query":"Rust Zero-Trust"}}}"#;
        let intercept_res = McpGateway::intercept(&manifest, safe_rpc).unwrap();

        assert!(intercept_res.is_none());
    }
}
