// Copyright (c) 2026 jarohull-ai. All rights reserved.
// Licensed under the PolyForm Noncommercial License 1.0.0 or Commercial License.

//! Universal policy parser supporting YAML, JSON, and legacy JFP formats.

use super::{parse_manifest, Manifest, Violation};
use std::collections::BTreeMap;

/// Automatically detect policy format (JSON, YAML, or JFP) and parse into a [`Manifest`].
pub fn parse_auto_manifest(input: &str) -> Result<Manifest, Vec<Violation>> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(vec![Violation::new(
            "ERR_EMPTY_MANIFEST",
            "manifest content is empty",
        )]);
    }

    // JSON format starts with `{`
    if trimmed.starts_with('{') {
        return parse_json_manifest(trimmed);
    }

    // Legacy JFP format has lines starting with `F:` or comments `#` followed by `F:`
    let has_jfp_directive = trimmed
        .lines()
        .map(str::trim)
        .any(|l| l.starts_with("F:") && l.ends_with(';'));

    if has_jfp_directive {
        return parse_manifest(input);
    }

    // Otherwise, treat as YAML (standard in modern agent systems)
    parse_yaml_manifest(trimmed)
}

/// Parses a JSON-formatted policy into a [`Manifest`].
pub fn parse_json_manifest(json_str: &str) -> Result<Manifest, Vec<Violation>> {
    let value: serde_json::Value = serde_json::from_str(json_str).map_err(|e| {
        vec![Violation::new(
            "ERR_SYNTAX_JSON",
            format!("malformed JSON manifest: {}", e),
        )]
    })?;

    manifest_from_json_value(value)
}

/// Parses a YAML-formatted policy into a [`Manifest`].
pub fn parse_yaml_manifest(yaml_str: &str) -> Result<Manifest, Vec<Violation>> {
    let value: serde_yaml::Value = serde_yaml::from_str(yaml_str).map_err(|e| {
        vec![Violation::new(
            "ERR_SYNTAX_YAML",
            format!("malformed YAML manifest: {}", e),
        )]
    })?;

    // Convert YAML Value to JSON Value for unified normalization
    let json_value: serde_json::Value = serde_json::to_value(value).map_err(|e| {
        vec![Violation::new(
            "ERR_SYNTAX_YAML",
            format!("failed to convert YAML: {}", e),
        )]
    })?;

    manifest_from_json_value(json_value)
}

/// Normalizes JSON key-values into canonical JFP Manifest uppercase fields.
fn manifest_from_json_value(value: serde_json::Value) -> Result<Manifest, Vec<Violation>> {
    let map = match value {
        serde_json::Value::Object(m) => m,
        _ => {
            return Err(vec![Violation::new(
                "ERR_SYNTAX",
                "policy root must be a dictionary/object",
            )])
        }
    };

    let mut fields = BTreeMap::new();

    for (k, v) in map {
        process_key_value(&k, &v, &mut fields);
    }

    // Check for duplicate or conflicting keys
    Ok(Manifest { fields })
}

fn process_key_value(key: &str, value: &serde_json::Value, fields: &mut BTreeMap<String, String>) {
    // If the key is a nested group (e.g. "budget", "limits", "metadata"), flatten its children
    if let serde_json::Value::Object(nested) = value {
        for (sub_k, sub_v) in nested {
            process_key_value(sub_k, sub_v, fields);
        }
        return;
    }

    let canonical_key = normalize_key(key);

    let string_value = match value {
        serde_json::Value::String(s) => s.trim().to_string(),
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::Bool(b) => {
            if *b {
                "TRUE".to_string()
            } else {
                "FALSE".to_string()
            }
        }
        serde_json::Value::Array(arr) => {
            let items: Vec<String> = arr
                .iter()
                .filter_map(|item| match item {
                    serde_json::Value::String(s) => Some(s.trim().to_string()),
                    serde_json::Value::Number(n) => Some(n.to_string()),
                    _ => None,
                })
                .collect();
            format!("[{}]", items.join(","))
        }
        serde_json::Value::Null => return,
        _ => return,
    };

    if !string_value.is_empty() {
        fields.insert(canonical_key, string_value);
    }
}

/// Normalizes human-friendly snake_case / camelCase keys to canonical uppercase JFP keys.
fn normalize_key(raw_key: &str) -> String {
    let upper = raw_key.trim().to_ascii_uppercase();
    match upper.as_str() {
        "SPEC_VERSION" | "VERSION" => "SPEC_VERSION".to_string(),
        "TASK_ID" | "TASK" | "ID" => "TASK_ID".to_string(),
        "BOX_ID" | "BOX" => "BOX_ID".to_string(),
        "AUDIT_TRACE_ID" | "TRACE_ID" => "AUDIT_TRACE_ID".to_string(),
        "NETWORK_MODE" | "MODE" => "NETWORK_MODE".to_string(),
        "DIRECT_NETWORK" => "DIRECT_NETWORK".to_string(),
        "ALLOWED_GATEWAYS" | "GATEWAYS" => "ALLOWED_GATEWAYS".to_string(),
        "TOOL_BINDINGS" | "TOOLS" | "BINDINGS" => "TOOL_BINDINGS".to_string(),
        "EVIDENCE_CLASS" | "EVIDENCE" => "EVIDENCE_CLASS".to_string(),
        "OUTPUT_SCHEMA" | "SCHEMA" => "OUTPUT_SCHEMA".to_string(),
        "GATEWAY_POLICY_ID" | "POLICY_ID" | "GATEWAY_POLICY" => "GATEWAY_POLICY_ID".to_string(),
        "WRITE_MODE" | "WRITE" => "WRITE_MODE".to_string(),
        "MAX_MODEL_TOKENS" | "TOKENS" | "MAX_TOKENS" => "MAX_MODEL_TOKENS".to_string(),
        "MODEL_COST_BUDGET_USD" | "BUDGET_USD" | "COST_BUDGET" | "MAX_COST_USD" => {
            "MODEL_COST_BUDGET_USD".to_string()
        }
        "MAX_RESEARCH_REQUESTS" | "MAX_REQUESTS" => "MAX_RESEARCH_REQUESTS".to_string(),
        "MAX_FETCH_BYTES" | "MAX_FETCH" => "MAX_FETCH_BYTES".to_string(),
        "MAX_TOTAL_EVIDENCE_BYTES" | "MAX_EVIDENCE_BYTES" => "MAX_TOTAL_EVIDENCE_BYTES".to_string(),
        "MAX_REDIRECTS" | "REDIRECTS" => "MAX_REDIRECTS".to_string(),
        "MAX_DOMAINS" | "DOMAINS" => "MAX_DOMAINS".to_string(),
        "ALLOWED_CONTENT_TYPES" | "CONTENT_TYPES" => "ALLOWED_CONTENT_TYPES".to_string(),
        other => other.to_string(),
    }
}

/// Converts a [`Manifest`] into clean YAML format.
pub fn manifest_to_yaml(manifest: &Manifest) -> String {
    let mut root = serde_json::Map::new();

    for (k, v) in manifest.all_fields() {
        let key_lower = k.to_lowercase();
        if v.starts_with('[') && v.ends_with(']') {
            let inner = &v[1..v.len() - 1];
            let items: Vec<serde_json::Value> = inner
                .split(',')
                .map(|s| serde_json::Value::String(s.trim().to_string()))
                .filter(|s| !s.as_str().unwrap_or("").is_empty())
                .collect();
            root.insert(key_lower, serde_json::Value::Array(items));
        } else if let Ok(num) = v.parse::<i64>() {
            root.insert(key_lower, serde_json::Value::Number(num.into()));
        } else {
            root.insert(key_lower, serde_json::Value::String(v.to_string()));
        }
    }

    serde_yaml::to_string(&root).unwrap_or_default()
}

/// Converts a [`Manifest`] into clean JSON format.
pub fn manifest_to_json(manifest: &Manifest) -> String {
    let mut root = serde_json::Map::new();

    for (k, v) in manifest.all_fields() {
        let key_lower = k.to_lowercase();
        if v.starts_with('[') && v.ends_with(']') {
            let inner = &v[1..v.len() - 1];
            let items: Vec<serde_json::Value> = inner
                .split(',')
                .map(|s| serde_json::Value::String(s.trim().to_string()))
                .filter(|s| !s.as_str().unwrap_or("").is_empty())
                .collect();
            root.insert(key_lower, serde_json::Value::Array(items));
        } else if let Ok(num) = v.parse::<i64>() {
            root.insert(key_lower, serde_json::Value::Number(num.into()));
        } else {
            root.insert(key_lower, serde_json::Value::String(v.to_string()));
        }
    }

    serde_json::to_string_pretty(&root).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::validate;

    #[test]
    fn test_parse_yaml_policy() {
        let yaml = r#"
spec_version: "0.1"
task_id: "OSINT_YAML_001"
box_id: "BOX_YAML_001"
audit_trace_id: "8f85f02a-0f3a-4b8e-9f93-8cc8d5cf8b3a"
network_mode: "RESEARCH"
direct_network: "DENY"
allowed_gateways:
  - "MODEL:VIPER_LOCAL_OLLAMA_V1"
  - "RESEARCH:PUBLIC_WEB_READONLY_V1"
tool_bindings:
  - "MODEL_GENERATE->MODEL:VIPER_LOCAL_OLLAMA_V1"
  - "SEARCH->RESEARCH:PUBLIC_WEB_READONLY_V1"
  - "FETCH->RESEARCH:PUBLIC_WEB_READONLY_V1"
evidence_class: "UNTRUSTED"
output_schema: "EVIDENCE_REPORT_V1"
gateway_policy_id: "OSINT_PUBLIC_WEB_V1"
write_mode: "PATCH_ONLY"
max_model_tokens: 12000
model_cost_budget_usd: 0.02
max_research_requests: 30
max_fetch_bytes: "5M"
max_total_evidence_bytes: "25M"
max_redirects: 3
max_domains: 10
allowed_content_types:
  - "text/html"
  - "application/pdf"
"#;

        let manifest = parse_yaml_manifest(yaml).expect("YAML parsing should succeed");
        let violations = validate(&manifest);
        assert!(
            violations.is_empty(),
            "YAML manifest should be accepted: {:?}",
            violations
        );
        assert_eq!(manifest.get("TASK_ID"), Some("OSINT_YAML_001"));
        assert_eq!(manifest.get("NETWORK_MODE"), Some("RESEARCH"));
    }

    #[test]
    fn test_parse_json_policy() {
        let json = r#"{
  "spec_version": "0.1",
  "task_id": "OFFLINE_JSON_001",
  "box_id": "BOX_OFFLINE_01",
  "audit_trace_id": "b3678c7c-1cb8-49a4-a9f5-4a272506b3a8",
  "network_mode": "OFFLINE_STRICT",
  "direct_network": "DENY",
  "allowed_gateways": [],
  "tool_bindings": [],
  "evidence_class": "UNTRUSTED",
  "output_schema": "DIFF_PATCH_V1",
  "gateway_policy_id": "OFFLINE_V1",
  "write_mode": "PATCH_ONLY"
}"#;

        let manifest = parse_json_manifest(json).expect("JSON parsing should succeed");
        let violations = validate(&manifest);
        assert!(
            violations.is_empty(),
            "JSON manifest should be accepted: {:?}",
            violations
        );
        assert_eq!(manifest.get("NETWORK_MODE"), Some("OFFLINE_STRICT"));
    }
}
