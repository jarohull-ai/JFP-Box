use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

const MODES: [&str; 4] = [
    "OFFLINE_STRICT",
    "MODEL_ONLY",
    "RESEARCH",
    "NETWORK_RESTRICTED",
];
const KNOWN_GATEWAYS: [&str; 3] = [
    "MODEL:VIPER_LOCAL_OLLAMA_V1",
    "RESEARCH:PUBLIC_WEB_READONLY_V1",
    "API:APPROVED_READONLY_V1",
];
const GATEWAY_POLICY_MODES: [(&str, &str); 4] = [
    ("OFFLINE_V1", "OFFLINE_STRICT"),
    ("MODEL_LOCAL_V1", "MODEL_ONLY"),
    ("OSINT_PUBLIC_WEB_V1", "RESEARCH"),
    ("APPROVED_API_V1", "NETWORK_RESTRICTED"),
];
const MODEL_LIMIT_FIELDS: [&str; 2] = ["MAX_MODEL_TOKENS", "MODEL_COST_BUDGET_USD"];
const RESEARCH_LIMIT_FIELDS: [&str; 6] = [
    "MAX_RESEARCH_REQUESTS",
    "MAX_FETCH_BYTES",
    "MAX_TOTAL_EVIDENCE_BYTES",
    "MAX_REDIRECTS",
    "MAX_DOMAINS",
    "ALLOWED_CONTENT_TYPES",
];
const RUNNER_RESERVED_FIELDS: [&str; 5] = [
    "MAX_ACTIVE_BOXES",
    "BOX_TTL_MAX",
    "BOX_TOKEN_BUDGET",
    "UI_CONFIRM_REQUIRED",
    "THREAT_PROFILE",
];
const ALLOWED_FIELDS: [&str; 25] = [
    "SPEC_VERSION",
    "TASK_ID",
    "BOX_ID",
    "AUDIT_TRACE_ID",
    "NETWORK_MODE",
    "DIRECT_NETWORK",
    "ALLOWED_GATEWAYS",
    "TOOL_BINDINGS",
    "EVIDENCE_CLASS",
    "OUTPUT_SCHEMA",
    "GATEWAY_POLICY_ID",
    "WRITE_MODE",
    "MAX_MODEL_TOKENS",
    "MODEL_COST_BUDGET_USD",
    "MAX_RESEARCH_REQUESTS",
    "MAX_FETCH_BYTES",
    "MAX_TOTAL_EVIDENCE_BYTES",
    "MAX_REDIRECTS",
    "MAX_DOMAINS",
    "ALLOWED_CONTENT_TYPES",
    "MAX_ACTIVE_BOXES",
    "BOX_TTL_MAX",
    "BOX_TOKEN_BUDGET",
    "UI_CONFIRM_REQUIRED",
    "THREAT_PROFILE",
];

#[derive(Debug, Clone, PartialEq, Eq)]
struct Violation {
    code: String,
    field: Option<String>,
    message: String,
}

impl Violation {
    fn new(code: &str, message: impl Into<String>) -> Self {
        Self {
            code: code.to_owned(),
            field: None,
            message: message.into(),
        }
    }

    fn for_field(code: &str, field: &str, message: impl Into<String>) -> Self {
        Self {
            code: code.to_owned(),
            field: Some(field.to_owned()),
            message: message.into(),
        }
    }

    fn field(&self) -> Option<&str> {
        if let Some(field) = self.field.as_deref() {
            return Some(field);
        }
        match self.code.as_str() {
            "ERR_DIRECT_NETWORK" => Some("DIRECT_NETWORK"),
            "ERR_EVIDENCE_CLASS" => Some("EVIDENCE_CLASS"),
            "ERR_WRITE_MODE" => Some("WRITE_MODE"),
            "ERR_UNSUPPORTED_VERSION" => Some("SPEC_VERSION"),
            "ERR_INVALID_NETWORK_MODE" => Some("NETWORK_MODE"),
            "ERR_UNKNOWN_GATEWAY" | "ERR_DUPLICATE_GATEWAY" | "ERR_OFFLINE_HAS_GATEWAYS" => {
                Some("ALLOWED_GATEWAYS")
            }
            "ERR_INVALID_TOOL_BINDINGS"
            | "ERR_INVALID_TOOL_BINDING"
            | "ERR_DUPLICATE_TOOL_BINDING"
            | "ERR_BINDING_GATEWAY_NOT_ALLOWED"
            | "ERR_TOOL_GATEWAY_TYPE"
            | "ERR_UNSUPPORTED_TOOL" => Some("TOOL_BINDINGS"),
            "ERR_MISSING_RESEARCH_GATEWAY" | "ERR_MISSING_MODEL_GATEWAY" => {
                Some("ALLOWED_GATEWAYS")
            }
            "ERR_EVIDENCE_LIMIT_CONFLICT" => Some("MAX_TOTAL_EVIDENCE_BYTES"),
            "ERR_UNKNOWN_GATEWAY_POLICY" | "ERR_POLICY_MODE_MISMATCH" => Some("GATEWAY_POLICY_ID"),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum OutputFormat {
    Human,
    Json,
}

#[derive(Debug)]
struct Manifest {
    fields: BTreeMap<String, String>,
}

impl Manifest {
    fn get(&self, key: &str) -> Option<&str> {
        self.fields.get(key).map(String::as_str)
    }

    fn list(&self, key: &str) -> Result<Vec<String>, String> {
        self.get(key)
            .ok_or_else(|| "field is missing".to_owned())
            .and_then(parse_list)
    }
}

fn parse_manifest(input: &str) -> Result<Manifest, Vec<Violation>> {
    let mut fields = BTreeMap::new();
    let mut errors = Vec::new();
    for (line_number, raw_line) in input.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if !line.starts_with("F:") || !line.ends_with(';') {
            errors.push(Violation::new(
                "ERR_SYNTAX",
                format!("line {}: expected F:KEY:VALUE;", line_number + 1),
            ));
            continue;
        }
        let body = &line[2..line.len() - 1];
        let Some((key, value)) = body.split_once(':') else {
            errors.push(Violation::new(
                "ERR_SYNTAX",
                format!("line {}: field has no value", line_number + 1),
            ));
            continue;
        };
        let key = key.trim();
        let value = value.trim();
        if key.is_empty() || value.is_empty() {
            errors.push(Violation::new(
                "ERR_SYNTAX",
                format!("line {}: empty key or value", line_number + 1),
            ));
            continue;
        }
        if !key
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
        {
            errors.push(Violation::new(
                "ERR_SYNTAX",
                format!(
                    "line {}: field names must use A-Z, 0-9, and _",
                    line_number + 1
                ),
            ));
            continue;
        }
        if fields.insert(key.to_owned(), value.to_owned()).is_some() {
            errors.push(Violation::new(
                "ERR_DUPLICATE_FIELD",
                format!("line {}: duplicate field {key}", line_number + 1),
            ));
        }
    }
    if errors.is_empty() {
        Ok(Manifest { fields })
    } else {
        Err(errors)
    }
}

fn parse_list(value: &str) -> Result<Vec<String>, String> {
    let value = value.trim();
    if !value.starts_with('[') || !value.ends_with(']') {
        return Err("expected [ITEM,ITEM] list".to_owned());
    }
    let body = value[1..value.len() - 1].trim();
    if body.is_empty() {
        return Ok(Vec::new());
    }
    let values: Vec<String> = body.split(',').map(|item| item.trim().to_owned()).collect();
    if values.iter().any(String::is_empty) {
        Err("list contains an empty item".to_owned())
    } else {
        Ok(values)
    }
}

fn require(manifest: &Manifest, key: &str, errors: &mut Vec<Violation>) {
    if manifest.get(key).is_none() {
        errors.push(Violation::new(
            "ERR_MISSING_FIELD",
            format!("missing required field: {key}"),
        ));
    }
}

fn parse_positive_u64(manifest: &Manifest, key: &str, errors: &mut Vec<Violation>) -> Option<u64> {
    let value = manifest.get(key)?;
    match value.parse::<u64>() {
        Ok(number) if number > 0 => Some(number),
        _ => {
            errors.push(Violation::new(
                "ERR_INVALID_LIMIT",
                format!("{key} must be a positive integer"),
            ));
            None
        }
    }
}

fn parse_size_bytes(manifest: &Manifest, key: &str, errors: &mut Vec<Violation>) -> Option<u64> {
    let value = manifest.get(key)?;
    let (number, multiplier) = match value.chars().last() {
        Some('K') => (&value[..value.len() - 1], 1_000),
        Some('M') => (&value[..value.len() - 1], 1_000_000),
        Some('G') => (&value[..value.len() - 1], 1_000_000_000),
        _ => (value, 1),
    };
    match number
        .parse::<u64>()
        .ok()
        .filter(|size| *size > 0)
        .and_then(|size| size.checked_mul(multiplier))
    {
        Some(size) => Some(size),
        None => {
            errors.push(Violation::new(
                "ERR_INVALID_LIMIT",
                format!("{key} must be a positive size such as 5M"),
            ));
            None
        }
    }
}

fn expected_mode_for_policy(policy: &str) -> Option<&'static str> {
    GATEWAY_POLICY_MODES
        .iter()
        .find_map(|(known_policy, mode)| (*known_policy == policy).then_some(*mode))
}

fn reject_orphaned_field(errors: &mut Vec<Violation>, field: &str, reason: &str) {
    errors.push(Violation::for_field(
        "ERR_ORPHANED_FIELD",
        field,
        format!("{field} is declared but has no active v0.1 consumer: {reason}"),
    ));
}

fn validate_field_consumers(
    manifest: &Manifest,
    mode: &str,
    bound_tools: &BTreeSet<&str>,
    errors: &mut Vec<Violation>,
) {
    if !bound_tools.contains("MODEL_GENERATE") {
        for field in MODEL_LIMIT_FIELDS {
            if manifest.get(field).is_some() {
                reject_orphaned_field(errors, field, "MODEL_GENERATE is not bound");
            }
        }
    }
    if mode != "RESEARCH" {
        for field in RESEARCH_LIMIT_FIELDS {
            if manifest.get(field).is_some() {
                reject_orphaned_field(errors, field, "NETWORK_MODE is not RESEARCH");
            }
        }
    }
    for field in RUNNER_RESERVED_FIELDS {
        if manifest.get(field).is_some() {
            reject_orphaned_field(
                errors,
                field,
                "the v0.1 validator has no live runner to enforce it",
            );
        }
    }
}

fn validate(manifest: &Manifest) -> Vec<Violation> {
    let mut errors = Vec::new();
    for key in manifest.fields.keys() {
        if !ALLOWED_FIELDS.contains(&key.as_str()) {
            errors.push(Violation::new(
                "ERR_UNKNOWN_FIELD",
                format!("field is not supported by JFP Box v0.1: {key}"),
            ));
        }
    }
    for key in [
        "SPEC_VERSION",
        "TASK_ID",
        "BOX_ID",
        "AUDIT_TRACE_ID",
        "NETWORK_MODE",
        "DIRECT_NETWORK",
        "ALLOWED_GATEWAYS",
        "TOOL_BINDINGS",
        "EVIDENCE_CLASS",
        "OUTPUT_SCHEMA",
        "GATEWAY_POLICY_ID",
        "WRITE_MODE",
    ] {
        require(manifest, key, &mut errors);
    }

    if manifest.get("SPEC_VERSION") != Some("0.1") {
        errors.push(Violation::new(
            "ERR_UNSUPPORTED_VERSION",
            "SPEC_VERSION must be 0.1",
        ));
    }
    if manifest.get("DIRECT_NETWORK") != Some("DENY") {
        errors.push(Violation::new(
            "ERR_DIRECT_NETWORK",
            "DIRECT_NETWORK must be DENY",
        ));
    }
    if manifest.get("EVIDENCE_CLASS") != Some("UNTRUSTED") {
        errors.push(Violation::new(
            "ERR_EVIDENCE_CLASS",
            "EVIDENCE_CLASS must be UNTRUSTED in v0.1",
        ));
    }
    if manifest.get("WRITE_MODE") != Some("PATCH_ONLY") {
        errors.push(Violation::new(
            "ERR_WRITE_MODE",
            "WRITE_MODE must be PATCH_ONLY in v0.1",
        ));
    }
    let mode = manifest.get("NETWORK_MODE").unwrap_or_default();
    if !MODES.contains(&mode) {
        errors.push(Violation::new(
            "ERR_INVALID_NETWORK_MODE",
            format!("NETWORK_MODE must be one of: {}", MODES.join(", ")),
        ));
    }
    if let Some(policy) = manifest.get("GATEWAY_POLICY_ID") {
        match expected_mode_for_policy(policy) {
            None => {
                errors.push(Violation::new(
                    "ERR_UNKNOWN_GATEWAY_POLICY",
                    format!("gateway policy is not registered: {policy}"),
                ));
            }
            Some(expected_mode) if MODES.contains(&mode) && mode != expected_mode => {
                errors.push(Violation::new(
                    "ERR_POLICY_MODE_MISMATCH",
                    format!("GATEWAY_POLICY_ID {policy} requires NETWORK_MODE {expected_mode}"),
                ));
            }
            Some(_) => {}
        }
    }

    let gateways = match manifest.list("ALLOWED_GATEWAYS") {
        Ok(items) => items,
        Err(reason) => {
            errors.push(Violation::new("ERR_INVALID_GATEWAY_LIST", reason));
            Vec::new()
        }
    };
    let gateway_set: BTreeSet<&str> = gateways.iter().map(String::as_str).collect();
    if gateway_set.len() != gateways.len() {
        errors.push(Violation::new(
            "ERR_DUPLICATE_GATEWAY",
            "ALLOWED_GATEWAYS contains a duplicate gateway",
        ));
    }
    for gateway in &gateways {
        if !KNOWN_GATEWAYS.contains(&gateway.as_str()) {
            errors.push(Violation::new(
                "ERR_UNKNOWN_GATEWAY",
                format!("gateway is not registered: {gateway}"),
            ));
        }
    }

    let bindings = match manifest.list("TOOL_BINDINGS") {
        Ok(items) => items,
        Err(reason) => {
            errors.push(Violation::new("ERR_INVALID_TOOL_BINDINGS", reason));
            Vec::new()
        }
    };
    let mut bound_tools = BTreeSet::new();
    for binding in &bindings {
        let Some((tool, gateway)) = binding.split_once("->") else {
            errors.push(Violation::new(
                "ERR_INVALID_TOOL_BINDING",
                format!("invalid tool binding: {binding}"),
            ));
            continue;
        };
        let tool = tool.trim();
        let gateway = gateway.trim();
        if !bound_tools.insert(tool) {
            errors.push(Violation::new(
                "ERR_DUPLICATE_TOOL_BINDING",
                format!("duplicate binding for tool: {tool}"),
            ));
        }
        if !gateway_set.contains(gateway) {
            errors.push(Violation::new(
                "ERR_BINDING_GATEWAY_NOT_ALLOWED",
                format!("binding {binding} points outside ALLOWED_GATEWAYS"),
            ));
        }
        let expected_type = match tool {
            "MODEL_GENERATE" => Some("MODEL:"),
            "SEARCH" | "FETCH" => Some("RESEARCH:"),
            "API_CALL" => Some("API:"),
            _ => None,
        };
        match expected_type {
            Some(prefix) if !gateway.starts_with(prefix) => errors.push(Violation::new(
                "ERR_TOOL_GATEWAY_TYPE",
                format!("binding {binding} requires a {prefix} gateway"),
            )),
            None => errors.push(Violation::new(
                "ERR_UNSUPPORTED_TOOL",
                format!("tool is not supported in v0.1: {tool}"),
            )),
            _ => {}
        }
    }

    if bound_tools.contains("MODEL_GENERATE") {
        require(manifest, "MAX_MODEL_TOKENS", &mut errors);
        require(manifest, "MODEL_COST_BUDGET_USD", &mut errors);
        if let Some(tokens) = parse_positive_u64(manifest, "MAX_MODEL_TOKENS", &mut errors) {
            if tokens > 200_000 {
                errors.push(Violation::new(
                    "ERR_LIMIT_EXCEEDED",
                    "MAX_MODEL_TOKENS may not exceed 200000 in v0.1",
                ));
            }
        }
        if let Some(cost) = manifest.get("MODEL_COST_BUDGET_USD") {
            if cost
                .parse::<f64>()
                .ok()
                .filter(|value| *value > 0.0)
                .is_none()
            {
                errors.push(Violation::new(
                    "ERR_INVALID_LIMIT",
                    "MODEL_COST_BUDGET_USD must be a positive number",
                ));
            }
        }
    }

    match mode {
        "OFFLINE_STRICT" if !gateways.is_empty() || !bindings.is_empty() => {
            errors.push(Violation::new(
                "ERR_OFFLINE_HAS_GATEWAYS",
                "OFFLINE_STRICT requires empty ALLOWED_GATEWAYS and TOOL_BINDINGS",
            ))
        }
        "MODEL_ONLY" => {
            if gateways.is_empty() || gateways.iter().any(|item| !item.starts_with("MODEL:")) {
                errors.push(Violation::new(
                    "ERR_MODEL_ONLY_GATEWAYS",
                    "MODEL_ONLY requires one or more MODEL gateways and no other gateway type",
                ));
            }
            if bound_tools != BTreeSet::from(["MODEL_GENERATE"]) {
                errors.push(Violation::new(
                    "ERR_MODEL_ONLY_TOOLS",
                    "MODEL_ONLY requires only MODEL_GENERATE in TOOL_BINDINGS",
                ));
            }
        }
        "RESEARCH" => {
            if !gateways.iter().any(|item| item.starts_with("MODEL:")) {
                errors.push(Violation::new(
                    "ERR_MISSING_MODEL_GATEWAY",
                    "RESEARCH requires a MODEL gateway",
                ));
            }
            if !gateways.iter().any(|item| item.starts_with("RESEARCH:")) {
                errors.push(Violation::new(
                    "ERR_MISSING_RESEARCH_GATEWAY",
                    "RESEARCH requires a RESEARCH gateway",
                ));
            }
            for tool in ["MODEL_GENERATE", "SEARCH", "FETCH"] {
                if !bound_tools.contains(tool) {
                    errors.push(Violation::new(
                        "ERR_MISSING_REQUIRED_TOOL",
                        format!("RESEARCH requires {tool} binding"),
                    ));
                }
            }
            validate_research_limits(manifest, &mut errors);
        }
        "NETWORK_RESTRICTED" if gateways.is_empty() => errors.push(Violation::new(
            "ERR_RESTRICTED_HAS_NO_GATEWAY",
            "NETWORK_RESTRICTED requires at least one registered gateway",
        )),
        _ => {}
    }

    validate_field_consumers(manifest, mode, &bound_tools, &mut errors);
    errors
}

fn validate_research_limits(manifest: &Manifest, errors: &mut Vec<Violation>) {
    for key in [
        "MAX_RESEARCH_REQUESTS",
        "MAX_FETCH_BYTES",
        "MAX_TOTAL_EVIDENCE_BYTES",
        "MAX_REDIRECTS",
        "MAX_DOMAINS",
        "ALLOWED_CONTENT_TYPES",
    ] {
        require(manifest, key, errors);
    }
    if let Some(requests) = parse_positive_u64(manifest, "MAX_RESEARCH_REQUESTS", errors) {
        if requests > 100 {
            errors.push(Violation::new(
                "ERR_LIMIT_EXCEEDED",
                "MAX_RESEARCH_REQUESTS may not exceed 100 in v0.1",
            ));
        }
    }
    let fetch_bytes = parse_size_bytes(manifest, "MAX_FETCH_BYTES", errors);
    let total_bytes = parse_size_bytes(manifest, "MAX_TOTAL_EVIDENCE_BYTES", errors);
    if let Some(fetch_bytes) = fetch_bytes {
        if !(4_000..=25_000_000).contains(&fetch_bytes) {
            errors.push(Violation::new(
                "ERR_LIMIT_EXCEEDED",
                "MAX_FETCH_BYTES must be between 4K and 25M",
            ));
        }
    }
    if let Some(total_bytes) = total_bytes {
        if total_bytes > 250_000_000 {
            errors.push(Violation::new(
                "ERR_LIMIT_EXCEEDED",
                "MAX_TOTAL_EVIDENCE_BYTES may not exceed 250M",
            ));
        }
    }
    if let (Some(fetch_bytes), Some(total_bytes)) = (fetch_bytes, total_bytes) {
        if total_bytes < fetch_bytes {
            errors.push(Violation::new(
                "ERR_EVIDENCE_LIMIT_CONFLICT",
                "MAX_TOTAL_EVIDENCE_BYTES must be at least MAX_FETCH_BYTES",
            ));
        }
    }
    if let Some(domains) = parse_positive_u64(manifest, "MAX_DOMAINS", errors) {
        if domains > 50 {
            errors.push(Violation::new(
                "ERR_LIMIT_EXCEEDED",
                "MAX_DOMAINS may not exceed 50 in v0.1",
            ));
        }
    }
    if let Some(value) = manifest.get("MAX_REDIRECTS") {
        if value
            .parse::<u64>()
            .ok()
            .filter(|value| *value <= 10)
            .is_none()
        {
            errors.push(Violation::new(
                "ERR_INVALID_LIMIT",
                "MAX_REDIRECTS must be an integer from 0 to 10",
            ));
        }
    }
    match manifest.list("ALLOWED_CONTENT_TYPES") {
        Ok(items) if !items.is_empty() => {}
        _ => errors.push(Violation::new(
            "ERR_INVALID_CONTENT_TYPES",
            "ALLOWED_CONTENT_TYPES must be a non-empty list",
        )),
    }
}

fn sha256_hex(input: &[u8]) -> String {
    const INITIAL: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];

    let bit_length = (input.len() as u64).wrapping_mul(8);
    let mut padded = input.to_vec();
    padded.push(0x80);
    while (padded.len() + 8) % 64 != 0 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_length.to_be_bytes());

    let mut hash = INITIAL;
    for chunk in padded.chunks_exact(64) {
        let mut words = [0u32; 64];
        for (index, bytes) in chunk.chunks_exact(4).take(16).enumerate() {
            words[index] = u32::from_be_bytes(bytes.try_into().expect("chunk has four bytes"));
        }
        for index in 16..64 {
            let small_sigma0 = words[index - 15].rotate_right(7)
                ^ words[index - 15].rotate_right(18)
                ^ (words[index - 15] >> 3);
            let small_sigma1 = words[index - 2].rotate_right(17)
                ^ words[index - 2].rotate_right(19)
                ^ (words[index - 2] >> 10);
            words[index] = words[index - 16]
                .wrapping_add(small_sigma0)
                .wrapping_add(words[index - 7])
                .wrapping_add(small_sigma1);
        }

        let mut state = hash;
        for index in 0..64 {
            let big_sigma1 =
                state[4].rotate_right(6) ^ state[4].rotate_right(11) ^ state[4].rotate_right(25);
            let choose = (state[4] & state[5]) ^ ((!state[4]) & state[6]);
            let temp1 = state[7]
                .wrapping_add(big_sigma1)
                .wrapping_add(choose)
                .wrapping_add(K[index])
                .wrapping_add(words[index]);
            let big_sigma0 =
                state[0].rotate_right(2) ^ state[0].rotate_right(13) ^ state[0].rotate_right(22);
            let majority = (state[0] & state[1]) ^ (state[0] & state[2]) ^ (state[1] & state[2]);
            let temp2 = big_sigma0.wrapping_add(majority);

            state = [
                temp1.wrapping_add(temp2),
                state[0],
                state[1],
                state[2],
                state[3].wrapping_add(temp1),
                state[4],
                state[5],
                state[6],
            ];
        }
        for index in 0..8 {
            hash[index] = hash[index].wrapping_add(state[index]);
        }
    }

    hash.iter().map(|word| format!("{word:08x}")).collect()
}

fn now_rfc3339() -> String {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let days = seconds.div_euclid(86_400);
    let seconds_of_day = seconds.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let hour = seconds_of_day / 3_600;
    let minute = (seconds_of_day % 3_600) / 60;
    let second = seconds_of_day % 60;
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

fn civil_from_days(days_since_unix_epoch: i64) -> (i64, i64, i64) {
    let days = days_since_unix_epoch + 719_468;
    let era = if days >= 0 { days } else { days - 146_096 } / 146_097;
    let day_of_era = days - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    (year + i64::from(month <= 2), month, day)
}

fn json_string(value: &str) -> String {
    let mut output = String::from("\"");
    for character in value.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            character if character.is_control() => {
                output.push_str(&format!("\\u{:04x}", character as u32))
            }
            character => output.push(character),
        }
    }
    output.push('"');
    output
}

fn json_optional(value: Option<&str>) -> String {
    value.map(json_string).unwrap_or_else(|| "null".to_owned())
}

fn json_report(
    manifest: Option<&Manifest>,
    errors: &[Violation],
    manifest_sha256: &str,
    generated_at: &str,
) -> String {
    let status = if errors.is_empty() {
        "PLAN_ACCEPTED"
    } else {
        "PLAN_REJECTED"
    };
    let errors = errors
        .iter()
        .map(|error| {
            format!(
                "{{\"code\":{},\"field\":{},\"message\":{}}}",
                json_string(&error.code),
                json_optional(error.field()),
                json_string(&error.message)
            )
        })
        .collect::<Vec<String>>()
        .join(",");
    format!(
        "{{\"validator_version\":{},\"manifest_spec_version\":{},\"plan_status\":{},\"errors\":[{}],\"audit_trace_id\":{},\"manifest_sha256\":{},\"generated_at\":{}}}",
        json_string(env!("CARGO_PKG_VERSION")),
        json_optional(manifest.and_then(|item| item.get("SPEC_VERSION"))),
        json_string(status),
        errors,
        json_optional(manifest.and_then(|item| item.get("AUDIT_TRACE_ID"))),
        json_string(manifest_sha256),
        json_string(generated_at),
    )
}

fn print_json_report(
    manifest: Option<&Manifest>,
    errors: &[Violation],
    manifest_sha256: &str,
    generated_at: &str,
) {
    println!(
        "{}",
        json_report(manifest, errors, manifest_sha256, generated_at)
    );
}

fn print_report(manifest: &Manifest, errors: &[Violation]) {
    println!("JFP Box policy simulation");
    println!(
        "status: {}",
        if errors.is_empty() {
            "PLAN_ACCEPTED"
        } else {
            "PLAN_REJECTED"
        }
    );
    for key in [
        "SPEC_VERSION",
        "TASK_ID",
        "BOX_ID",
        "AUDIT_TRACE_ID",
        "NETWORK_MODE",
    ] {
        if let Some(value) = manifest.get(key) {
            println!("{key}: {value}");
        }
    }
    println!("execution: NOT_STARTED");
    if errors.is_empty() {
        println!("policy: consistent; no process, mount, or network action was performed");
    } else {
        println!("violations:");
        for error in errors {
            println!("- {}: {}", error.code, error.message);
        }
    }
}

fn usage() {
    eprintln!("Usage: jfp-box plan [--format human|json] <manifest.jfp>");
}

fn parse_cli(arguments: &[String]) -> Result<(OutputFormat, String), String> {
    if arguments.first().map(String::as_str) != Some("plan") {
        return Err("expected plan subcommand".to_owned());
    }
    let mut format = OutputFormat::Human;
    let mut path = None;
    let mut index = 1;
    while index < arguments.len() {
        match arguments[index].as_str() {
            "--format" => {
                index += 1;
                let Some(value) = arguments.get(index) else {
                    return Err("--format requires human or json".to_owned());
                };
                format = match value.as_str() {
                    "human" => OutputFormat::Human,
                    "json" => OutputFormat::Json,
                    _ => return Err("--format accepts only human or json".to_owned()),
                };
            }
            value if value.starts_with('-') => return Err(format!("unknown option: {value}")),
            value if path.is_none() => path = Some(value.to_owned()),
            value => return Err(format!("unexpected argument: {value}")),
        }
        index += 1;
    }
    path.map(|path| (format, path))
        .ok_or_else(|| "manifest path is required".to_owned())
}

fn main() -> ExitCode {
    let arguments: Vec<String> = env::args().skip(1).collect();
    if arguments.as_slice() == ["--version"] {
        println!("jfp-box {}", env!("CARGO_PKG_VERSION"));
        return ExitCode::SUCCESS;
    }
    let (format, path) = match parse_cli(&arguments) {
        Ok(command) => command,
        Err(error) => {
            usage();
            eprintln!("error: {error}");
            return ExitCode::from(2);
        }
    };
    let bytes = match fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) => {
            eprintln!("cannot read {path}: {error}");
            return ExitCode::from(2);
        }
    };
    let manifest_sha256 = sha256_hex(&bytes);
    let generated_at = now_rfc3339();
    let input = match std::str::from_utf8(&bytes) {
        Ok(input) => input,
        Err(_) => {
            let errors = vec![Violation::new(
                "ERR_INVALID_ENCODING",
                "manifest must be valid UTF-8 text",
            )];
            if format == OutputFormat::Json {
                print_json_report(None, &errors, &manifest_sha256, &generated_at);
            } else {
                eprintln!("JFP Box policy simulation\nstatus: PLAN_REJECTED\nexecution: NOT_STARTED\nsyntax violations:");
                eprintln!("- ERR_INVALID_ENCODING: manifest must be valid UTF-8 text");
            }
            return ExitCode::from(1);
        }
    };
    let manifest = match parse_manifest(input) {
        Ok(manifest) => manifest,
        Err(errors) => {
            if format == OutputFormat::Json {
                print_json_report(None, &errors, &manifest_sha256, &generated_at);
            } else {
                eprintln!("JFP Box policy simulation\nstatus: PLAN_REJECTED\nexecution: NOT_STARTED\nsyntax violations:");
                for error in errors {
                    eprintln!("- {}: {}", error.code, error.message);
                }
            }
            return ExitCode::from(1);
        }
    };
    let errors = validate(&manifest);
    if format == OutputFormat::Json {
        print_json_report(Some(&manifest), &errors, &manifest_sha256, &generated_at);
    } else {
        print_report(&manifest, &errors);
    }
    if errors.is_empty() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest(input: &str) -> Manifest {
        parse_manifest(input).expect("fixture syntax must be valid")
    }
    fn codes(input: &str) -> BTreeSet<String> {
        validate(&manifest(input))
            .into_iter()
            .map(|violation| violation.code)
            .collect()
    }

    #[test]
    fn accepts_golden_fixtures() {
        for fixture in [
            include_str!("../examples/offline.jfp"),
            include_str!("../examples/model-only.jfp"),
            include_str!("../examples/research.jfp"),
            include_str!("../examples/network-restricted.jfp"),
        ] {
            assert!(validate(&manifest(fixture)).is_empty());
        }
    }

    #[test]
    fn rejects_offline_box_with_a_gateway() {
        assert!(codes(include_str!("../examples/invalid-offline.jfp"))
            .contains("ERR_OFFLINE_HAS_GATEWAYS"));
    }

    #[test]
    fn rejects_unregistered_gateway_and_shell_tool() {
        let fixture = include_str!("../examples/model-only.jfp")
            .replace("MODEL:VIPER_LOCAL_OLLAMA_V1", "MODEL:UNREGISTERED")
            .replace("MODEL_GENERATE", "SHELL_EXEC");
        let result = codes(&fixture);
        assert!(result.contains("ERR_UNKNOWN_GATEWAY"));
        assert!(result.contains("ERR_UNSUPPORTED_TOOL"));
    }

    #[test]
    fn rejects_direct_network_and_zero_research_budget() {
        let fixture = include_str!("../examples/research.jfp")
            .replace("F:DIRECT_NETWORK:DENY;", "F:DIRECT_NETWORK:ALLOW;")
            .replace("F:MAX_RESEARCH_REQUESTS:30;", "F:MAX_RESEARCH_REQUESTS:0;");
        let result = codes(&fixture);
        assert!(result.contains("ERR_DIRECT_NETWORK"));
        assert!(result.contains("ERR_INVALID_LIMIT"));
    }

    #[test]
    fn rejects_evidence_limit_conflict() {
        let fixture = include_str!("../examples/research.jfp").replace(
            "F:MAX_TOTAL_EVIDENCE_BYTES:25M;",
            "F:MAX_TOTAL_EVIDENCE_BYTES:1M;",
        );
        assert!(codes(&fixture).contains("ERR_EVIDENCE_LIMIT_CONFLICT"));
    }

    #[test]
    fn rejects_unknown_fields_and_duplicate_fields() {
        let duplicate = format!(
            "{}\nF:TASK_ID:SECOND;\n",
            include_str!("../examples/offline.jfp")
        );
        assert!(parse_manifest(&duplicate)
            .expect_err("duplicate field must fail syntax parsing")
            .iter()
            .any(|error| error.code == "ERR_DUPLICATE_FIELD"));
        let unknown = format!(
            "{}\nF:HOST_PATH:/home/jaro;\n",
            include_str!("../examples/offline.jfp")
        );
        assert!(codes(&unknown).contains("ERR_UNKNOWN_FIELD"));
    }

    #[test]
    fn rejects_every_invalid_gateway_policy_mode_pair() {
        let fixtures = [
            (include_str!("../examples/offline.jfp"), "OFFLINE_V1"),
            (include_str!("../examples/model-only.jfp"), "MODEL_LOCAL_V1"),
            (
                include_str!("../examples/research.jfp"),
                "OSINT_PUBLIC_WEB_V1",
            ),
            (
                include_str!("../examples/network-restricted.jfp"),
                "APPROVED_API_V1",
            ),
        ];

        for (fixture, expected_policy) in fixtures {
            for (policy, _) in GATEWAY_POLICY_MODES {
                if policy == expected_policy {
                    continue;
                }
                let mismatch = fixture.replace(
                    &format!("F:GATEWAY_POLICY_ID:{expected_policy};"),
                    &format!("F:GATEWAY_POLICY_ID:{policy};"),
                );
                assert!(
                    codes(&mismatch).contains("ERR_POLICY_MODE_MISMATCH"),
                    "{policy} must not validate with the fixture for {expected_policy}"
                );
            }
        }
    }

    #[test]
    fn rejects_every_optional_field_without_an_active_consumer() {
        let offline = include_str!("../examples/offline.jfp");
        let cases = [
            ("MAX_MODEL_TOKENS", "50000"),
            ("MODEL_COST_BUDGET_USD", "0.25"),
            ("MAX_RESEARCH_REQUESTS", "10"),
            ("MAX_FETCH_BYTES", "5M"),
            ("MAX_TOTAL_EVIDENCE_BYTES", "25M"),
            ("MAX_REDIRECTS", "3"),
            ("MAX_DOMAINS", "10"),
            ("ALLOWED_CONTENT_TYPES", "[text/html]"),
            ("MAX_ACTIVE_BOXES", "2"),
            ("BOX_TTL_MAX", "5M"),
            ("BOX_TOKEN_BUDGET", "12000"),
            ("UI_CONFIRM_REQUIRED", "TRUE"),
            ("THREAT_PROFILE", "P2"),
        ];

        for (field, value) in cases {
            let candidate = format!("{offline}\nF:{field}:{value};\n");
            let errors = validate(&manifest(&candidate));
            assert!(
                errors.iter().any(|error| {
                    error.code == "ERR_ORPHANED_FIELD" && error.field() == Some(field)
                }),
                "{field} must be rejected without an active consumer"
            );
        }
    }

    #[test]
    fn accepts_optional_fields_with_their_active_consumers() {
        for fixture in [
            include_str!("../examples/model-only.jfp"),
            include_str!("../examples/research.jfp"),
        ] {
            assert!(validate(&manifest(fixture))
                .iter()
                .all(|error| error.code != "ERR_ORPHANED_FIELD"));
        }
    }

    #[test]
    fn hashes_exact_manifest_bytes_with_sha256() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_ne!(
            sha256_hex(b"F:TASK_ID:ONE;\n"),
            sha256_hex(b"F:TASK_ID:ONE;\r\n")
        );
    }

    #[test]
    fn creates_stable_json_contract_for_accepted_plan() {
        let manifest = manifest(include_str!("../examples/offline.jfp"));
        let hash = sha256_hex(include_str!("../examples/offline.jfp").as_bytes());
        let report = json_report(Some(&manifest), &[], &hash, "2026-09-02T08:20:00Z");
        assert_eq!(
            report,
            format!(
                "{{\"validator_version\":\"0.1.2\",\"manifest_spec_version\":\"0.1\",\"plan_status\":\"PLAN_ACCEPTED\",\"errors\":[],\"audit_trace_id\":\"b3678c7c-1cb8-49a4-a9f5-4a272506b3a8\",\"manifest_sha256\":\"{hash}\",\"generated_at\":\"2026-09-02T08:20:00Z\"}}"
            )
        );
    }

    #[test]
    fn creates_json_error_with_code_field_and_message() {
        let manifest = manifest(include_str!("../examples/invalid-offline.jfp"));
        let errors = validate(&manifest);
        let report = json_report(Some(&manifest), &errors, "hash", "2026-09-02T08:20:00Z");
        assert!(report.contains("\"plan_status\":\"PLAN_REJECTED\""));
        assert!(report.contains("\"code\":\"ERR_OFFLINE_HAS_GATEWAYS\""));
        assert!(report.contains("\"field\":\"ALLOWED_GATEWAYS\""));
        assert!(report.contains(
            "\"message\":\"OFFLINE_STRICT requires empty ALLOWED_GATEWAYS and TOOL_BINDINGS\""
        ));
    }
}
