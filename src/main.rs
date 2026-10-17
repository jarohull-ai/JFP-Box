// Copyright (c) 2026 jarohull-ai. All rights reserved.
// Licensed under the PolyForm Noncommercial License 1.0.0 or Commercial License.

use std::env;
use std::fs;
use std::process::ExitCode;

use jfp_box::{
    json_report, manifest_to_json, manifest_to_yaml, now_rfc3339, parse_auto_manifest, sha256_hex,
    validate, Manifest, McpGateway, PolicyExplainer, ToolDecision, ToolGate, Violation,
};

#[derive(Clone, Copy, PartialEq, Eq)]
enum OutputFormat {
    Human,
    Json,
    Markdown,
}

enum Command {
    Plan {
        format: OutputFormat,
        path: String,
        explain: bool,
    },
    Explain {
        format: OutputFormat,
        path: String,
    },
    Convert {
        path: String,
        target_format: String,
    },
    CheckTool {
        manifest_path: String,
        tool: String,
        arg: String,
    },
    McpProxy {
        manifest_path: String,
    },
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
            println!("- {}: {}", error.code(), error.message());
        }
    }
}

fn usage() {
    eprintln!(
        "JFP Box v{} - Universal Policy Gate and Zero-Trust Guardrail for AI Agents",
        env!("CARGO_PKG_VERSION")
    );
    eprintln!();
    eprintln!("Usage:");
    eprintln!("  jfp-box plan [--format human|json|markdown] [--explain] <manifest.yaml|json|jfp>");
    eprintln!("  jfp-box explain [--format human|json|markdown] <manifest>");
    eprintln!("  jfp-box convert <manifest> --to yaml|json|jfp");
    eprintln!("  jfp-box check-tool --manifest <manifest> --tool <tool_name> [--arg <argument>]");
    eprintln!("  jfp-box mcp-proxy --manifest <manifest>");
    eprintln!();
    eprintln!("Options:");
    eprintln!("  --format <fmt>  Output format: human (default), json, or markdown");
    eprintln!("  --explain       Include executive risk and plain-English violation analysis");
    eprintln!("  --version       Display version information");
    eprintln!("  --help          Display this help message");
}

fn parse_cli(arguments: &[String]) -> Result<Command, String> {
    let subcommand = arguments
        .first()
        .map(String::as_str)
        .ok_or_else(|| "expected a subcommand (plan, explain, convert, check-tool, mcp-proxy)".to_owned())?;

    match subcommand {
        "plan" => {
            let mut format = OutputFormat::Human;
            let mut path = None;
            let mut explain = false;
            let mut index = 1;

            while index < arguments.len() {
                match arguments[index].as_str() {
                    "--format" => {
                        index += 1;
                        let Some(value) = arguments.get(index) else {
                            return Err("--format requires human, json, or markdown".to_owned());
                        };
                        format = match value.as_str() {
                            "human" => OutputFormat::Human,
                            "json" => OutputFormat::Json,
                            "markdown" | "md" => OutputFormat::Markdown,
                            _ => return Err("--format accepts human, json, or markdown".to_owned()),
                        };
                    }
                    "--explain" => {
                        explain = true;
                    }
                    value if value.starts_with('-') => {
                        return Err(format!("unknown option: {value}"))
                    }
                    value if path.is_none() => path = Some(value.to_owned()),
                    value => return Err(format!("unexpected argument: {value}")),
                }
                index += 1;
            }

            let path = path.ok_or_else(|| "manifest path is required".to_owned())?;
            Ok(Command::Plan {
                format,
                path,
                explain,
            })
        }
        "explain" => {
            let mut format = OutputFormat::Human;
            let mut path = None;
            let mut index = 1;

            while index < arguments.len() {
                match arguments[index].as_str() {
                    "--format" => {
                        index += 1;
                        let Some(value) = arguments.get(index) else {
                            return Err("--format requires human, json, or markdown".to_owned());
                        };
                        format = match value.as_str() {
                            "human" => OutputFormat::Human,
                            "json" => OutputFormat::Json,
                            "markdown" | "md" => OutputFormat::Markdown,
                            _ => return Err("--format accepts human, json, or markdown".to_owned()),
                        };
                    }
                    value if value.starts_with('-') => {
                        return Err(format!("unknown option: {value}"))
                    }
                    value if path.is_none() => path = Some(value.to_owned()),
                    value => return Err(format!("unexpected argument: {value}")),
                }
                index += 1;
            }

            let path = path.ok_or_else(|| "manifest path is required".to_owned())?;
            Ok(Command::Explain { format, path })
        }
        "convert" => {
            let mut path = None;
            let mut target_format = None;
            let mut index = 1;

            while index < arguments.len() {
                match arguments[index].as_str() {
                    "--to" => {
                        index += 1;
                        target_format = arguments.get(index).cloned();
                    }
                    value if value.starts_with('-') => {
                        return Err(format!("unknown option: {value}"))
                    }
                    value if path.is_none() => path = Some(value.to_owned()),
                    value => return Err(format!("unexpected argument: {value}")),
                }
                index += 1;
            }

            let path = path.ok_or_else(|| "source manifest path is required".to_owned())?;
            let target_format = target_format
                .ok_or_else(|| "--to <yaml|json|jfp> is required for convert".to_owned())?;
            Ok(Command::Convert {
                path,
                target_format,
            })
        }
        "check-tool" => {
            let mut manifest_path = None;
            let mut tool = None;
            let mut arg = String::new();
            let mut index = 1;

            while index < arguments.len() {
                match arguments[index].as_str() {
                    "--manifest" | "-m" => {
                        index += 1;
                        manifest_path = arguments.get(index).cloned();
                    }
                    "--tool" | "-t" => {
                        index += 1;
                        tool = arguments.get(index).cloned();
                    }
                    "--arg" | "--command" | "-a" => {
                        index += 1;
                        if let Some(val) = arguments.get(index) {
                            arg = val.clone();
                        }
                    }
                    value if value.starts_with('-') => {
                        return Err(format!("unknown option: {value}"))
                    }
                    value if manifest_path.is_none() => manifest_path = Some(value.to_owned()),
                    value => return Err(format!("unexpected argument: {value}")),
                }
                index += 1;
            }

            let manifest_path =
                manifest_path.ok_or_else(|| "--manifest <path> is required".to_owned())?;
            let tool = tool.ok_or_else(|| "--tool <tool_name> is required".to_owned())?;
            Ok(Command::CheckTool {
                manifest_path,
                tool,
                arg,
            })
        }
        "mcp-proxy" => {
            let mut manifest_path = None;
            let mut index = 1;

            while index < arguments.len() {
                match arguments[index].as_str() {
                    "--manifest" | "-m" => {
                        index += 1;
                        manifest_path = arguments.get(index).cloned();
                    }
                    value if value.starts_with('-') => {
                        return Err(format!("unknown option: {value}"))
                    }
                    value if manifest_path.is_none() => manifest_path = Some(value.to_owned()),
                    value => return Err(format!("unexpected argument: {value}")),
                }
                index += 1;
            }

            let manifest_path =
                manifest_path.ok_or_else(|| "--manifest <path> is required".to_owned())?;
            Ok(Command::McpProxy { manifest_path })
        }
        other => Err(format!(
            "unknown subcommand '{other}'. Expected plan, explain, convert, check-tool, or mcp-proxy"
        )),
    }
}

fn read_manifest_file(path: &str) -> Result<(Vec<u8>, String, String, String), ExitCode> {
    let bytes = match fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("cannot read {path}: {e}");
            return Err(ExitCode::from(2));
        }
    };
    let manifest_sha256 = sha256_hex(&bytes);
    let generated_at = now_rfc3339();
    let input = match std::str::from_utf8(&bytes) {
        Ok(s) => s.to_string(),
        Err(_) => {
            eprintln!("ERR_INVALID_ENCODING: manifest must be valid UTF-8 text");
            return Err(ExitCode::from(1));
        }
    };
    Ok((bytes, manifest_sha256, generated_at, input))
}

fn main() -> ExitCode {
    let arguments: Vec<String> = env::args().skip(1).collect();
    if arguments.as_slice() == ["--version"] || arguments.as_slice() == ["-v"] {
        println!("jfp-box {}", env!("CARGO_PKG_VERSION"));
        return ExitCode::SUCCESS;
    }
    if arguments.is_empty() || arguments.as_slice() == ["--help"] || arguments.as_slice() == ["-h"]
    {
        usage();
        return ExitCode::SUCCESS;
    }

    let command = match parse_cli(&arguments) {
        Ok(cmd) => cmd,
        Err(error) => {
            usage();
            eprintln!("error: {error}");
            return ExitCode::from(2);
        }
    };

    match command {
        Command::Plan {
            format,
            path,
            explain,
        } => {
            let (_bytes, manifest_sha256, generated_at, input) = match read_manifest_file(&path) {
                Ok(data) => data,
                Err(code) => return code,
            };

            let manifest = match parse_auto_manifest(&input) {
                Ok(m) => m,
                Err(errors) => {
                    if format == OutputFormat::Json {
                        print_json_report(None, &errors, &manifest_sha256, &generated_at);
                    } else {
                        eprintln!("JFP Box policy simulation\nstatus: PLAN_REJECTED\nexecution: NOT_STARTED\nsyntax violations:");
                        for error in errors {
                            eprintln!("- {}: {}", error.code(), error.message());
                        }
                    }
                    return ExitCode::from(1);
                }
            };

            let errors = validate(&manifest);

            if explain {
                let explanation = PolicyExplainer::explain(&manifest, &errors);
                match format {
                    OutputFormat::Json => {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&explanation).unwrap_or_default()
                        );
                    }
                    OutputFormat::Markdown => {
                        println!("{}", PolicyExplainer::render_markdown(&explanation));
                    }
                    OutputFormat::Human => {
                        println!("{}", PolicyExplainer::render_human(&explanation));
                    }
                }
            } else {
                match format {
                    OutputFormat::Json => {
                        print_json_report(
                            Some(&manifest),
                            &errors,
                            &manifest_sha256,
                            &generated_at,
                        );
                    }
                    OutputFormat::Markdown => {
                        let explanation = PolicyExplainer::explain(&manifest, &errors);
                        println!("{}", PolicyExplainer::render_markdown(&explanation));
                    }
                    OutputFormat::Human => {
                        print_report(&manifest, &errors);
                    }
                }
            }

            if errors.is_empty() {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            }
        }
        Command::Explain { format, path } => {
            let (_bytes, manifest_sha256, generated_at, input) = match read_manifest_file(&path) {
                Ok(data) => data,
                Err(code) => return code,
            };

            let manifest = match parse_auto_manifest(&input) {
                Ok(m) => m,
                Err(errors) => {
                    if format == OutputFormat::Json {
                        print_json_report(None, &errors, &manifest_sha256, &generated_at);
                    } else {
                        eprintln!("JFP Box policy simulation\nstatus: PLAN_REJECTED\nexecution: NOT_STARTED\nsyntax violations:");
                        for error in errors {
                            eprintln!("- {}: {}", error.code(), error.message());
                        }
                    }
                    return ExitCode::from(1);
                }
            };

            let errors = validate(&manifest);
            let explanation = PolicyExplainer::explain(&manifest, &errors);

            match format {
                OutputFormat::Json => {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&explanation).unwrap_or_default()
                    );
                }
                OutputFormat::Markdown => {
                    println!("{}", PolicyExplainer::render_markdown(&explanation));
                }
                OutputFormat::Human => {
                    println!("{}", PolicyExplainer::render_human(&explanation));
                }
            }

            if errors.is_empty() {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            }
        }
        Command::Convert {
            path,
            target_format,
        } => {
            let (_bytes, _hash, _time, input) = match read_manifest_file(&path) {
                Ok(data) => data,
                Err(code) => return code,
            };

            let manifest = match parse_auto_manifest(&input) {
                Ok(m) => m,
                Err(errors) => {
                    eprintln!("Cannot convert malformed manifest:");
                    for error in errors {
                        eprintln!("- {}: {}", error.code(), error.message());
                    }
                    return ExitCode::from(1);
                }
            };

            match target_format.to_lowercase().as_str() {
                "yaml" | "yml" => {
                    println!("{}", manifest_to_yaml(&manifest));
                }
                "json" => {
                    println!("{}", manifest_to_json(&manifest));
                }
                "jfp" => {
                    for (k, v) in manifest.all_fields() {
                        println!("F:{k}:{v};");
                    }
                }
                other => {
                    eprintln!("unsupported target format '{other}'. Choose yaml, json, or jfp.");
                    return ExitCode::from(2);
                }
            }
            ExitCode::SUCCESS
        }
        Command::CheckTool {
            manifest_path,
            tool,
            arg,
        } => {
            let (_bytes, _hash, _time, input) = match read_manifest_file(&manifest_path) {
                Ok(data) => data,
                Err(code) => return code,
            };

            let manifest = match parse_auto_manifest(&input) {
                Ok(m) => m,
                Err(errors) => {
                    eprintln!("Policy manifest is invalid:");
                    for error in errors {
                        eprintln!("- {}: {}", error.code(), error.message());
                    }
                    return ExitCode::from(1);
                }
            };

            let result = ToolGate::evaluate(&manifest, &tool, &arg);

            println!("\n🛡️  JFP BOX TOOL-CALL INTERCEPTOR VERDICT");
            println!(
                "================================================================================"
            );
            println!("🔧 Proposed Tool:       {}", result.tool_name);
            println!("📝 Arguments / Command:  \"{}\"", arg);
            println!("⚖️  Gate Decision:        {}", result.decision);
            println!("🎯 Risk Score:          {}/100", result.risk_score);
            println!("📜 Policy Reference:    {}", result.policy_reference);
            println!("💬 Evaluation Reason:   {}", result.reason);
            println!("================================================================================\n");

            if result.decision == ToolDecision::Allowed {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            }
        }
        Command::McpProxy { manifest_path } => {
            use std::io::{self, BufRead};

            let (_bytes, _hash, _time, input) = match read_manifest_file(&manifest_path) {
                Ok(data) => data,
                Err(code) => return code,
            };

            let manifest = match parse_auto_manifest(&input) {
                Ok(m) => m,
                Err(errors) => {
                    eprintln!("Policy manifest is invalid:");
                    for error in errors {
                        eprintln!("- {}: {}", error.code(), error.message());
                    }
                    return ExitCode::from(1);
                }
            };

            eprintln!("🛡️ JFP-Box MCP Zero-Trust Security Proxy active for policy: {}", manifest_path);
            eprintln!("Listening for JSON-RPC messages on STDIN...");

            let stdin = io::stdin();
            for line in stdin.lock().lines() {
                let line_str = match line {
                    Ok(l) => l,
                    Err(_) => break,
                };

                match McpGateway::intercept(&manifest, &line_str) {
                    Ok(Some(blocked_resp)) => {
                        // Print blocked response back to MCP client
                        if let Ok(json_out) = serde_json::to_string(&blocked_resp) {
                            println!("{}", json_out);
                        }
                    }
                    Ok(None) => {
                        // Pass-through or allowed
                        eprintln!("[JFP-Box Pass-Through] {}", line_str);
                    }
                    Err(err) => {
                        eprintln!("[JFP-Box Error] {}", err);
                    }
                }
            }
            ExitCode::SUCCESS
        }
    }
}
