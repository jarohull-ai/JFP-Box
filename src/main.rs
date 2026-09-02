use std::env;
use std::fs;
use std::process::ExitCode;

use jfp_box::{
    json_report, now_rfc3339, parse_manifest, sha256_hex, validate, Manifest, Violation,
};

#[derive(Clone, Copy, PartialEq, Eq)]
enum OutputFormat {
    Human,
    Json,
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
                    eprintln!("- {}: {}", error.code(), error.message());
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
