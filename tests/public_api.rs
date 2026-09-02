use jfp_box::{json_report, parse_manifest, sha256_hex, validate};

#[test]
fn exposes_policy_validation_as_a_library_api() {
    let source = include_str!("../examples/offline.jfp");
    let manifest = parse_manifest(source).expect("golden fixture syntax must be valid");
    let violations = validate(&manifest);

    assert!(violations.is_empty());

    let report = json_report(
        Some(&manifest),
        &violations,
        &sha256_hex(source.as_bytes()),
        "2026-09-02T08:20:00Z",
    );
    assert!(report.contains("\"plan_status\":\"PLAN_ACCEPTED\""));
    assert!(report.contains("\"manifest_spec_version\":\"0.1\""));
}
