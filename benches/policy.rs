use criterion::{black_box, criterion_group, criterion_main, Criterion};
use jfp_box::{json_report, parse_manifest, sha256_hex, validate};

const OFFLINE: &str = include_str!("../examples/offline.jfp");
const RESEARCH: &str = include_str!("../examples/research.jfp");

fn benchmark_parse(c: &mut Criterion) {
    c.bench_function("parse/research", |bench| {
        bench.iter(|| parse_manifest(black_box(RESEARCH)).expect("fixture has valid syntax"));
    });
}

fn benchmark_validate(c: &mut Criterion) {
    let manifest = parse_manifest(RESEARCH).expect("fixture has valid syntax");
    c.bench_function("validate/research", |bench| {
        bench.iter(|| black_box(validate(black_box(&manifest))));
    });
}

fn benchmark_json_report(c: &mut Criterion) {
    let manifest = parse_manifest(OFFLINE).expect("fixture has valid syntax");
    let errors = validate(&manifest);
    let hash = sha256_hex(OFFLINE.as_bytes());
    c.bench_function("report_json/offline", |bench| {
        bench.iter(|| {
            black_box(json_report(
                Some(black_box(&manifest)),
                black_box(&errors),
                black_box(&hash),
                "2026-09-02T08:20:00Z",
            ))
        });
    });
}

criterion_group!(
    policy_benchmarks,
    benchmark_parse,
    benchmark_validate,
    benchmark_json_report
);
criterion_main!(policy_benchmarks);
