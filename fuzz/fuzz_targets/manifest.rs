#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Exercise both UTF-8 parsing and arbitrary-byte handling. Invalid UTF-8
    // is converted lossily so every fuzzer input reaches the parser without
    // introducing a harness panic.
    let input = String::from_utf8_lossy(data);
    let _ = jfp_box::parse_manifest(&input);
});
