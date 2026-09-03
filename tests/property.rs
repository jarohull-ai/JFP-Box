use jfp_box::{parse_manifest, validate};
use proptest::prelude::*;

proptest! {
    #[test]
    fn arbitrary_utf8_never_panics(input in any::<String>()) {
        let _ = parse_manifest(&input);
    }

    #[test]
    fn arbitrary_bytes_never_panic_after_lossy_decode(input in prop::collection::vec(any::<u8>(), 0..8192)) {
        let decoded = String::from_utf8_lossy(&input);
        let _ = parse_manifest(&decoded);
    }
}

#[test]
fn direct_network_allow_is_never_accepted() {
    let source = include_str!("../examples/research.jfp")
        .replace("F:DIRECT_NETWORK:DENY;", "F:DIRECT_NETWORK:ALLOW;");
    let manifest = parse_manifest(&source).expect("fixture remains syntactically valid");
    assert!(validate(&manifest)
        .iter()
        .any(|v| v.code() == "ERR_DIRECT_NETWORK"));
}

#[test]
fn offline_with_gateway_is_never_accepted() {
    let source = include_str!("../examples/offline.jfp").replace(
        "F:ALLOWED_GATEWAYS:[];",
        "F:ALLOWED_GATEWAYS:[MODEL:VIPER_LOCAL_OLLAMA_V1];",
    );
    let manifest = parse_manifest(&source).expect("fixture remains syntactically valid");
    assert!(validate(&manifest)
        .iter()
        .any(|v| v.code() == "ERR_OFFLINE_HAS_GATEWAYS"));
}
