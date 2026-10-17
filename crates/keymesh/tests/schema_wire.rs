//! Golden JSON API/schema compatibility and safe opaque extension roundtrips.
use keymesh::{
    AlgorithmProfile, CAPABILITY_SCHEMA_VERSION, CapabilityError, CryptoOperation,
    ExportRequirement, ExtensionProfile, OperationIntent, PayloadDescriptor, ProviderCapabilities,
};
use serde_json::{Value, json};
use std::collections::BTreeMap;

const GOLDEN: &str = include_str!("../../../tests/fixtures/capability_schema_v1.json");

#[test]
fn golden_capability_schema_v1_deserializes_and_roundtrips_losslessly() {
    let parsed: ProviderCapabilities =
        serde_json::from_str(GOLDEN).unwrap_or_else(|e| panic!("capability fixture invalid: {e}"));
    assert_eq!(parsed.schema_version, CAPABILITY_SCHEMA_VERSION);
    assert_eq!(parsed.entries.len(), 7);
    assert!(parsed.validate().is_ok());
    let serialized = serde_json::to_string(&parsed)
        .unwrap_or_else(|e| panic!("golden fixture serialize failed: {e}"));
    let canonical: ProviderCapabilities = serde_json::from_str(&serialized)
        .unwrap_or_else(|e| panic!("golden fixture roundtrip failed: {e}"));
    assert_eq!(parsed, canonical);
    let golden_json: Value =
        serde_json::from_str(GOLDEN).unwrap_or_else(|e| panic!("invalid JSON value: {e}"));
    let roundtrip_json: Value =
        serde_json::from_str(&serialized).unwrap_or_else(|e| panic!("invalid emitted JSON: {e}"));
    assert_eq!(golden_json, roundtrip_json);
}
#[test]
fn explicitly_namespaced_unknown_extension_values_preserved() {
    let mut params = BTreeMap::new();
    params.insert("dialect".to_string(), "future_10".to_string());
    params.insert("new_parameter".to_string(), "opaque_value_18".to_string());
    let extension = AlgorithmProfile::Extension(ExtensionProfile {
        namespace: "net.future".into(),
        identifier: "algorithm_42".into(),
        parameters: params,
    });
    let encoded =
        serde_json::to_string(&extension).unwrap_or_else(|e| panic!("serialization failed: {e}"));
    let parsed: AlgorithmProfile = serde_json::from_str(&encoded)
        .unwrap_or_else(|e| panic!("extension roundtrip failed: {e}"));
    assert_eq!(extension, parsed);
    assert!(parsed.validate().is_ok());
}
#[test]
fn unknown_top_level_algorithm_or_operation_discriminator_is_rejected() {
    let unknown = json!({"family":"remote_magic_algo","parameters":{"alpha":"new"}});
    assert!(serde_json::from_value::<AlgorithmProfile>(unknown).is_err());
    let unknown = json!({"type":"digest_or_raw_auto","details":{"hash":"sha256"}});
    assert!(serde_json::from_value::<CryptoOperation>(unknown).is_err());
}
#[test]
fn backward_incompatible_or_unknown_capability_schema_fails_closed() {
    let mut source: Value =
        serde_json::from_str(GOLDEN).unwrap_or_else(|e| panic!("fixture JSON failed: {e}"));
    source["schema_version"] = json!(2);
    let parsed: ProviderCapabilities =
        serde_json::from_value(source).unwrap_or_else(|e| panic!("schema parse failed: {e}"));
    assert_eq!(parsed.validate(), Err(CapabilityError::InvalidCatalog));
}
#[test]
fn schema_rejects_unexpected_provider_response_fields() {
    let mut source: Value =
        serde_json::from_str(GOLDEN).unwrap_or_else(|e| panic!("fixture JSON failed: {e}"));
    source["private_key"] = json!("DO_NOT_COPY_SECRETS");
    assert!(serde_json::from_value::<ProviderCapabilities>(source).is_err());
}
#[test]
fn request_schema_serialization_preserves_input_form_and_exact_binding() {
    let input = json!({
        "operation":{"type":"sign_digest","details":{"digest":"sha256"}},
        "profile":{"family":"rsa_pss","parameters":{
            "modulus_bits":3072,"digest":"sha256","mgf1_digest":"sha256","salt_bytes":32
        }},
        "payload":{"form":"digest","parameters":{"algorithm":"sha256","bytes":32}},
        "binding":"provider_version",
        "protection":"hsm",
        "export":"none"
    });
    let request: OperationIntent = serde_json::from_value(input.clone())
        .unwrap_or_else(|e| panic!("request parse failed: {e}"));
    assert!(request.validate().is_ok());
    assert_eq!(
        serde_json::to_value(&request).unwrap_or_else(|e| panic!("{e}")),
        input
    );
    let mut mutated = request;
    mutated.payload = PayloadDescriptor::Message { bytes: 32 };
    assert!(mutated.validate().is_err());
}
#[test]
fn neither_unknown_extensions_nor_implicit_private_export_can_be_dispatched() {
    let source: ProviderCapabilities =
        serde_json::from_str(GOLDEN).unwrap_or_else(|e| panic!("fixture invalid: {e}"));
    let extension_entry = source
        .entries
        .last()
        .unwrap_or_else(|| panic!("missing test extension"))
        .clone();
    let request = OperationIntent {
        operation: extension_entry.operation,
        profile: extension_entry.profile,
        payload: PayloadDescriptor::None,
        binding: keymesh::VersionRequirement::ProviderVersion,
        protection: keymesh::ProtectionRequirement::Any,
        export: ExportRequirement::None,
    };
    let host = keymesh::HostValidatedCapabilities {
        version_model: Some(keymesh::VersionModel::ProviderVersion),
        ..Default::default()
    };
    assert_eq!(
        source.admit(&request, &host),
        Err(CapabilityError::ExtensionNotPermitted)
    );
    let mut allow_ext = host;
    allow_ext.permit_extensions = true;
    assert_eq!(
        source.admit(&request, &allow_ext),
        Err(CapabilityError::UnknownCapability)
    );
}
#[test]
fn error_types_are_redacted_and_never_echo_credentials() {
    let mut source: Value = serde_json::from_str(GOLDEN).unwrap_or_else(|e| panic!("{e}"));
    source["feature_revision"] = json!("PRIVATE_TOKEN_DO_NOT_ECHO");
    let bad: ProviderCapabilities =
        serde_json::from_value(source).unwrap_or_else(|e| panic!("{e}"));
    let e = match bad.validate() {
        Ok(()) => panic!("secret-like provider revision unexpectedly accepted"),
        Err(error) => error,
    };
    assert!(!format!("{e:?} {e}").contains("PRIVATE_TOKEN_DO_NOT_ECHO"));
}
