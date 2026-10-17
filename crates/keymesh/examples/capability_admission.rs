//! Executable no-cryptography demonstration of capability admission and version binding.
use keymesh::{
    AlgorithmProfile, CapabilityEntry, CryptoOperation, DigestAlgorithm, DispatchTarget,
    ExportRequirement, Exportability, HostScope, HostValidatedCapabilities, KeyRef, KeySelector,
    LogicalKeyId, OperationIntent, PayloadDescriptor, ProtectionClass, ProtectionRequirement,
    ProviderCapabilities, ProviderInstanceId, ProviderNamespace, ProviderResourceId,
    ProviderVersionId, RequiredAssurance, ResolvedKey, SupportStatus, VersionModel,
    VersionRequirement, CAPABILITY_SCHEMA_VERSION, preflight_bind,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // This is a mock *contract* only. The host must authenticate tenant context
    // and verify custody/version claims before constructing host evidence.
    let provider = ProviderInstanceId::parse("mock-hsm")?;
    let namespace = ProviderNamespace::parse("tenant-a")?;
    let key = LogicalKeyId::parse("payments")?;
    let resource = ProviderResourceId::parse("mock:hsm:payments")?;
    let version = ProviderVersionId::parse("v7")?;

    let profile = AlgorithmProfile::RsaPss {
        modulus_bits: 3072,
        digest: DigestAlgorithm::Sha256,
        mgf1_digest: DigestAlgorithm::Sha256,
        salt_bytes: 32,
    };
    let operation = CryptoOperation::SignDigest {
        digest: DigestAlgorithm::Sha256,
    };
    let catalog = ProviderCapabilities {
        schema_version: CAPABILITY_SCHEMA_VERSION,
        protocol_revision: "fixture.r1".into(),
        feature_revision: "fixture.v1".into(),
        reported_protection: ProtectionClass::Hsm,
        reported_version_model: VersionModel::ProviderVersion,
        reported_exportability: Exportability::None,
        attestation_claims: Vec::new(),
        entries: vec![CapabilityEntry {
            operation: operation.clone(),
            profile: profile.clone(),
            support: SupportStatus::Supported,
            max_input_bytes: Some(32),
        }],
    };
    let request = OperationIntent {
        operation,
        profile,
        payload: PayloadDescriptor::Digest {
            algorithm: DigestAlgorithm::Sha256,
            bytes: 32,
        },
        binding: VersionRequirement::ProviderVersion,
        protection: ProtectionRequirement::Hsm,
        export: ExportRequirement::None,
    };
    let host = HostValidatedCapabilities {
        // In a real host, neither value may come from untrusted request text.
        protection: Some(ProtectionClass::Hsm),
        version_model: Some(VersionModel::ProviderVersion),
        permit_extensions: false,
        permit_private_export: false,
    };
    let admitted = catalog.admit(&request, &host)?;
    assert_eq!(admitted.max_input_bytes, Some(32));

    let reference = KeyRef::new(
        provider.clone(),
        namespace.clone(),
        key.clone(),
        KeySelector::ExactProviderVersion {
            resource: resource.clone(),
            version: version.clone(),
        },
    );
    let authorized = HostScope::new(provider.clone(), namespace.clone());
    let resolved = ResolvedKey::new(
        provider,
        namespace,
        key,
        DispatchTarget::ProviderVersion { resource, version },
    );
    let bound = preflight_bind(
        &reference,
        &authorized,
        &resolved,
        RequiredAssurance::ProviderVersion,
    )?;
    println!(
        "No-dispatch capability admitted; selected resource {}",
        bound.dispatch_target().resource()
    );
    println!("No key generation, signature, KMS call or attestation performed.");
    Ok(())
}
