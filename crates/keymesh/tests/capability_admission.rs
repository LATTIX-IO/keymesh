//! FOSS-403 fail-closed provider capability admission tests.
use keymesh::{
    AlgorithmProfile as A, AttestationClaim, CAPABILITY_SCHEMA_VERSION, CapabilityEntry,
    CapabilityError, CryptoOperation as O, DigestAlgorithm as D, ExportRequirement, Exportability,
    HostScope, HostValidatedCapabilities, MAX_CAPABILITY_ENTRIES, OperationIntent,
    PayloadDescriptor as P, ProfileError, ProtectionClass, ProtectionRequirement,
    ProviderCapabilities, ProviderInstanceId, ProviderNamespace, SupportStatus, VersionModel,
    VersionRequirement,
};

fn rsa() -> A {
    A::RsaPss {
        modulus_bits: 3072,
        digest: D::Sha256,
        mgf1_digest: D::Sha256,
        salt_bytes: 32,
    }
}
fn capability(
    operation: O,
    profile: A,
    support: SupportStatus,
    limit: Option<u64>,
) -> CapabilityEntry {
    CapabilityEntry {
        operation,
        profile,
        support,
        max_input_bytes: limit,
    }
}
fn catalog() -> ProviderCapabilities {
    ProviderCapabilities {
        schema_version: CAPABILITY_SCHEMA_VERSION,
        provider_instance: "mock-hsm".into(),
        namespace: "tenant-a".into(),
        protocol_revision: "vault.transit.v1".into(),
        feature_revision: "fixture.r1".into(),
        reported_protection: ProtectionClass::Hsm,
        reported_version_model: VersionModel::ProviderVersion,
        reported_exportability: Exportability::PublicOnly,
        attestation_claims: vec![AttestationClaim {
            kind: "vendor_label".into(),
            source: "provider".into(),
            reference: "unverified.reference.1".into(),
        }],
        entries: vec![
            capability(
                O::SignDigest { digest: D::Sha256 },
                rsa(),
                SupportStatus::Supported,
                Some(32),
            ),
            capability(O::SignMessage, rsa(), SupportStatus::Unknown, None),
        ],
    }
}
fn host() -> HostValidatedCapabilities {
    HostValidatedCapabilities {
        scope: Some(HostScope::new(
            ProviderInstanceId::parse("mock-hsm").unwrap_or_else(|e| panic!("{e}")),
            ProviderNamespace::parse("tenant-a").unwrap_or_else(|e| panic!("{e}")),
        )),
        protection: Some(ProtectionClass::Hsm),
        version_model: Some(VersionModel::ProviderVersion),
        permit_extensions: false,
        permit_private_export: false,
    }
}
fn request() -> OperationIntent {
    OperationIntent {
        operation: O::SignDigest { digest: D::Sha256 },
        profile: rsa(),
        payload: P::Digest {
            algorithm: D::Sha256,
            bytes: 32,
        },
        binding: VersionRequirement::ProviderVersion,
        protection: ProtectionRequirement::Hsm,
        export: ExportRequirement::None,
    }
}
#[test]
fn admitted_only_with_exact_supported_profile_and_host_verified_assurance() {
    let admit = catalog()
        .admit(&request(), &host())
        .unwrap_or_else(|e| panic!("exact supported profile rejected: {e}"));
    assert_eq!(
        admit.capability.operation,
        O::SignDigest { digest: D::Sha256 }
    );
    assert_eq!(admit.max_input_bytes, Some(32));
}
#[test]
fn unknown_and_explicitly_unsupported_are_both_non_dispatchable() {
    let mut req = request();
    req.operation = O::SignMessage;
    req.payload = P::Message { bytes: 32 };
    assert_eq!(
        catalog().admit(&req, &host()),
        Err(CapabilityError::UnknownCapability)
    );
    let mut caps = catalog();
    caps.entries[1].support = SupportStatus::Unsupported;
    assert_eq!(
        caps.admit(&req, &host()),
        Err(CapabilityError::UnsupportedCapability)
    );
}
#[test]
fn sign_message_capability_never_substitutes_for_sign_digest() {
    let mut caps = catalog();
    caps.entries.remove(0);
    caps.entries[0].support = SupportStatus::Supported;
    caps.entries[0].max_input_bytes = Some(1024);
    assert_eq!(
        caps.admit(&request(), &host()),
        Err(CapabilityError::MissingCapability)
    );
}
#[test]
fn same_digest_length_different_hash_family_is_not_equivalent() {
    let mut req = request();
    req.operation = O::SignDigest {
        digest: D::Sha3_256,
    };
    req.payload = P::Digest {
        algorithm: D::Sha3_256,
        bytes: 32,
    };
    assert_eq!(
        catalog().admit(&req, &host()),
        Err(CapabilityError::InvalidIntent(ProfileError::DigestMismatch))
    );
}
#[test]
fn provider_hsm_claim_without_independent_host_verification_is_not_enough() {
    let mut h = host();
    h.protection = None;
    assert_eq!(
        catalog().admit(&request(), &h),
        Err(CapabilityError::UnverifiedProtection)
    );
    let mut c = catalog();
    c.reported_protection = ProtectionClass::Tee;
    assert_eq!(
        c.admit(&request(), &host()),
        Err(CapabilityError::UnverifiedProtection)
    );
    let mut h2 = host();
    h2.protection = Some(ProtectionClass::Tee);
    assert_eq!(
        catalog().admit(&request(), &h2),
        Err(CapabilityError::UnverifiedProtection)
    );
}
#[test]
fn attestation_claim_is_metadata_and_never_grants_trust_by_itself() {
    let mut caps = catalog();
    caps.attestation_claims.push(AttestationClaim {
        kind: "fips_certificate".into(),
        source: "cloud".into(),
        reference: "claim.999".into(),
    });
    let mut trusted = host();
    trusted.protection = None;
    trusted.version_model = None;
    assert_eq!(
        caps.admit(&request(), &trusted),
        Err(CapabilityError::UnverifiedVersion)
    );
}
#[test]
fn claimed_aws_material_revision_is_not_verified_selectable_material() {
    let mut c = catalog();
    c.reported_version_model = VersionModel::StableResource;
    let mut r = request();
    r.binding = VersionRequirement::MaterialRevision;
    let mut h = host();
    h.version_model = Some(VersionModel::MaterialRevision);
    assert_eq!(c.admit(&r, &h), Err(CapabilityError::UnverifiedVersion));
    c.reported_version_model = VersionModel::MaterialRevision;
    h.version_model = Some(VersionModel::ProviderVersion);
    assert_eq!(c.admit(&r, &h), Err(CapabilityError::UnverifiedVersion));
}
#[test]
fn unknown_version_provenance_never_satisfies_stable_key_requirement() {
    let mut c = catalog();
    c.reported_version_model = VersionModel::Unknown;
    let mut req = request();
    req.binding = VersionRequirement::StableResource;
    assert_eq!(
        c.admit(&req, &host()),
        Err(CapabilityError::UnverifiedVersion)
    );
    let mut h = host();
    h.version_model = None;
    assert_eq!(
        catalog().admit(&req, &h),
        Err(CapabilityError::UnverifiedVersion)
    );
}
#[test]
fn unsupported_protection_is_not_satisfied_by_stronger_name_guessing() {
    let mut req = request();
    req.protection = ProtectionRequirement::Tee;
    assert_eq!(
        catalog().admit(&req, &host()),
        Err(CapabilityError::UnverifiedProtection)
    );
}
#[test]
fn payload_limits_are_required_and_never_guessed_from_profile_family() {
    let mut c = catalog();
    c.entries[0].max_input_bytes = Some(31);
    assert_eq!(
        c.admit(&request(), &host()),
        Err(CapabilityError::PayloadTooLarge)
    );
    c.entries[0].max_input_bytes = None;
    assert_eq!(
        c.admit(&request(), &host()),
        Err(CapabilityError::PayloadLimitUnknown)
    );
}
#[test]
fn private_material_export_requires_explicit_operation_and_host_approval() {
    let mut req = request();
    req.operation = O::ExportPrivate;
    req.payload = P::None;
    req.export = ExportRequirement::Private;
    let mut c = catalog();
    c.entries.push(capability(
        O::ExportPrivate,
        rsa(),
        SupportStatus::Supported,
        Some(0),
    ));
    assert_eq!(
        c.admit(&req, &host()),
        Err(CapabilityError::ExportNotPermitted)
    );
    c.reported_exportability = Exportability::Private;
    assert_eq!(
        c.admit(&req, &host()),
        Err(CapabilityError::ExportNotPermitted)
    );
    let mut h = host();
    h.permit_private_export = true;
    assert!(c.admit(&req, &h).is_ok());
    let mut bad_req = req;
    bad_req.operation = O::SignDigest { digest: D::Sha256 };
    assert_eq!(
        c.admit(&bad_req, &h),
        Err(CapabilityError::InvalidIntent(
            ProfileError::OperationMismatch
        ))
    );
}
#[test]
fn duplicate_or_contradictory_exact_capabilities_rejected() {
    let mut c = catalog();
    let duplicate = c.entries[0].clone();
    c.entries.push(duplicate);
    assert_eq!(c.validate(), Err(CapabilityError::DuplicateCapability));
    c.entries.pop();
    c.entries[1].max_input_bytes = Some(22);
    assert_eq!(c.validate(), Err(CapabilityError::InvalidCatalog));
}
#[test]
fn catalog_revision_and_attestation_metadata_are_bounded() {
    let mut c = catalog();
    c.schema_version = 999;
    assert_eq!(c.validate(), Err(CapabilityError::InvalidCatalog));
    c.schema_version = CAPABILITY_SCHEMA_VERSION;
    c.feature_revision = "x".repeat(97);
    assert_eq!(c.validate(), Err(CapabilityError::InvalidCatalog));
    c.feature_revision = "v1".into();
    c.attestation_claims[0].reference = "credential.token".into();
    assert_eq!(c.validate(), Err(CapabilityError::InvalidCatalog));
    // Even syntactically valid references never elevate claims to trust.
    c.attestation_claims[0].reference = "r.1".into();
    assert!(c.validate().is_ok());
    c.attestation_claims[0].reference = "has spaces and secrets".into();
    assert_eq!(c.validate(), Err(CapabilityError::InvalidCatalog));
    c.attestation_claims[0].reference = "r.1".into();
    c.entries = vec![c.entries[0].clone(); MAX_CAPABILITY_ENTRIES + 1];
    assert_eq!(c.validate(), Err(CapabilityError::InvalidCatalog));
}
#[test]
fn capability_intersection_is_order_stable_and_downgrades_unknown() {
    let mut left = catalog();
    let mut right = catalog();
    right.entries.reverse();
    left.entries[0].max_input_bytes = Some(32);
    right.entries[0].support = SupportStatus::Unknown;
    right.entries[0].max_input_bytes = None;
    // The entry at index 0 is the reversed raw-message capability.
    let first = left.intersection(&right).unwrap_or_else(|e| panic!("{e}"));
    let second = right.intersection(&left).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(first.entries, second.entries);
    assert_eq!(first.attestation_claims.len(), 0);
    assert_eq!(first.entries.len(), 2);
    assert!(
        first
            .entries
            .iter()
            .any(|e| e.operation == O::SignDigest { digest: D::Sha256 }
                && e.support == SupportStatus::Supported
                && e.max_input_bytes == Some(32))
    );
    assert!(first.entries.iter().any(|e| e.operation == O::SignMessage
        && e.support == SupportStatus::Unknown
        && e.max_input_bytes.is_none()));
}
#[test]
fn intersection_does_not_expand_unknown_support_or_protection() {
    let mut left = catalog();
    let mut right = catalog();
    right.reported_protection = ProtectionClass::Software;
    right.reported_version_model = VersionModel::StableResource;
    right.reported_exportability = Exportability::None;
    right.entries.remove(1);
    left.entries[0].max_input_bytes = Some(1024);
    right.entries[0].max_input_bytes = Some(12);
    let common = left.intersection(&right).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(common.reported_protection, ProtectionClass::Unknown);
    assert_eq!(common.reported_version_model, VersionModel::StableResource);
    assert_eq!(common.reported_exportability, Exportability::Unknown);
    assert_eq!(common.entries.len(), 1);
    assert_eq!(common.entries[0].max_input_bytes, Some(12));
}
#[test]
fn random_order_of_capabilities_does_not_change_intersection() {
    let mut c = catalog();
    let mut d = catalog();
    for iteration in 0..240 {
        if iteration % 2 == 0 {
            c.entries.reverse();
        }
        if iteration % 3 == 0 {
            d.entries.reverse();
        }
        let a = c.intersection(&d).unwrap_or_else(|e| panic!("{e}"));
        let b = d.intersection(&c).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(a.entries, b.entries);
    }
}

#[test]
fn cross_provider_and_cross_tenant_assurance_evidence_must_fail_closed() {
    let trusted = host();
    let mut other = catalog();
    other.provider_instance = "other-hsm".into();
    assert_eq!(
        other.admit(&request(), &trusted),
        Err(CapabilityError::ScopeMismatch)
    );
    assert_eq!(
        catalog().intersection(&other),
        Err(CapabilityError::ScopeMismatch)
    );
    other = catalog();
    other.namespace = "tenant-b".into();
    assert_eq!(
        other.admit(&request(), &trusted),
        Err(CapabilityError::ScopeMismatch)
    );
    assert_eq!(
        catalog().intersection(&other),
        Err(CapabilityError::ScopeMismatch)
    );
    let mut incomplete = host();
    incomplete.scope = None;
    assert_eq!(
        catalog().admit(&request(), &incomplete),
        Err(CapabilityError::ScopeMismatch)
    );
    let mut wrong_host = host();
    wrong_host.scope = Some(HostScope::new(
        ProviderInstanceId::parse("mock-hsm").unwrap_or_else(|e| panic!("{e}")),
        ProviderNamespace::parse("tenant-b").unwrap_or_else(|e| panic!("{e}")),
    ));
    assert_eq!(
        catalog().admit(&request(), &wrong_host),
        Err(CapabilityError::ScopeMismatch)
    );
}

#[test]
fn hkdf_capability_input_limit_counts_info_only_not_derived_output() {
    let mut c = catalog();
    c.entries.push(capability(
        O::DeriveKey,
        A::Hkdf { digest: D::Sha256 },
        SupportStatus::Supported,
        Some(10),
    ));
    let mut req = request();
    req.operation = O::DeriveKey;
    req.profile = A::Hkdf { digest: D::Sha256 };
    req.payload = P::Derivation {
        info_bytes: 10,
        output_bytes: 64,
    };
    assert!(c.admit(&req, &host()).is_ok());
    req.payload = P::Derivation {
        info_bytes: 11,
        output_bytes: 64,
    };
    assert_eq!(
        c.admit(&req, &host()),
        Err(CapabilityError::PayloadTooLarge)
    );
}
