//! FOSS-401 identity and version-assurance adversarial regression suite.
//! Semantics mirror selected KM-01 fixtures, not provider implementation tests.
use keymesh::{
    BindingAssurance, BindingError, DispatchTarget, HostScope, IdentityError, KeyRef, KeySelector,
    LogicalKeyId, MAX_IDENTIFIER_BYTES, MAX_RESOURCE_BYTES, MaterialRevisionId, ProviderInstanceId,
    ProviderNamespace, ProviderResourceId, ProviderVersionId, RequiredAssurance, ResolvedKey,
    preflight_bind,
};

fn provider(s: &str) -> ProviderInstanceId {
    ProviderInstanceId::parse(s).unwrap_or_else(|e| panic!("invalid test provider: {e}"))
}
fn namespace(s: &str) -> ProviderNamespace {
    ProviderNamespace::parse(s).unwrap_or_else(|e| panic!("invalid test namespace: {e}"))
}
fn logical(s: &str) -> LogicalKeyId {
    LogicalKeyId::parse(s).unwrap_or_else(|e| panic!("invalid test logical ID: {e}"))
}
fn resource(s: &str) -> ProviderResourceId {
    ProviderResourceId::parse(s).unwrap_or_else(|e| panic!("invalid test resource: {e}"))
}
fn version(s: &str) -> ProviderVersionId {
    ProviderVersionId::parse(s).unwrap_or_else(|e| panic!("invalid test version: {e}"))
}
fn material(s: &str) -> MaterialRevisionId {
    MaterialRevisionId::parse(s).unwrap_or_else(|e| panic!("invalid test material: {e}"))
}
fn baseline() -> (HostScope, KeyRef, ResolvedKey) {
    let p = provider("software-local");
    let ns = namespace("tenant-a");
    let k = logical("customer-data");
    let r = resource("software:customer-data:42");
    (
        HostScope::new(p.clone(), ns.clone()),
        KeyRef::new(
            p.clone(),
            ns.clone(),
            k.clone(),
            KeySelector::StableResource(r.clone()),
        ),
        ResolvedKey::new(p, ns, k, DispatchTarget::StableResource(r)),
    )
}

#[test]
fn software_stable_resource_success_and_explicit_bound_target() {
    let (scope, reference, resolved) = baseline();
    let bound = preflight_bind(
        &reference,
        &scope,
        &resolved,
        RequiredAssurance::StableResource,
    )
    .unwrap_or_else(|e| panic!("expected permitted binding: {e}"));
    assert_eq!(bound.assurance(), BindingAssurance::StableResourceBound);
    assert_eq!(
        bound.dispatch_target().resource().as_str(),
        "software:customer-data:42"
    );
}

#[test]
fn zero_duplicate_or_invalid_identifier_values() {
    for invalid in [
        "",
        ".",
        "..",
        "tenant/name",
        "bad key",
        "bad\nname",
        "ténant",
        "xn--💥",
    ] {
        assert!(
            ProviderNamespace::parse(invalid).is_err(),
            "accepted invalid: {invalid}"
        );
        assert!(
            LogicalKeyId::parse(invalid).is_err(),
            "accepted invalid: {invalid}"
        );
        assert!(
            ProviderInstanceId::parse(invalid).is_err(),
            "accepted invalid: {invalid}"
        );
        assert!(
            ProviderVersionId::parse(invalid).is_err(),
            "accepted invalid: {invalid}"
        );
        assert!(
            MaterialRevisionId::parse(invalid).is_err(),
            "accepted invalid: {invalid}"
        );
    }
    let too_long = "x".repeat(MAX_IDENTIFIER_BYTES + 1);
    assert_eq!(
        ProviderNamespace::parse(&too_long),
        Err(IdentityError::TooLong)
    );
    assert!(ProviderNamespace::parse(&"x".repeat(MAX_IDENTIFIER_BYTES)).is_ok());
    assert_ne!(namespace("tenant-a"), namespace("tenant-b"));
}

#[test]
fn opaque_locator_accepts_provider_uris_and_rejects_secret_bearing_values() {
    for value in [
        "arn:aws:kms:us-east-1:111122223333:key/1234abcd",
        "https://vault.vault.azure.net/keys/payments/key-v7",
        "transit:payments",
        "pkcs11:token=HSM1;object=my-key;type=private;id=%01",
    ] {
        assert_eq!(resource(value).as_str(), value);
    }
    for forbidden in [
        "",
        "https://user:password@vault.example/keys/test",
        "pkcs11:object=mykey?pin-value=1234",
        "pkcs11:object=mykey?pin-source=/tmp/secret",
        "pkcs11:object=x?%70in-value%3d1234",
        "pkcs11:object=x?%2570in-value%253d1234",
        "arn:aws:kms:us-east-1:111122223333:alias/payments",
        "alias/payments",
        "https://user%40vault.example/keys/test",
        "42",
        "000000",
        "aws:secret=example",
        "https://host/vault#fragment",
        "https://host/bad path",
        "https://vault.example/token?access_token=SECRET",
    ] {
        assert!(
            ProviderResourceId::parse(forbidden).is_err(),
            "leak: {forbidden}"
        );
    }
    assert_eq!(
        ProviderResourceId::parse(&"x".repeat(MAX_RESOURCE_BYTES + 1)),
        Err(IdentityError::TooLong)
    );
    assert_eq!(
        ProviderResourceId::parse("abc%zz"),
        Err(IdentityError::InvalidEncoding)
    );
    assert!(ProviderResourceId::parse(&"x".repeat(MAX_RESOURCE_BYTES)).is_ok());
    assert!(!format!("{:?}", ProviderResourceId::parse("pin-value=bad")).contains("bad"));
}

#[test]
fn cross_instance_namespace_and_logical_substitution_fail_closed() {
    let (scope, reference, resolved) = baseline();
    let alternate_scope = HostScope::new(provider("software-other"), namespace("tenant-a"));
    assert_eq!(
        preflight_bind(
            &reference,
            &alternate_scope,
            &resolved,
            RequiredAssurance::StableResource
        )
        .err(),
        Some(BindingError::ProviderMismatch)
    );
    let swapped_provider = ResolvedKey::new(
        provider("software-other"),
        namespace("tenant-a"),
        logical("customer-data"),
        DispatchTarget::StableResource(resource("software:customer-data:42")),
    );
    assert_eq!(
        preflight_bind(
            &reference,
            &scope,
            &swapped_provider,
            RequiredAssurance::StableResource
        )
        .err(),
        Some(BindingError::ProviderMismatch)
    );
    let swapped_ns = ResolvedKey::new(
        provider("software-local"),
        namespace("tenant-b"),
        logical("customer-data"),
        DispatchTarget::StableResource(resource("software:customer-data:42")),
    );
    assert_eq!(
        preflight_bind(
            &reference,
            &scope,
            &swapped_ns,
            RequiredAssurance::StableResource
        )
        .err(),
        Some(BindingError::NamespaceMismatch)
    );
    let swapped_logical = ResolvedKey::new(
        provider("software-local"),
        namespace("tenant-a"),
        logical("system-master"),
        DispatchTarget::StableResource(resource("software:customer-data:42")),
    );
    assert_eq!(
        preflight_bind(
            &reference,
            &scope,
            &swapped_logical,
            RequiredAssurance::StableResource
        )
        .err(),
        Some(BindingError::LogicalKeyMismatch)
    );
}

#[test]
fn resource_and_alias_race_denied_even_with_matching_logical_name() {
    let (scope, reference, _) = baseline();
    let changed = ResolvedKey::new(
        provider("software-local"),
        namespace("tenant-a"),
        logical("customer-data"),
        DispatchTarget::StableResource(resource("software:customer-data:99")),
    );
    assert_eq!(
        preflight_bind(
            &reference,
            &scope,
            &changed,
            RequiredAssurance::StableResource
        )
        .err(),
        Some(BindingError::ResourceMismatch)
    );
    let alias = KeyRef::new(
        provider("software-local"),
        namespace("tenant-a"),
        logical("customer-data"),
        KeySelector::Active,
    );
    let bound = preflight_bind(&alias, &scope, &changed, RequiredAssurance::StableResource)
        .unwrap_or_else(|e| panic!("expected resolved active version: {e}"));
    assert_eq!(
        bound.dispatch_target().resource().as_str(),
        "software:customer-data:99"
    );
    // An adapter must use only the bound stable target, never the original alias.
}

#[test]
fn azure_and_vault_exact_versions_bind_and_stale_version_is_rejected() {
    for (p, locator, v) in [
        (
            "azure-prod",
            "https://vault.vault.azure.net/keys/payments/key-v7",
            "key-v7",
        ),
        ("vault-prod", "transit:payments", "5"),
    ] {
        let ns = namespace("tenant-a");
        let k = logical("customer-data");
        let r = resource(locator);
        let wanted = version(v);
        let scope = HostScope::new(provider(p), ns.clone());
        let reference = KeyRef::new(
            provider(p),
            ns.clone(),
            k.clone(),
            KeySelector::ExactProviderVersion {
                resource: r.clone(),
                version: wanted.clone(),
            },
        );
        let resolved = ResolvedKey::new(
            provider(p),
            ns.clone(),
            k.clone(),
            DispatchTarget::ProviderVersion {
                resource: r.clone(),
                version: wanted,
            },
        );
        let bound = preflight_bind(
            &reference,
            &scope,
            &resolved,
            RequiredAssurance::ProviderVersion,
        )
        .unwrap_or_else(|e| panic!("expected exact provider version: {e}"));
        assert_eq!(bound.assurance(), BindingAssurance::ProviderVersionBound);
        let stale = ResolvedKey::new(
            provider(p),
            ns,
            k,
            DispatchTarget::ProviderVersion {
                resource: r,
                version: version("stale"),
            },
        );
        assert_eq!(
            preflight_bind(
                &reference,
                &scope,
                &stale,
                RequiredAssurance::ProviderVersion
            )
            .err(),
            Some(BindingError::VersionMismatch)
        );
    }
}

#[test]
fn aws_rotation_observation_cannot_impersonate_exact_material_selection() {
    let p = provider("aws-prod");
    let ns = namespace("tenant-a");
    let k = logical("customer-data");
    let r = resource("arn:aws:kms:us-east-1:111122223333:key/1234abcd");
    let scope = HostScope::new(p.clone(), ns.clone());
    let requested = KeyRef::new(
        p.clone(),
        ns.clone(),
        k.clone(),
        KeySelector::ExactMaterialRevision {
            resource: r.clone(),
            version: version("rotation-7"),
            revision: material("material-7"),
        },
    );
    let observed = ResolvedKey::new(p, ns, k, DispatchTarget::StableResource(r))
        .with_observed_material_revision(material("material-7"));
    assert_eq!(
        observed
            .observed_material_revision()
            .map(MaterialRevisionId::as_str),
        Some("material-7")
    );
    assert_eq!(
        preflight_bind(
            &requested,
            &scope,
            &observed,
            RequiredAssurance::MaterialVersion
        )
        .err(),
        Some(BindingError::UnsupportedVersionAssurance)
    );
}

#[test]
fn software_exact_material_requires_both_correct_version_and_revision() {
    let p = provider("software-local");
    let ns = namespace("tenant-a");
    let k = logical("customer-data");
    let r = resource("software:customer-data:42");
    let v = version("v3");
    let rev = material("rev3");
    let scope = HostScope::new(p.clone(), ns.clone());
    let request = KeyRef::new(
        p.clone(),
        ns.clone(),
        k.clone(),
        KeySelector::ExactMaterialRevision {
            resource: r.clone(),
            version: v.clone(),
            revision: rev.clone(),
        },
    );
    let good = ResolvedKey::new(
        p.clone(),
        ns.clone(),
        k.clone(),
        DispatchTarget::MaterialVersion {
            resource: r.clone(),
            version: v,
            revision: rev,
        },
    );
    assert_eq!(
        preflight_bind(&request, &scope, &good, RequiredAssurance::MaterialVersion)
            .unwrap_or_else(|e| panic!("expected bound material: {e}"))
            .assurance(),
        BindingAssurance::MaterialVersionBound
    );
    let stale = ResolvedKey::new(
        p,
        ns,
        k,
        DispatchTarget::MaterialVersion {
            resource: r,
            version: version("v3"),
            revision: material("rev2"),
        },
    );
    assert_eq!(
        preflight_bind(&request, &scope, &stale, RequiredAssurance::MaterialVersion).err(),
        Some(BindingError::MaterialRevisionMismatch)
    );
}

#[test]
fn provider_version_never_upgrades_to_material_revision() {
    let (scope, reference, resolved) = baseline();
    assert_eq!(
        preflight_bind(
            &reference,
            &scope,
            &resolved,
            RequiredAssurance::ProviderVersion
        )
        .err(),
        Some(BindingError::UnsupportedVersionAssurance)
    );
    assert_eq!(
        preflight_bind(
            &reference,
            &scope,
            &resolved,
            RequiredAssurance::MaterialVersion
        )
        .err(),
        Some(BindingError::UnsupportedVersionAssurance)
    );
    let p = provider("azure-prod");
    let ns = namespace("tenant-a");
    let key = logical("payments");
    let r = resource("azure:payments");
    let scope = HostScope::new(p.clone(), ns.clone());
    let request = KeyRef::new(p.clone(), ns.clone(), key.clone(), KeySelector::Active);
    let resolved = ResolvedKey::new(
        p,
        ns,
        key,
        DispatchTarget::ProviderVersion {
            resource: r,
            version: version("v7"),
        },
    );
    assert!(
        preflight_bind(
            &request,
            &scope,
            &resolved,
            RequiredAssurance::ProviderVersion
        )
        .is_ok()
    );
    assert_eq!(
        preflight_bind(
            &request,
            &scope,
            &resolved,
            RequiredAssurance::MaterialVersion
        )
        .err(),
        Some(BindingError::UnsupportedVersionAssurance)
    );
}

#[test]
fn malformed_input_properties_are_fail_closed_over_many_values() {
    let alphabet = [
        " ", "\t", "\n", "/", "\\", "#", "?", "@", "é", "λ", "💥", "\0",
    ];
    for character in alphabet {
        for position in 0..10 {
            let value = format!("tenant{}{}", "a".repeat(position), character);
            assert!(
                ProviderNamespace::parse(&value).is_err(),
                "accepted {value:?}"
            );
        }
    }
}

// These explicit type boundaries are also enforced by public doctests:
// ProviderResourceId::try_from(42usize) must not type-check as a key handle.
