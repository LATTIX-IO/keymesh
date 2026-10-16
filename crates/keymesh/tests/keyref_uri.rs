//! FOSS-402: canonical KeyRef URI golden, regression, and adversarial tests.
use keymesh::{
    BindingError, DispatchTarget, HostScope, KeyRef, KeyRefUriError, KeySelector, LogicalKeyId,
    MAX_KEY_REF_URI_BYTES, MaterialRevisionId, ProviderInstanceId, ProviderNamespace,
    ProviderResourceId, ProviderVersionId, RequiredAssurance, ResolvedKey, preflight_bind,
};

const GOLDEN: &str = include_str!("../../../tests/fixtures/keyref_uri_v1.tsv");

fn provider(s: &str) -> ProviderInstanceId {
    ProviderInstanceId::parse(s).unwrap_or_else(|e| panic!("provider fixture invalid: {e}"))
}
fn scope(s: &str) -> ProviderNamespace {
    ProviderNamespace::parse(s).unwrap_or_else(|e| panic!("namespace fixture invalid: {e}"))
}
fn logical(s: &str) -> LogicalKeyId {
    LogicalKeyId::parse(s).unwrap_or_else(|e| panic!("logical fixture invalid: {e}"))
}
fn resource(s: &str) -> ProviderResourceId {
    ProviderResourceId::parse(s).unwrap_or_else(|e| panic!("resource fixture invalid: {e}"))
}
fn version(s: &str) -> ProviderVersionId {
    ProviderVersionId::parse(s).unwrap_or_else(|e| panic!("version fixture invalid: {e}"))
}
fn revision(s: &str) -> MaterialRevisionId {
    MaterialRevisionId::parse(s).unwrap_or_else(|e| panic!("revision fixture invalid: {e}"))
}

#[test]
fn versioned_uri_golden_fixtures_are_exact_and_fail_closed() {
    let mut accepted = 0;
    let mut rejected = 0;
    for line in GOLDEN.lines() {
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        let (kind, text) = line
            .split_once('\t')
            .unwrap_or_else(|| panic!("fixture must have one tab"));
        match kind {
            "valid" => {
                accepted += 1;
                let parsed: KeyRef = text
                    .parse()
                    .unwrap_or_else(|e| panic!("valid fixture unexpectedly rejected: {text}: {e}"));
                assert_eq!(parsed.to_string(), text, "not canonical: {text}");
                assert_eq!(
                    parsed
                        .to_string()
                        .parse::<KeyRef>()
                        .unwrap_or_else(|_| unreachable!()),
                    parsed
                );
            }
            "invalid" => {
                rejected += 1;
                assert!(
                    text.parse::<KeyRef>().is_err(),
                    "unexpected acceptance of invalid URI: {text}"
                );
            }
            _ => panic!("invalid golden fixture tag"),
        }
    }
    assert_eq!(accepted, 9);
    assert_eq!(rejected, 41);
}

#[test]
fn construction_and_parse_roundtrip_for_all_selector_variants() {
    let instance = provider("azure-prod");
    let namespace = scope("tenant-A");
    let key = logical("payments.v1");
    let native = resource("https://vault.vault.azure.net/keys/payments/key-v7");
    let selectors = [
        KeySelector::Active,
        KeySelector::Latest,
        KeySelector::StableResource(native.clone()),
        KeySelector::ExactProviderVersion {
            resource: native.clone(),
            version: version("key-v7"),
        },
        KeySelector::ExactMaterialRevision {
            resource: native,
            version: version("key-v7"),
            revision: revision("rev_17"),
        },
    ];
    for selector in selectors {
        let wanted = KeyRef::new(instance.clone(), namespace.clone(), key.clone(), selector);
        let rendered = wanted.to_string();
        let parsed: KeyRef = rendered.parse().unwrap_or_else(|_| unreachable!());
        assert_eq!(wanted, parsed);
        assert_eq!(parsed.to_string(), rendered);
    }
}

#[test]
fn parser_binds_tenant_and_key_without_trusting_uri_as_authorization() {
    let untrusted: KeyRef = "keymesh://v1/sw/tenant-b/billing/active"
        .parse()
        .unwrap_or_else(|_| unreachable!());
    let host = HostScope::new(provider("sw"), scope("tenant-a"));
    let resolved = ResolvedKey::new(
        provider("sw"),
        scope("tenant-a"),
        logical("billing"),
        DispatchTarget::StableResource(resource("software:billing:42")),
    );
    assert_eq!(
        preflight_bind(
            &untrusted,
            &host,
            &resolved,
            RequiredAssurance::StableResource,
        )
        .err(),
        Some(BindingError::NamespaceMismatch)
    );
}

#[test]
fn uri_cannot_upgrade_opaque_material_rotation_to_exact_material() {
    let ref_uri = "keymesh://v1/aws-prod/tenant-a/payments/material/arn%3Aaws%3Akms%3Aus-east-1%3A111122223333%3Akey%2F1234abcd/v2/rev4";
    let reference: KeyRef = ref_uri.parse().unwrap_or_else(|_| unreachable!());
    let provider_id = provider("aws-prod");
    let tenant = scope("tenant-a");
    let resolved = ResolvedKey::new(
        provider_id.clone(),
        tenant.clone(),
        logical("payments"),
        DispatchTarget::StableResource(resource("arn:aws:kms:us-east-1:111122223333:key/1234abcd")),
    )
    .with_observed_material_revision(revision("rev4"));
    assert_eq!(
        preflight_bind(
            &reference,
            &HostScope::new(provider_id, tenant),
            &resolved,
            RequiredAssurance::MaterialVersion,
        )
        .err(),
        Some(BindingError::UnsupportedVersionAssurance)
    );
}

#[test]
fn native_provider_locator_is_data_not_an_outer_uri_scope() {
    let reference: KeyRef = "keymesh://v1/hsm-prod/tenant-a/key/resource/pkcs11%3Atoken%3DHSM1%3Bobject%3Dmy-key%3Btype%3Dprivate%3Bid%3D%2501"
        .parse()
        .unwrap_or_else(|_| unreachable!());
    match reference.selector() {
        KeySelector::StableResource(resource) => assert_eq!(
            resource.as_str(),
            "pkcs11:token=HSM1;object=my-key;type=private;id=%01"
        ),
        _ => panic!("wrong selector"),
    }
    assert_eq!(reference.namespace().as_str(), "tenant-a");
    assert_eq!(reference.provider().as_str(), "hsm-prod");
}

#[test]
fn invalid_uris_never_echo_secrets_into_errors() {
    let sample = "keymesh://v1/p/t/key/resource/pkcs11%3Apin-value%3DSUPERSECRET123";
    let error = match sample.parse::<KeyRef>() {
        Err(error) => error,
        Ok(_) => panic!("credential-bearing URI unexpectedly accepted"),
    };
    let shown = format!("{error:?} {error}");
    assert!(!shown.contains("SUPERSECRET123"));
    assert!(matches!(error, KeyRefUriError::InvalidResource(_)));
}

#[test]
fn native_credentials_and_decoded_controls_are_rejected() {
    let forbidden = [
        "https://s3.amazonaws.com/key?X-Amz-Signature=SUPERSECRET",
        "https://account.blob.core.windows.net/c/b?sv=2026&sig=SUPERSECRET",
        "https://s3.amazonaws.com/key?X-Amz-Credential=ACCESSKEY",
        "foo%0Abar",
        "foo%C3%A9",
        "foo%250Abar",
        "pkcs11:token=%0A;object=my-key;id=%01",
        "pkcs11:token=HSM1;object=my-key;id=%01;object=%0A",
    ];
    for native in forbidden {
        assert!(ProviderResourceId::parse(native).is_err());
    }
    // RFC 7512 binary object identifiers remain addressable when encoded
    // precisely once in the terminal PKCS#11 id= parameter.
    assert!(
        ProviderResourceId::parse("pkcs11:token=HSM1;object=my-key;type=private;id=%01").is_ok()
    );
}

#[test]
fn byte_length_limit_is_enforced_before_parsing() {
    let oversized = format!(
        "keymesh://v1/p/t/k/resource/{}",
        "x".repeat(MAX_KEY_REF_URI_BYTES)
    );
    assert_eq!(oversized.parse::<KeyRef>(), Err(KeyRefUriError::TooLong));
    assert_eq!(
        ProviderResourceId::parse("../cross-tenant"),
        Err(keymesh::IdentityError::InvalidCharacter)
    );
    assert_eq!(
        ProviderResourceId::parse("key%2F..%2Fcross-tenant"),
        Err(keymesh::IdentityError::InvalidCharacter)
    );
}

#[test]
fn deterministic_roundtrips_and_adversarial_mutations() {
    let alphabet = b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-_.";
    let mut seed = 0x84D1B03D6EE8AB9Fu64;
    for i in 0..700 {
        let mut namespace = String::from("tenant");
        for _ in 0..(i % 50) {
            seed = seed
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            namespace.push(char::from(
                alphabet[((seed >> 32) as usize) % alphabet.len()],
            ));
        }
        let reference = KeyRef::new(
            provider("sw"),
            scope(&namespace),
            logical("project-key"),
            KeySelector::StableResource(resource(&format!("urn:untrusted:source/{i}:%2Fslash"))),
        );
        let text = reference.to_string();
        let parsed: KeyRef = text.parse().unwrap_or_else(|_| unreachable!());
        assert_eq!(reference, parsed);
        assert_eq!(text, parsed.to_string());
        for bad in [
            format!("{text}?secret=abc"),
            format!("{text}#fragment"),
            format!("{text}/duplicate"),
        ] {
            assert!(bad.parse::<KeyRef>().is_err());
        }
    }
}

#[test]
fn malformed_unicode_percent_sequences_and_delimiters_cannot_panic() {
    let alphabet = [
        'a', 'B', '0', '/', '%', ':', '?', '#', '@', '\\', '.', 'é', 'λ', '\0', '-', '+',
    ];
    let mut state = 0xA81B4DE25127AA45u64;
    for _ in 0..2000 {
        state = state
            .wrapping_mul(2862933555777941757)
            .wrapping_add(3037000493);
        let len = ((state >> 32) % 80) as usize;
        let mut value = String::from("keymesh://v1/");
        for _ in 0..len {
            state = state
                .wrapping_mul(2862933555777941757)
                .wrapping_add(3037000493);
            value.push(alphabet[((state >> 32) as usize) % alphabet.len()]);
        }
        if let Ok(parsed) = value.parse::<KeyRef>() {
            assert_eq!(parsed.to_string(), value);
            assert_eq!(
                parsed
                    .to_string()
                    .parse::<KeyRef>()
                    .unwrap_or_else(|_| unreachable!()),
                parsed
            );
        }
    }
}
