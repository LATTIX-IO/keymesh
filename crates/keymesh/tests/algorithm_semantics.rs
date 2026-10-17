//! FOSS-403 algorithm/operation security regression suite (no cryptography).
use keymesh::{
    AesWrapVariant, AlgorithmProfile as A, CryptoOperation as O, DigestAlgorithm as D, EcCurve,
    EcdsaEncoding, EdDsaVariant, ExportRequirement, ExtensionProfile, MlDsaInput, MlDsaVariant,
    MlKemVariant, OperationIntent, PayloadDescriptor as P, ProfileError, ProtectionRequirement,
    SlhDsaVariant, VersionRequirement,
};
use std::collections::BTreeMap;

fn intent(operation: O, profile: A, payload: P) -> OperationIntent {
    OperationIntent {
        operation,
        profile,
        payload,
        binding: VersionRequirement::StableResource,
        protection: ProtectionRequirement::Any,
        export: ExportRequirement::None,
    }
}
fn pss() -> A {
    A::RsaPss {
        modulus_bits: 3072,
        digest: D::Sha256,
        mgf1_digest: D::Sha256,
        salt_bytes: 32,
    }
}
fn oaep() -> A {
    A::RsaOaep {
        modulus_bits: 2048,
        digest: D::Sha256,
        mgf1_digest: D::Sha256,
    }
}
fn ecdsa() -> A {
    A::Ecdsa {
        curve: EcCurve::P256,
        digest: D::Sha256,
        encoding: EcdsaEncoding::Der,
    }
}
fn aes_gcm() -> A {
    A::AesGcm {
        key_bits: 256,
        nonce_bytes: 12,
        tag_bytes: 16,
    }
}
fn key_wrap(mode: AesWrapVariant) -> A {
    A::AesKeyWrap {
        key_bits: 256,
        variant: mode,
    }
}
#[test]
fn rsa_sign_message_and_sign_digest_are_distinct_operations() {
    assert!(
        intent(O::SignMessage, pss(), P::Message { bytes: 42 })
            .validate()
            .is_ok()
    );
    assert!(
        intent(
            O::SignDigest { digest: D::Sha256 },
            pss(),
            P::Digest {
                algorithm: D::Sha256,
                bytes: 32
            }
        )
        .validate()
        .is_ok()
    );
    assert_eq!(
        intent(
            O::SignDigest { digest: D::Sha256 },
            pss(),
            P::Message { bytes: 32 }
        )
        .validate(),
        Err(ProfileError::PayloadMismatch)
    );
    assert_eq!(
        intent(
            O::SignMessage,
            pss(),
            P::Digest {
                algorithm: D::Sha256,
                bytes: 32
            }
        )
        .validate(),
        Err(ProfileError::OperationMismatch)
    );
}

#[test]
fn digest_name_mismatch_and_digest_length_mismatch_fail_closed() {
    assert_eq!(
        intent(
            O::SignDigest { digest: D::Sha384 },
            pss(),
            P::Digest {
                algorithm: D::Sha384,
                bytes: 48
            }
        )
        .validate(),
        Err(ProfileError::DigestMismatch)
    );
    assert_eq!(
        intent(
            O::VerifyDigest { digest: D::Sha256 },
            pss(),
            P::Digest {
                algorithm: D::Sha256,
                bytes: 31
            }
        )
        .validate(),
        Err(ProfileError::DigestLengthMismatch)
    );
    assert_eq!(
        intent(
            O::SignDigest { digest: D::Sha256 },
            pss(),
            P::Digest {
                algorithm: D::Sha3_256,
                bytes: 32
            }
        )
        .validate(),
        Err(ProfileError::DigestMismatch)
    );
}
#[test]
fn rsa_parameters_enforce_security_and_oaep_plaintext_bound() {
    assert_eq!(
        A::RsaPss {
            modulus_bits: 1024,
            digest: D::Sha256,
            mgf1_digest: D::Sha256,
            salt_bytes: 32
        }
        .validate(),
        Err(ProfileError::InvalidParameters)
    );
    assert_eq!(
        A::RsaPss {
            modulus_bits: 2048,
            digest: D::Sha512,
            mgf1_digest: D::Sha256,
            salt_bytes: 256
        }
        .validate(),
        Err(ProfileError::InvalidParameters)
    );
    assert!(
        intent(O::Encrypt, oaep(), P::Message { bytes: 190 })
            .validate()
            .is_ok()
    );
    assert_eq!(
        intent(O::Encrypt, oaep(), P::Message { bytes: 191 }).validate(),
        Err(ProfileError::AlgorithmInputTooLarge)
    );
    assert_eq!(
        intent(O::Decrypt, oaep(), P::Ciphertext { bytes: 255 }).validate(),
        Err(ProfileError::AlgorithmInputTooLarge)
    );
}

#[test]
fn wrapping_and_encryption_are_separately_typed_and_non_interchangeable() {
    assert!(
        intent(
            O::WrapKey,
            key_wrap(AesWrapVariant::Rfc3394),
            P::KeyMaterial { bytes: 32 }
        )
        .validate()
        .is_ok()
    );
    assert_eq!(
        intent(
            O::Encrypt,
            key_wrap(AesWrapVariant::Rfc3394),
            P::Message { bytes: 32 }
        )
        .validate(),
        Err(ProfileError::OperationMismatch)
    );
    assert_eq!(
        intent(O::WrapKey, aes_gcm(), P::KeyMaterial { bytes: 32 }).validate(),
        Err(ProfileError::OperationMismatch)
    );
    assert!(
        intent(O::Encrypt, aes_gcm(), P::Message { bytes: 32 })
            .validate()
            .is_ok()
    );
    assert!(
        intent(O::WrapKey, oaep(), P::KeyMaterial { bytes: 32 })
            .validate()
            .is_ok()
    );
    assert_eq!(
        intent(O::WrapKey, oaep(), P::Message { bytes: 32 }).validate(),
        Err(ProfileError::OperationMismatch)
    );
}
#[test]
fn aes_key_wrap_enforces_rfc3394_block_alignment_but_rfc5649_handles_padding() {
    assert_eq!(
        intent(
            O::WrapKey,
            key_wrap(AesWrapVariant::Rfc3394),
            P::KeyMaterial { bytes: 15 }
        )
        .validate(),
        Err(ProfileError::InvalidParameters)
    );
    assert!(
        intent(
            O::WrapKey,
            key_wrap(AesWrapVariant::Rfc5649),
            P::KeyMaterial { bytes: 15 }
        )
        .validate()
        .is_ok()
    );
    assert_eq!(
        intent(
            O::WrapKey,
            key_wrap(AesWrapVariant::Rfc5649),
            P::KeyMaterial { bytes: 0 }
        )
        .validate(),
        Err(ProfileError::InvalidParameters)
    );
    assert_eq!(
        intent(
            O::UnwrapKey,
            key_wrap(AesWrapVariant::Rfc3394),
            P::Ciphertext { bytes: 15 }
        )
        .validate(),
        Err(ProfileError::InvalidParameters)
    );
}
#[test]
fn aes_aead_profile_never_guesses_nonce_or_tag_size() {
    for nonce in [0u8, 8u8, 16u8, 255u8] {
        assert_eq!(
            A::AesGcm {
                key_bits: 256,
                nonce_bytes: nonce,
                tag_bytes: 16
            }
            .validate(),
            Err(ProfileError::InvalidParameters)
        );
    }
    assert_eq!(
        A::AesGcm {
            key_bits: 256,
            nonce_bytes: 12,
            tag_bytes: 8
        }
        .validate(),
        Err(ProfileError::InvalidParameters)
    );
    assert!(aes_gcm().validate().is_ok());
}
#[test]
fn hmac_is_not_digital_signature_and_hkdf_is_not_mac() {
    let hmac = A::Hmac {
        digest: D::Sha512,
        key_bits: 256,
    };
    assert!(
        intent(O::MacMessage, hmac.clone(), P::Message { bytes: 300 })
            .validate()
            .is_ok()
    );
    assert_eq!(
        intent(O::SignMessage, hmac, P::Message { bytes: 300 }).validate(),
        Err(ProfileError::OperationMismatch)
    );
    let hkdf = A::Hkdf { digest: D::Sha256 };
    assert!(
        intent(
            O::DeriveKey,
            hkdf.clone(),
            P::Derivation {
                info_bytes: 10,
                output_bytes: 64
            }
        )
        .validate()
        .is_ok()
    );
    assert_eq!(
        intent(
            O::DeriveKey,
            hkdf,
            P::Derivation {
                info_bytes: 10,
                output_bytes: 8161
            }
        )
        .validate(),
        Err(ProfileError::AlgorithmInputTooLarge)
    );
}
#[test]
fn eddsa_message_signing_is_not_generic_sign_digest() {
    let ed = A::EdDsa {
        variant: EdDsaVariant::Ed25519,
    };
    assert!(
        intent(O::SignMessage, ed.clone(), P::Message { bytes: 0 })
            .validate()
            .is_ok()
    );
    assert_eq!(
        intent(
            O::SignDigest { digest: D::Sha512 },
            ed,
            P::Digest {
                algorithm: D::Sha512,
                bytes: 64
            }
        )
        .validate(),
        Err(ProfileError::OperationMismatch)
    );
}
#[test]
fn mlkem_exact_parameter_sets_only_allow_kem_operations() {
    for variant in [
        MlKemVariant::MlKem512,
        MlKemVariant::MlKem768,
        MlKemVariant::MlKem1024,
    ] {
        let p = A::MlKem { variant };
        assert!(
            intent(O::Encapsulate, p.clone(), P::None)
                .validate()
                .is_ok()
        );
        assert!(
            intent(O::Decapsulate, p.clone(), P::Ciphertext { bytes: 1024 })
                .validate()
                .is_ok()
        );
        assert_eq!(
            intent(O::Encrypt, p.clone(), P::Message { bytes: 42 }).validate(),
            Err(ProfileError::OperationMismatch)
        );
        assert_eq!(
            intent(O::SignMessage, p, P::Message { bytes: 42 }).validate(),
            Err(ProfileError::OperationMismatch)
        );
    }
}
#[test]
fn mldsa_pure_hash_and_external_mu_are_distinct_typed_inputs() {
    let pure = A::MlDsa {
        variant: MlDsaVariant::MlDsa87,
        input: MlDsaInput::Pure,
    };
    let hashed = A::MlDsa {
        variant: MlDsaVariant::MlDsa65,
        input: MlDsaInput::HashMessage { digest: D::Sha512 },
    };
    let mu = A::MlDsa {
        variant: MlDsaVariant::MlDsa44,
        input: MlDsaInput::ExternalMu,
    };
    assert!(
        intent(O::SignMessage, pure, P::Message { bytes: 2 })
            .validate()
            .is_ok()
    );
    assert!(
        intent(O::SignMessage, hashed, P::Message { bytes: 2 })
            .validate()
            .is_ok()
    );
    assert_eq!(
        intent(O::SignMessage, mu.clone(), P::Message { bytes: 64 }).validate(),
        Err(ProfileError::OperationMismatch)
    );
    assert!(
        intent(O::SignExternalMu, mu.clone(), P::ExternalMu { bytes: 64 })
            .validate()
            .is_ok()
    );
    assert_eq!(
        intent(O::SignExternalMu, mu.clone(), P::ExternalMu { bytes: 63 }).validate(),
        Err(ProfileError::DigestLengthMismatch)
    );
    assert_eq!(
        intent(
            O::SignDigest { digest: D::Sha512 },
            mu,
            P::Digest {
                algorithm: D::Sha512,
                bytes: 64
            }
        )
        .validate(),
        Err(ProfileError::OperationMismatch)
    );
}
#[test]
fn slhdsa_parameter_sets_remain_signature_specific() {
    for variant in [SlhDsaVariant::Sha2_128s, SlhDsaVariant::Shake256f] {
        let p = A::SlhDsa { variant };
        assert!(
            intent(O::VerifyMessage, p.clone(), P::Message { bytes: 256 })
                .validate()
                .is_ok()
        );
        assert_eq!(
            intent(O::Encapsulate, p, P::None).validate(),
            Err(ProfileError::OperationMismatch)
        );
    }
}
#[test]
fn export_permissions_are_explicit_and_never_implied_by_signing() {
    let mut request = intent(O::SignMessage, pss(), P::Message { bytes: 100 });
    request.export = ExportRequirement::Private;
    assert_eq!(request.validate(), Err(ProfileError::OperationMismatch));
    request.operation = O::ExportPublic;
    request.payload = P::None;
    request.export = ExportRequirement::Public;
    assert!(request.validate().is_ok());
    request.export = ExportRequirement::Private;
    assert_eq!(request.validate(), Err(ProfileError::OperationMismatch));
    request.operation = O::ExportPrivate;
    assert!(request.validate().is_ok());
}
#[test]
fn extensions_require_bounded_non_secret_names_and_fields() {
    let mut params = BTreeMap::new();
    params.insert("custom_size".to_string(), "v2".to_string());
    let profile = A::Extension(ExtensionProfile {
        namespace: "org.example".into(),
        identifier: "experimental_sig".into(),
        parameters: params,
    });
    assert!(profile.validate().is_ok());
    assert!(
        intent(
            O::Extension {
                namespace: "org.example".into(),
                identifier: "demo".into()
            },
            profile.clone(),
            P::None
        )
        .validate()
        .is_ok()
    );
    assert_eq!(
        intent(O::SignMessage, profile, P::Message { bytes: 32 }).validate(),
        Err(ProfileError::OperationMismatch)
    );
    let bad = A::Extension(ExtensionProfile {
        namespace: "org.example".into(),
        identifier: "access_token".into(),
        parameters: BTreeMap::new(),
    });
    assert_eq!(bad.validate(), Err(ProfileError::InvalidExtension));
}
#[test]
fn digest_profile_mutation_checks_do_not_infer_hash_from_byte_length() {
    let hash_types = [
        D::Sha256,
        D::Sha3_256,
        D::Sha384,
        D::Sha3_384,
        D::Sha512,
        D::Sha3_512,
    ];
    for algorithm in hash_types {
        for input_hash in hash_types {
            let req = intent(
                O::SignDigest { digest: algorithm },
                ecdsa(),
                P::Digest {
                    algorithm: input_hash,
                    bytes: input_hash.output_bytes(),
                },
            );
            if algorithm == D::Sha256 && input_hash == D::Sha256 {
                assert!(req.validate().is_ok());
            } else {
                assert!(req.validate().is_err());
            }
        }
    }
}
