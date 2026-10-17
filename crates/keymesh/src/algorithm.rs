//! Strongly typed cryptographic algorithm profiles and operation intent.
//!
//! No primitive or provider call is executed here. This taxonomy prevents
//! cryptographic operations, payload forms and parameter sets from being
//! silently substituted during future adapter dispatch.

use crate::binding::RequiredAssurance;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Hash function carried explicitly by digest-signing and hash profiles.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DigestAlgorithm {
    /// SHA-256.
    Sha256,
    /// SHA-384.
    Sha384,
    /// SHA-512.
    Sha512,
    /// SHA3-256.
    Sha3_256,
    /// SHA3-384.
    Sha3_384,
    /// SHA3-512.
    Sha3_512,
}
impl DigestAlgorithm {
    /// Required digest length. Never infer digest identity from byte length.
    pub const fn output_bytes(self) -> u16 {
        match self {
            Self::Sha256 | Self::Sha3_256 => 32,
            Self::Sha384 | Self::Sha3_384 => 48,
            Self::Sha512 | Self::Sha3_512 => 64,
        }
    }
}

/// Named elliptic curve; algorithm profile includes the digest independently.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EcCurve {
    /// NIST P-256.
    P256,
    /// NIST P-384.
    P384,
    /// NIST P-521.
    P521,
}

/// ECDSA signature representation; DER and IEEE P1363 must not be confused.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EcdsaEncoding {
    /// ASN.1 DER sequence of integers.
    Der,
    /// Fixed-width concatenated r || s representation.
    P1363,
}

/// A concrete EdDSA variant. Prehash modes require separate, future profiles.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EdDsaVariant {
    /// Pure Ed25519 message signing.
    Ed25519,
    /// Pure Ed448 message signing.
    Ed448,
}

/// AES key-wrap mechanism; neither mode is an AES-GCM cipher mode.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AesWrapVariant {
    /// RFC 3394 AES Key Wrap.
    Rfc3394,
    /// RFC 5649 padded AES Key Wrap.
    Rfc5649,
}

/// FIPS 203 ML-KEM parameter set, not a general encryption algorithm.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MlKemVariant {
    /// ML-KEM-512.
    MlKem512,
    /// ML-KEM-768.
    MlKem768,
    /// ML-KEM-1024.
    MlKem1024,
}
impl MlKemVariant {
    /// FIPS 203 fixed encapsulation ciphertext size for the exact parameter set.
    pub const fn ciphertext_bytes(self) -> u64 {
        match self {
            Self::MlKem512 => 768,
            Self::MlKem768 => 1088,
            Self::MlKem1024 => 1568,
        }
    }
}

/// FIPS 204 ML-DSA parameter set, not a digest algorithm.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MlDsaVariant {
    /// ML-DSA-44.
    MlDsa44,
    /// ML-DSA-65.
    MlDsa65,
    /// ML-DSA-87.
    MlDsa87,
}

/// Explicit ML-DSA input transformation, including provider-specific mu mode.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(
    tag = "mode",
    content = "parameters",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum MlDsaInput {
    /// Pure ML-DSA signs the message under the provider's precise profile.
    Pure,
    /// HashML-DSA: provider applies the explicitly named prehash to a message.
    HashMessage {
        /// Prehash algorithm; not an arbitrary externally supplied digest.
        digest: DigestAlgorithm,
    },
    /// A provider-specific externally computed 64-byte mu; not SignDigest.
    ExternalMu,
}

/// FIPS 205 SLH-DSA parameter set (hash family, strength and speed class).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SlhDsaVariant {
    /// SHA2-128s.
    Sha2_128s,
    /// SHA2-128f.
    Sha2_128f,
    /// SHA2-192s.
    Sha2_192s,
    /// SHA2-192f.
    Sha2_192f,
    /// SHA2-256s.
    Sha2_256s,
    /// SHA2-256f.
    Sha2_256f,
    /// SHAKE-128s.
    Shake128s,
    /// SHAKE-128f.
    Shake128f,
    /// SHAKE-192s.
    Shake192s,
    /// SHAKE-192f.
    Shake192f,
    /// SHAKE-256s.
    Shake256s,
    /// SHAKE-256f.
    Shake256f,
}

/// A forward-compatible, non-executable-by-default algorithm extension envelope.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExtensionProfile {
    /// Vendor or standards namespace, e.g. org.example.
    pub namespace: String,
    /// Algorithm identifier in that namespace.
    pub identifier: String,
    /// Bounded, printable, non-secret parameter identifiers and values.
    pub parameters: BTreeMap<String, String>,
}

/// An algorithm with exact parameters. No algorithm family means "any variant".
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(
    tag = "family",
    content = "parameters",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum AlgorithmProfile {
    /// RSA-PSS signing: key modulus, signature hash, MGF1 hash and salt bytes.
    RsaPss {
        /// RSA modulus size.
        modulus_bits: u16,
        /// Message digest function.
        digest: DigestAlgorithm,
        /// MGF1 digest; never silently assumed equal to digest.
        mgf1_digest: DigestAlgorithm,
        /// Explicit salt length.
        salt_bytes: u16,
    },
    /// RSA-OAEP encryption/key wrapping with explicit MGF1 profile.
    RsaOaep {
        /// RSA modulus size.
        modulus_bits: u16,
        /// OAEP hash function.
        digest: DigestAlgorithm,
        /// MGF1 hash function.
        mgf1_digest: DigestAlgorithm,
    },
    /// ECDSA with precise curve, digest and signature encoding.
    Ecdsa {
        /// Elliptic curve.
        curve: EcCurve,
        /// Hash function.
        digest: DigestAlgorithm,
        /// Signature byte representation.
        encoding: EcdsaEncoding,
    },
    /// Pure EdDSA (prehash modes must never be treated as pure EdDSA).
    EdDsa {
        /// Pure EdDSA variant.
        variant: EdDsaVariant,
    },
    /// AES-GCM authenticated symmetric encryption, not wrapping.
    AesGcm {
        /// Key length in bits.
        key_bits: u16,
        /// Nonce length in bytes; v1 requires 12.
        nonce_bytes: u8,
        /// Tag length in bytes; v1 requires 16.
        tag_bytes: u8,
    },
    /// AES Key Wrap (with or without padding), not AES-GCM encryption.
    AesKeyWrap {
        /// Key-encryption-key length in bits.
        key_bits: u16,
        /// RFC 3394 or 5649 variant.
        variant: AesWrapVariant,
    },
    /// HMAC authentication; distinct from digital signatures.
    Hmac {
        /// Hash function.
        digest: DigestAlgorithm,
        /// Key length in bits.
        key_bits: u16,
    },
    /// HKDF key derivation; does not sign or encrypt messages.
    Hkdf {
        /// Pseudorandom-key hash function.
        digest: DigestAlgorithm,
    },
    /// FIPS 203 KEM; only encapsulation/decapsulation applies.
    MlKem {
        /// FIPS 203 parameter set.
        variant: MlKemVariant,
    },
    /// FIPS 204 signatures with explicitly classified input transformation.
    MlDsa {
        /// FIPS 204 parameter set.
        variant: MlDsaVariant,
        /// Pure, HashML-DSA, or provider-specific external mu.
        input: MlDsaInput,
    },
    /// FIPS 205 hash-based digital signature.
    SlhDsa {
        /// FIPS 205 parameter set.
        variant: SlhDsaVariant,
    },
    /// An opaque, namespaced extension; no implicit authorization.
    Extension(ExtensionProfile),
}

/// Typed cryptographic operation; distinct permissions cannot be equated.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(
    tag = "type",
    content = "details",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum CryptoOperation {
    /// Provider receives raw message; any internal hashing is profile-specific.
    SignMessage,
    /// Provider receives a precomputed digest, never a message to rehash.
    SignDigest {
        /// Expected digest algorithm, not inferred from input bytes.
        digest: DigestAlgorithm,
    },
    /// Verify a signature over an original message.
    VerifyMessage,
    /// Verify a signature over an explicitly identified precomputed digest.
    VerifyDigest {
        /// Expected digest algorithm.
        digest: DigestAlgorithm,
    },
    /// Sign provider-specific externally computed ML-DSA mu.
    SignExternalMu,
    /// Verify provider-specific externally computed ML-DSA mu.
    VerifyExternalMu,
    /// Encrypt a message (not authorization to wrap keys).
    Encrypt,
    /// Decrypt a ciphertext (not authorization to unwrap keys).
    Decrypt,
    /// Wrap key material, even when underlying RSA primitives are reused.
    WrapKey,
    /// Unwrap previously wrapped key material.
    UnwrapKey,
    /// Generate a keyed MAC (not a digital signature).
    MacMessage,
    /// Verify a keyed MAC.
    VerifyMacMessage,
    /// Generate a KEM ciphertext and shared secret.
    Encapsulate,
    /// Recover a KEM shared secret from ciphertext.
    Decapsulate,
    /// Derive key bytes under an explicit KDF.
    DeriveKey,
    /// Generate a new key.
    Generate,
    /// Import key material into a provider.
    Import,
    /// Rotate a logical key or provider version.
    Rotate,
    /// Enable an existing key.
    Enable,
    /// Disable an existing key.
    Disable,
    /// Schedule deferred deletion.
    ScheduleDelete,
    /// Recover a disabled/deleted key when supported.
    Recover,
    /// Irreversibly purge a key with separate approval in later increments.
    Purge,
    /// Export only public key material.
    ExportPublic,
    /// Export private or secret material, independently approved and feature-gated.
    ExportPrivate,
    /// Explicit vendor operation extension, never dispatched by default.
    Extension {
        /// Vendor or standards namespace.
        namespace: String,
        /// Operation name.
        identifier: String,
    },
}

/// Metadata about supplied input; never carries plaintext, private keys or secrets.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(
    tag = "form",
    content = "parameters",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum PayloadDescriptor {
    /// No operation payload.
    None,
    /// Original message (not a digest).
    Message {
        /// Message size in bytes.
        bytes: u64,
    },
    /// A precomputed digest with explicit function and exact output length.
    Digest {
        /// Prehash function.
        algorithm: DigestAlgorithm,
        /// Input bytes; must equal digest output length.
        bytes: u16,
    },
    /// ML-DSA external mu (a separate 64-byte typed input).
    ExternalMu {
        /// Exactly 64 bytes.
        bytes: u16,
    },
    /// Encrypted or wrapped byte string.
    Ciphertext {
        /// Number of ciphertext bytes.
        bytes: u64,
    },
    /// Import/wrap input only; no raw secret material in this descriptor.
    KeyMaterial {
        /// Declared material length.
        bytes: u64,
    },
    /// HKDF derivation metadata only.
    Derivation {
        /// HKDF info context size.
        info_bytes: u64,
        /// Requested output size.
        output_bytes: u64,
    },
}

/// Exact version/binding required before any provider dispatch.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VersionRequirement {
    /// Stable native resource ID (underlying material may rotate).
    StableResource,
    /// Provider-selectable version of a resource.
    ProviderVersion,
    /// Provider-selectable cryptographic material revision.
    MaterialRevision,
}
impl VersionRequirement {
    /// Convert to the preflight contract introduced in KM-02.
    pub const fn binding(self) -> RequiredAssurance {
        match self {
            Self::StableResource => RequiredAssurance::StableResource,
            Self::ProviderVersion => RequiredAssurance::ProviderVersion,
            Self::MaterialRevision => RequiredAssurance::MaterialVersion,
        }
    }
}

/// Protection assurance required by application policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtectionRequirement {
    /// No specific physical key-protection requirement.
    Any,
    /// Independently host-validated HSM custody.
    Hsm,
    /// Independently host-validated TEE custody, not automatically HSM.
    Tee,
}

/// Key export requirement, independent of crypto-operation permission.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExportRequirement {
    /// No key export requested.
    None,
    /// Public key export only.
    Public,
    /// Export private/secret material; must be independently authorized.
    Private,
}

/// Validated operation intent (metadata only), for later provider admission.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationIntent {
    /// Exact permission/operation and any digest mode.
    pub operation: CryptoOperation,
    /// Exact algorithm profile and parameters.
    pub profile: AlgorithmProfile,
    /// Input shape; no bytes/credentials are stored here.
    pub payload: PayloadDescriptor,
    /// Required binding strength for eventual pre-dispatch.
    pub binding: VersionRequirement,
    /// Minimum independently verified protection class.
    pub protection: ProtectionRequirement,
    /// Private/public export requirement, if any.
    pub export: ExportRequirement,
}

/// Failure to validate an algorithm/operation profile; never echoes inputs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProfileError {
    /// Invalid, insecure, or unsupported parameter combination.
    InvalidParameters,
    /// The operation is not defined for that algorithm family or transform.
    OperationMismatch,
    /// Message/digest/ciphertext/key input form is incorrect.
    PayloadMismatch,
    /// A declared digest algorithm does not match the profile.
    DigestMismatch,
    /// Digest or specialized prehash has the wrong byte length.
    DigestLengthMismatch,
    /// Input exceeds an algorithm-specific structural limit.
    AlgorithmInputTooLarge,
    /// A fixed-size ciphertext does not match its exact algorithm parameter set.
    CiphertextLengthMismatch,
    /// Vendor extension has unsafe names, parameters, or unbounded fields.
    InvalidExtension,
}
impl std::fmt::Display for ProfileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let text = match self {
            Self::InvalidParameters => "invalid algorithm parameters",
            Self::OperationMismatch => "algorithm and operation are incompatible",
            Self::PayloadMismatch => "invalid operation input classification",
            Self::DigestMismatch => "digest algorithm does not match profile",
            Self::DigestLengthMismatch => "invalid digest or prehash length",
            Self::AlgorithmInputTooLarge => "algorithm structural input limit exceeded",
            Self::CiphertextLengthMismatch => "ciphertext length does not match algorithm profile",
            Self::InvalidExtension => "invalid extension envelope",
        };
        f.write_str(text)
    }
}
impl std::error::Error for ProfileError {}

fn allowed_extension_label(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= 64
        && !matches!(label, "." | "..")
        && label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        && ![
            "pin",
            "secret",
            "token",
            "password",
            "credential",
            "signature",
            "apikey",
        ]
        .iter()
        .any(|bad| label.to_ascii_lowercase().contains(bad))
}

fn validate_extension(ext: &ExtensionProfile) -> Result<(), ProfileError> {
    if !allowed_extension_label(&ext.namespace)
        || !allowed_extension_label(&ext.identifier)
        || ext.parameters.len() > 16
        || ext.parameters.iter().any(|(key, value)| {
            !allowed_extension_label(key)
                || value.len() > 128
                || !value
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        })
    {
        return Err(ProfileError::InvalidExtension);
    }
    Ok(())
}

impl AlgorithmProfile {
    /// Check structural security bounds without claiming provider support.
    pub fn validate(&self) -> Result<(), ProfileError> {
        match self {
            Self::RsaPss {
                modulus_bits,
                digest,
                salt_bytes,
                ..
            } => {
                if !valid_modulus(*modulus_bits)
                    || u32::from(*salt_bytes) + u32::from(digest.output_bytes()) + 2
                        > u32::from(*modulus_bits) / 8
                {
                    return Err(ProfileError::InvalidParameters);
                }
            }
            Self::RsaOaep {
                modulus_bits,
                digest,
                ..
            } => {
                if !valid_modulus(*modulus_bits)
                    || u32::from(*modulus_bits) / 8 <= 2 * u32::from(digest.output_bytes()) + 2
                {
                    return Err(ProfileError::InvalidParameters);
                }
            }
            Self::MlDsa {
                variant,
                input: MlDsaInput::HashMessage { digest },
            } => {
                // FIPS 204 5.4: prehash collision strength must be at least
                // twice the classical signature security strength.
                let min_bytes = match variant {
                    MlDsaVariant::MlDsa44 => 32,
                    MlDsaVariant::MlDsa65 => 48,
                    MlDsaVariant::MlDsa87 => 64,
                };
                if digest.output_bytes() < min_bytes {
                    return Err(ProfileError::InvalidParameters);
                }
            }
            Self::Ecdsa { .. }
            | Self::EdDsa { .. }
            | Self::Hkdf { .. }
            | Self::MlKem { .. }
            | Self::MlDsa { .. }
            | Self::SlhDsa { .. } => {}
            Self::AesGcm {
                key_bits,
                nonce_bytes,
                tag_bytes,
            } => {
                if !valid_aes_bits(*key_bits) || *nonce_bytes != 12 || *tag_bytes != 16 {
                    return Err(ProfileError::InvalidParameters);
                }
            }
            Self::AesKeyWrap { key_bits, .. } => {
                if !valid_aes_bits(*key_bits) {
                    return Err(ProfileError::InvalidParameters);
                }
            }
            Self::Hmac { key_bits, .. } => {
                if !(128..=4096).contains(key_bits) || key_bits % 8 != 0 {
                    return Err(ProfileError::InvalidParameters);
                }
            }
            Self::Extension(profile) => validate_extension(profile)?,
        }
        Ok(())
    }
}

fn valid_aes_bits(bits: u16) -> bool {
    matches!(bits, 128 | 192 | 256)
}
fn valid_modulus(bits: u16) -> bool {
    (2048..=16384).contains(&bits) && bits % 256 == 0
}

impl OperationIntent {
    /// Fail closed on operation-family and payload-shape mismatches.
    ///
    /// This validates input *metadata*. The real payload must be checked
    /// again at the provider boundary, and the exact capability must be
    /// confirmed before cryptographic execution (KM-05).
    pub fn validate(&self) -> Result<(), ProfileError> {
        use AlgorithmProfile as A;
        use CryptoOperation as O;
        use PayloadDescriptor as P;
        self.profile.validate()?;
        if matches!(self.operation, O::ExportPublic) && self.export != ExportRequirement::Public {
            return Err(ProfileError::OperationMismatch);
        }
        if matches!(self.operation, O::ExportPrivate) && self.export != ExportRequirement::Private {
            return Err(ProfileError::OperationMismatch);
        }
        if !matches!(self.operation, O::ExportPublic | O::ExportPrivate)
            && self.export != ExportRequirement::None
        {
            return Err(ProfileError::OperationMismatch);
        }
        if let O::Extension {
            namespace,
            identifier,
        } = &self.operation
        {
            if !allowed_extension_label(namespace) || !allowed_extension_label(identifier) {
                return Err(ProfileError::InvalidExtension);
            }
            if !matches!(self.profile, A::Extension(_)) {
                return Err(ProfileError::OperationMismatch);
            }
            return Ok(());
        }
        // Lifecycle operations are distinct capabilities. The import payload
        // is metadata only and never transported through this type.
        match &self.operation {
            O::Generate
            | O::Rotate
            | O::Enable
            | O::Disable
            | O::ScheduleDelete
            | O::Recover
            | O::Purge
            | O::ExportPublic
            | O::ExportPrivate => {
                if !matches!(self.payload, P::None) {
                    return Err(ProfileError::PayloadMismatch);
                }
                if matches!(self.operation, O::ExportPublic | O::ExportPrivate)
                    && matches!(
                        self.profile,
                        A::AesGcm { .. } | A::AesKeyWrap { .. } | A::Hmac { .. } | A::Hkdf { .. }
                    )
                {
                    return Err(ProfileError::OperationMismatch);
                }
                return Ok(());
            }
            O::Import => {
                if !matches!(self.payload, P::KeyMaterial { bytes } if bytes > 0) {
                    return Err(ProfileError::PayloadMismatch);
                }
                return Ok(());
            }
            _ => {}
        }
        if matches!(self.profile, A::Extension(_)) {
            return Err(ProfileError::OperationMismatch);
        }
        let allowed = match (&self.operation, &self.profile) {
            (
                O::SignMessage | O::VerifyMessage,
                A::RsaPss { .. } | A::Ecdsa { .. } | A::EdDsa { .. } | A::SlhDsa { .. },
            ) => matches!(self.payload, P::Message { .. }),
            (
                O::SignMessage | O::VerifyMessage,
                A::MlDsa {
                    input: MlDsaInput::Pure | MlDsaInput::HashMessage { .. },
                    ..
                },
            ) => matches!(self.payload, P::Message { .. }),
            (
                O::SignDigest { digest } | O::VerifyDigest { digest },
                A::RsaPss {
                    digest: profile, ..
                }
                | A::Ecdsa {
                    digest: profile, ..
                },
            ) => {
                if digest != profile {
                    return Err(ProfileError::DigestMismatch);
                }
                match self.payload {
                    P::Digest { algorithm, bytes }
                        if algorithm == *digest && bytes == digest.output_bytes() =>
                    {
                        true
                    }
                    P::Digest { algorithm, .. } if algorithm != *digest => {
                        return Err(ProfileError::DigestMismatch);
                    }
                    P::Digest { .. } => return Err(ProfileError::DigestLengthMismatch),
                    _ => return Err(ProfileError::PayloadMismatch),
                }
            }
            (
                O::SignExternalMu | O::VerifyExternalMu,
                A::MlDsa {
                    input: MlDsaInput::ExternalMu,
                    ..
                },
            ) => {
                if let P::ExternalMu { bytes } = self.payload {
                    if bytes != 64 {
                        return Err(ProfileError::DigestLengthMismatch);
                    }
                    true
                } else {
                    return Err(ProfileError::PayloadMismatch);
                }
            }
            (O::Encrypt | O::Decrypt, A::AesGcm { .. }) => match self.operation {
                O::Encrypt => matches!(self.payload, P::Message { .. }),
                _ => matches!(self.payload, P::Ciphertext { .. }),
            },
            (
                O::Encrypt | O::Decrypt | O::WrapKey | O::UnwrapKey,
                A::RsaOaep {
                    modulus_bits,
                    digest,
                    ..
                },
            ) => match (&self.operation, &self.payload) {
                (O::Encrypt, P::Message { bytes }) | (O::WrapKey, P::KeyMaterial { bytes }) => {
                    let max =
                        u64::from(*modulus_bits) / 8 - 2 * u64::from(digest.output_bytes()) - 2;
                    if *bytes > max {
                        return Err(ProfileError::AlgorithmInputTooLarge);
                    }
                    true
                }
                (O::Decrypt | O::UnwrapKey, P::Ciphertext { bytes }) => {
                    if *bytes != u64::from(*modulus_bits) / 8 {
                        return Err(ProfileError::AlgorithmInputTooLarge);
                    }
                    true
                }
                _ => false,
            },
            (O::WrapKey | O::UnwrapKey, A::AesKeyWrap { variant, .. }) => {
                match (&self.operation, &self.payload) {
                    (O::WrapKey, P::KeyMaterial { bytes }) => {
                        if *bytes == 0
                            || matches!(variant, AesWrapVariant::Rfc3394)
                                && (*bytes < 16 || bytes % 8 != 0)
                        {
                            return Err(ProfileError::InvalidParameters);
                        }
                        true
                    }
                    (O::UnwrapKey, P::Ciphertext { bytes }) => {
                        // RFC 3394: 8-byte A value + >=2 blocks (>=24 bytes).
                        // RFC 5649 padded key wrap admits a 16-byte ciphertext.
                        let min_bytes = match variant {
                            AesWrapVariant::Rfc3394 => 24,
                            AesWrapVariant::Rfc5649 => 16,
                        };
                        if *bytes < min_bytes || bytes % 8 != 0 {
                            return Err(ProfileError::InvalidParameters);
                        }
                        true
                    }
                    _ => false,
                }
            }
            (O::MacMessage | O::VerifyMacMessage, A::Hmac { .. }) => {
                matches!(self.payload, P::Message { .. })
            }
            (O::Encapsulate, A::MlKem { .. }) => matches!(self.payload, P::None),
            (O::Decapsulate, A::MlKem { variant }) => match self.payload {
                P::Ciphertext { bytes } if bytes == variant.ciphertext_bytes() => true,
                P::Ciphertext { .. } => return Err(ProfileError::CiphertextLengthMismatch),
                _ => false,
            },
            (O::DeriveKey, A::Hkdf { digest }) => {
                if let P::Derivation {
                    info_bytes,
                    output_bytes,
                } = self.payload
                {
                    if info_bytes > 65536
                        || output_bytes == 0
                        || output_bytes > 255 * u64::from(digest.output_bytes())
                    {
                        return Err(ProfileError::AlgorithmInputTooLarge);
                    }
                    true
                } else {
                    false
                }
            }
            _ => false,
        };
        if !allowed {
            return Err(ProfileError::OperationMismatch);
        }
        Ok(())
    }
}
