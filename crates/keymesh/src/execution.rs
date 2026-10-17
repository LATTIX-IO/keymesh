//! Fail-closed checked execution gateway. Provider reads precede any
//! crypto/lifecycle dispatch; all failures before that boundary are NotDispatched.
//! A policy evaluator is injected by the host. No runtime/SDK/retry is included.

use crate::{
    BindingAssurance, BindingError, CapabilityError, CorrelationId, CryptoOperation,
    DigestAlgorithm, DispatchTarget, HostScope, HostValidatedCapabilities, KeyProvider, KeyRef,
    LogicalKeyId, OperationIntent, PayloadDescriptor, PreparedDispatch, ProfileError,
    ProviderCapabilities, ProviderError, ProviderErrorKind, ProviderFuture, ProviderInstanceId,
    ProviderNamespace, ProviderOutput, ProviderReply, ResolvedKey, preflight_bind,
};
use core::fmt;

/// Policy verdict from the host-mandated policy hook. No implicit allow.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolicyVerdict {
    /// Host policy permits this specific scope/key/operation snapshot.
    Permit,
    /// Host policy explicitly denied.
    Deny,
    /// Policy cannot determine an enforceable result.
    Indeterminate,
}

/// Safe view provided to a host-defined policy hook. No secret input,
/// credentials, raw message bytes or private key material are exposed.
pub struct PolicyContext<'a> {
    /// Host-authorized provider/namespace.
    pub scope: &'a HostScope,
    /// Requested logical reference.
    pub reference: &'a KeyRef,
    /// Provider-read-only concrete resolution proposal.
    pub resolved: &'a ResolvedKey,
    /// Provider-reported, non-attested capabilities.
    pub catalog: &'a ProviderCapabilities,
    /// Exact requested operation profile and payload length metadata.
    pub intent: &'a OperationIntent,
}

/// Mandatory asynchronous policy hook. The host implements the evaluator.
/// Calling this trait does not authenticate the host or prove policy freshness.
pub trait PolicyGate: Send + Sync {
    /// Return permit/deny/indeterminate, with no provider crypto side effects.
    fn evaluate<'a>(&'a self, context: &'a PolicyContext<'_>) -> ProviderFuture<'a, PolicyVerdict>;
}

/// Borrowed and deliberately non-Debug operation input. Secret-bearing bytes
/// are never copied into error messages or telemetry by Keymesh.
pub enum OperationInput<'a> {
    /// Key/lifecycle actions with no input bytes.
    None,
    /// Original message, plus a signature/tag only for verify operations.
    Message {
        /// Raw original bytes.
        bytes: &'a [u8],
        /// Signature or MAC tag for verification, not secret key material.
        authenticator: Option<&'a [u8]>,
    },
    /// Named precomputed digest, not a message for re-hashing.
    Digest {
        /// Explicit digest algorithm.
        algorithm: DigestAlgorithm,
        /// Exact precomputed digest bytes.
        bytes: &'a [u8],
        /// Signature bytes when verifying; absent when signing.
        authenticator: Option<&'a [u8]>,
    },
    /// Provider-specific ML-DSA 64-byte mu; not arbitrary SignDigest.
    ExternalMu {
        /// Externally computed mu bytes.
        bytes: &'a [u8],
        /// Signature for verification only.
        authenticator: Option<&'a [u8]>,
    },
    /// Ciphertext input for a corresponding typed decrypt/unwrap/decap.
    Ciphertext(&'a [u8]),
    /// Raw key input to a wrapping/import boundary. KM-07 must replace this
    /// with a sensitive-memory wrapper before any production adapter.
    KeyMaterial(&'a [u8]),
    /// HKDF derivation info and a separately bounded output length.
    Derivation {
        /// Public context info (never a secret master key).
        info: &'a [u8],
        /// Requested secret output size, not part of provider input-size cap.
        output_bytes: u64,
    },
}
impl OperationInput<'_> {
    /// Classify actual bytes into KM-04 payload metadata and check whether
    /// authenticator/signature is present only for verify operations.
    pub fn classify(
        &self,
        operation: &CryptoOperation,
    ) -> Result<PayloadDescriptor, ProviderError> {
        use CryptoOperation as O;
        let requires_proof = matches!(
            operation,
            O::VerifyMessage | O::VerifyDigest { .. } | O::VerifyExternalMu | O::VerifyMacMessage
        );
        let proof_ok = |authenticator: &Option<&[u8]>| -> bool {
            if requires_proof {
                authenticator.is_some_and(|p| !p.is_empty())
            } else {
                authenticator.is_none()
            }
        };
        let invalid = || ProviderError::not_dispatched(ProviderErrorKind::InvalidInput);
        match self {
            Self::None => Ok(PayloadDescriptor::None),
            Self::Message {
                bytes,
                authenticator,
            } => {
                if !proof_ok(authenticator) {
                    return Err(invalid());
                }
                Ok(PayloadDescriptor::Message {
                    bytes: bytes.len() as u64,
                })
            }
            Self::Digest {
                algorithm,
                bytes,
                authenticator,
            } => {
                if !proof_ok(authenticator) {
                    return Err(invalid());
                }
                let len = u16::try_from(bytes.len()).map_err(|_| invalid())?;
                Ok(PayloadDescriptor::Digest {
                    algorithm: *algorithm,
                    bytes: len,
                })
            }
            Self::ExternalMu {
                bytes,
                authenticator,
            } => {
                if !proof_ok(authenticator) {
                    return Err(invalid());
                }
                let len = u16::try_from(bytes.len()).map_err(|_| invalid())?;
                Ok(PayloadDescriptor::ExternalMu { bytes: len })
            }
            Self::Ciphertext(bytes) => Ok(PayloadDescriptor::Ciphertext {
                bytes: bytes.len() as u64,
            }),
            Self::KeyMaterial(bytes) => Ok(PayloadDescriptor::KeyMaterial {
                bytes: bytes.len() as u64,
            }),
            Self::Derivation { info, output_bytes } => Ok(PayloadDescriptor::Derivation {
                info_bytes: info.len() as u64,
                output_bytes: *output_bytes,
            }),
        }
    }
}

/// Borrowed request to the provider execution gateway. These host-supplied
/// authorities are not self-authenticating; the embedding application MUST
/// construct HostScope/host assurance from verified identity and config.
pub struct OperationRequest<'a> {
    /// Host-approved scope, independent of the caller-provided KeyRef.
    pub scope: &'a HostScope,
    /// Untrusted but validated logical key reference.
    pub reference: &'a KeyRef,
    /// Independently host-verified provider custody and version semantics.
    pub host_assurance: &'a HostValidatedCapabilities,
    /// Exact KM-04 typed operation and declared payload metadata.
    pub intent: &'a OperationIntent,
    /// Real, borrowed payload bytes; never printed by this library.
    pub input: OperationInput<'a>,
    /// Safe audit correlation only; not a bearer token.
    pub correlation: &'a CorrelationId,
}

/// Immutable operation evidence constructed by the checked gateway only.
/// Provider claims do not constitute cryptographic/HSM attestation.
#[derive(Clone, Eq, PartialEq)]
pub struct OperationEvidence {
    /// Instance configured by host and reported by provider.
    pub provider: ProviderInstanceId,
    /// Host-authorized tenant namespace.
    pub namespace: ProviderNamespace,
    /// Logical key used in read-only resolution.
    pub logical_key: LogicalKeyId,
    /// Concrete provider target with no alias.
    pub target: DispatchTarget,
    /// Exact provider/version assurance of this binding.
    pub assurance: BindingAssurance,
    /// Operation that was admitted and dispatched.
    pub operation: CryptoOperation,
    /// Correlation token, redacted from Debug.
    pub correlation: CorrelationId,
    /// Optional provider receipt token; a claim, not signed attestation.
    pub provider_request_id: Option<CorrelationId>,
    /// Operation success was confirmed by provider response (not hardware proof).
    pub outcome: crate::OperationState,
}
impl fmt::Debug for OperationEvidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OperationEvidence(<redacted: provider/tenant/target/correlation>)")
    }
}

/// Checked successful result. All public artifacts are returned separately
/// from redacted evidence; no private material is embedded in Debug.
pub struct OperationCompletion {
    /// Operation identity and claimed result provenance.
    pub evidence: OperationEvidence,
    /// Type-checked provider output.
    pub output: ProviderOutput,
}
impl fmt::Debug for OperationCompletion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OperationCompletion(<redacted>)")
    }
}

/// Maximum byte length of a verification signature/MAC accepted at preflight.
/// Individual profiles impose tighter checks; adapters validate signature
/// encoding/DER and cryptographic correctness at their native boundary.
pub const MAX_VERIFICATION_PROOF_BYTES: usize = 65_536;

fn validate_authenticator(
    input: &OperationInput<'_>,
    intent: &OperationIntent,
) -> Result<(), ProviderError> {
    let proof = match input {
        OperationInput::Message { authenticator, .. }
        | OperationInput::Digest { authenticator, .. }
        | OperationInput::ExternalMu { authenticator, .. } => *authenticator,
        _ => None,
    };
    let Some(bytes) = proof else {
        return Ok(());
    };
    let n = bytes.len();
    let invalid = || ProviderError::not_dispatched(ProviderErrorKind::InvalidInput);
    if n == 0 || n > MAX_VERIFICATION_PROOF_BYTES {
        return Err(invalid());
    }
    use crate::{AlgorithmProfile as A, EcCurve, EcdsaEncoding, EdDsaVariant};
    let valid = match &intent.profile {
        A::RsaPss { modulus_bits, .. } => n == usize::from(*modulus_bits) / 8,
        A::Ecdsa {
            curve, encoding, ..
        } => {
            let bytes_per_integer = match curve {
                EcCurve::P256 => 32usize,
                EcCurve::P384 => 48,
                EcCurve::P521 => 66,
            };
            match encoding {
                EcdsaEncoding::P1363 => n == bytes_per_integer * 2,
                EcdsaEncoding::Der => (8..=(bytes_per_integer * 2 + 16)).contains(&n),
            }
        }
        A::EdDsa { variant } => {
            n == match variant {
                EdDsaVariant::Ed25519 => 64,
                EdDsaVariant::Ed448 => 114,
            }
        }
        A::MlDsa { variant, .. } => {
            n == match variant {
                crate::MlDsaVariant::MlDsa44 => 2420,
                crate::MlDsaVariant::MlDsa65 => 3309,
                crate::MlDsaVariant::MlDsa87 => 4627,
            }
        }
        A::SlhDsa { variant } => {
            use crate::SlhDsaVariant as V;
            n == match variant {
                V::Sha2_128s | V::Shake128s => 7856,
                V::Sha2_128f | V::Shake128f => 17088,
                V::Sha2_192s | V::Shake192s => 16224,
                V::Sha2_192f | V::Shake192f => 35664,
                V::Sha2_256s | V::Shake256s => 29792,
                V::Sha2_256f | V::Shake256f => 49856,
            }
        }
        A::Hmac { digest, .. } => n == usize::from(digest.output_bytes()),
        _ => false,
    };
    if !valid {
        return Err(invalid());
    }
    Ok(())
}

/// Capability and resolution reads are declared side-effect-free by the
/// adapter contract. Their errors therefore cannot establish any operation
/// commit state. Never report a read timeout as UnknownCommitState for crypto.
fn read_error(error: ProviderError) -> ProviderError {
    let kind = match error.kind() {
        ProviderErrorKind::UnknownCommitState | ProviderErrorKind::InvalidOperationEvidence => {
            ProviderErrorKind::Unavailable
        }
        other => other,
    };
    ProviderError::not_dispatched(kind)
}

fn map_capability(error: CapabilityError) -> ProviderError {
    use CapabilityError as C;
    let kind = match error {
        C::InvalidIntent(_) | C::InvalidCatalog | C::DuplicateCapability => {
            ProviderErrorKind::InvalidInput
        }
        C::ScopeMismatch => ProviderErrorKind::ScopeMismatch,
        C::UnverifiedVersion => ProviderErrorKind::UnsupportedVersionAssurance,
        C::UnverifiedProtection => ProviderErrorKind::UnverifiedCapability,
        C::ExportNotPermitted => ProviderErrorKind::AuthorizationDenied,
        C::MissingCapability
        | C::UnsupportedCapability
        | C::UnknownCapability
        | C::ExtensionNotPermitted => ProviderErrorKind::UnsupportedOperationOrProfile,
        C::PayloadLimitUnknown | C::PayloadTooLarge => ProviderErrorKind::InvalidInput,
    };
    ProviderError::not_dispatched(kind)
}
fn map_binding(error: BindingError) -> ProviderError {
    let kind = match error {
        BindingError::UnsupportedVersionAssurance
        | BindingError::VersionMismatch
        | BindingError::MaterialRevisionMismatch => ProviderErrorKind::UnsupportedVersionAssurance,
        BindingError::ProviderMismatch
        | BindingError::NamespaceMismatch
        | BindingError::ResourceMismatch
        | BindingError::LogicalKeyMismatch => ProviderErrorKind::ScopeMismatch,
    };
    ProviderError::not_dispatched(kind)
}
fn map_profile(_error: ProfileError) -> ProviderError {
    ProviderError::not_dispatched(ProviderErrorKind::InvalidInput)
}
fn is_creation(operation: &CryptoOperation) -> bool {
    matches!(
        operation,
        CryptoOperation::Generate | CryptoOperation::Import
    )
}
fn is_destructive(operation: &CryptoOperation) -> bool {
    matches!(
        operation,
        CryptoOperation::Rotate | CryptoOperation::ScheduleDelete | CryptoOperation::Purge
    )
}

/// Checked gateway: host scope -> shape -> read-only capability/resolution ->
/// hard key binding -> mandatory policy -> exactly one provider operation.
///
/// Only this function constructs PreparedDispatch; adapter entrypoints do NOT
/// receive an unvalidated target from the caller. The method is runtime
/// neutral, but eventual native blocking calls belong in adapter executors.
/// An error after dispatch may be UnknownCommitState; dropping an in-flight
/// future does not prove the remote operation was cancelled.
///
/// # Security
///
/// Before the final provider method call, no cryptographic or lifecycle
/// operation is dispatched. Providers MUST keep capabilities()/resolve()
/// side-effect-free. Provider-side enforcement must revalidate actual key
/// and feature version at its own native boundary.
///
/// # Examples
///
/// See examples/provider_contract.rs for a runtime-neutral fake provider
/// proving an authorized operation can complete without a network client.
pub async fn execute_checked(
    provider: &dyn KeyProvider,
    policy: &dyn PolicyGate,
    request: OperationRequest<'_>,
) -> Result<OperationCompletion, ProviderError> {
    use CryptoOperation as O;
    let invalid = || ProviderError::not_dispatched(ProviderErrorKind::InvalidInput);

    // Host/provider/KeyRef binding is checked before ANY provider query.
    if provider.instance() != request.scope.provider()
        || request.reference.provider() != request.scope.provider()
        || request.reference.namespace() != request.scope.namespace()
    {
        return Err(ProviderError::not_dispatched(
            ProviderErrorKind::ScopeMismatch,
        ));
    }
    if request.host_assurance.scope.as_ref() != Some(request.scope) {
        return Err(ProviderError::not_dispatched(
            ProviderErrorKind::ScopeMismatch,
        ));
    }
    request.intent.validate().map_err(map_profile)?;
    let actual = request.input.classify(&request.intent.operation)?;
    if request.intent.payload != actual {
        return Err(invalid());
    }
    validate_authenticator(&request.input, request.intent)?;

    // No new-key creation or raw sensitive-material operation until KM-07 has
    // a safe creation/secret ownership contract; do not forge a BoundKey.
    if is_creation(&request.intent.operation) {
        return Err(ProviderError::not_dispatched(
            ProviderErrorKind::UnsupportedOperationOrProfile,
        ));
    }
    // Sensitive input ownership/zeroization is not implemented in KM-05.
    // Returning Unsupported is safer than exposing private input to a future
    // adapter through an unprotected, borrowed byte slice.
    if matches!(&request.input, OperationInput::KeyMaterial(_)) {
        return Err(ProviderError::not_dispatched(
            ProviderErrorKind::UnsupportedOperationOrProfile,
        ));
    }
    if is_destructive(&request.intent.operation)
        && matches!(
            request.reference.selector(),
            crate::KeySelector::Active | crate::KeySelector::Latest
        )
    {
        return Err(invalid());
    }
    // AES-GCM requires nonce/AAD/tag-specific request types and nonce
    // uniqueness guarantees. No such adapter boundary exists in KM-05.
    if matches!(
        request.intent.profile,
        crate::AlgorithmProfile::AesGcm { .. }
    ) && matches!(request.intent.operation, O::Encrypt | O::Decrypt)
    {
        return Err(ProviderError::not_dispatched(
            ProviderErrorKind::UnsupportedOperationOrProfile,
        ));
    }

    let catalog = provider
        .capabilities(request.scope)
        .await
        .map_err(read_error)?;
    catalog
        .admit(request.intent, request.host_assurance)
        .map_err(map_capability)?;
    let resolved = provider
        .resolve(request.scope, request.reference)
        .await
        .map_err(read_error)?;
    let bound = preflight_bind(
        request.reference,
        request.scope,
        &resolved,
        request.intent.binding.binding(),
    )
    .map_err(map_binding)?;

    let ctx = PolicyContext {
        scope: request.scope,
        reference: request.reference,
        resolved: &resolved,
        catalog: &catalog,
        intent: request.intent,
    };
    match policy.evaluate(&ctx).await {
        Ok(PolicyVerdict::Permit) => {}
        Ok(PolicyVerdict::Deny) => {
            return Err(ProviderError::not_dispatched(
                ProviderErrorKind::PolicyDenied,
            ));
        }
        Ok(PolicyVerdict::Indeterminate) | Err(_) => {
            return Err(ProviderError::not_dispatched(
                ProviderErrorKind::PolicyIndeterminate,
            ));
        }
    }

    let prepared = PreparedDispatch {
        bound,
        intent: request.intent,
        correlation: request.correlation,
        feature_revision: &catalog.feature_revision,
        protocol_revision: &catalog.protocol_revision,
    };
    // The only operation dispatch point. No generic implicit provider fallback.
    let reply: ProviderReply = match &request.intent.operation {
        O::SignMessage | O::SignDigest { .. } | O::SignExternalMu => {
            provider.sign(&prepared, &request.input).await?
        }
        O::VerifyMessage | O::VerifyDigest { .. } | O::VerifyExternalMu => {
            provider.verify(&prepared, &request.input).await?
        }
        O::Encrypt => provider.encrypt(&prepared, &request.input).await?,
        O::Decrypt => provider.decrypt(&prepared, &request.input).await?,
        O::WrapKey => provider.wrap_key(&prepared, &request.input).await?,
        O::UnwrapKey => provider.unwrap_key(&prepared, &request.input).await?,
        O::MacMessage | O::VerifyMacMessage => provider.mac(&prepared, &request.input).await?,
        O::Encapsulate | O::Decapsulate => provider.kem(&prepared, &request.input).await?,
        O::DeriveKey => provider.derive_key(&prepared, &request.input).await?,
        O::Extension { .. } => {
            return Err(ProviderError::not_dispatched(
                ProviderErrorKind::UnsupportedOperationOrProfile,
            ));
        }
        _ => provider.lifecycle(&prepared, &request.input).await?,
    };
    let (observed_target, output, provider_request_id) = reply.into_parts();
    // A bad receipt arrives *after* possible remote side effects: never
    // return NotDispatched or blindly retry a side-effecting operation.
    if observed_target != *prepared.target() || !output.matches_operation(request.intent) {
        return Err(ProviderError::unknown_commit_state());
    }
    Ok(OperationCompletion {
        evidence: OperationEvidence {
            provider: prepared.provider().clone(),
            namespace: prepared.namespace().clone(),
            logical_key: prepared.logical_key().clone(),
            target: prepared.target().clone(),
            assurance: prepared.assurance(),
            operation: request.intent.operation.clone(),
            correlation: request.correlation.clone(),
            provider_request_id,
            outcome: crate::OperationState::ConfirmedSuccess,
        },
        output,
    })
}
