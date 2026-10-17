//! Opt-in, ephemeral Ed25519 **software-only** provider.
//!
//! This module is absent unless the caller explicitly enables the
//! `software-provider` feature. It is not a KMS, secure enclave, HSM, vault,
//! FIPS module or persistent key store. All private bytes remain within
//! Rust-owned, zeroized allocations until the provider is dropped.
//!
//! KM-05 `execute_checked` remains the ONLY sign/verify/public-export gateway.
//! New-key creation has a separate, policy-gated, targetless boundary rather
//! than removing KM-05's Generate/Import and raw-material denial guards.

use crate::{
    AlgorithmProfile, CAPABILITY_SCHEMA_VERSION, CapabilityEntry, CryptoOperation, DispatchTarget,
    EdDsaVariant, ExportRequirement, Exportability, HostScope, HostValidatedCapabilities,
    KeyMaterial, KeyProvider, KeyRef, KeySelector, LogicalKeyId, OperationInput, OperationIntent,
    PayloadDescriptor, PolicyVerdict, PreparedDispatch, ProtectionClass, ProtectionRequirement,
    ProviderCapabilities, ProviderError, ProviderErrorKind, ProviderFuture, ProviderInstanceId,
    ProviderNamespace, ProviderOutput, ProviderReply, ProviderResourceId, ProviderVersionId,
    ResolvedKey, SupportStatus, VersionModel, VersionRequirement,
};
use core::fmt;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use std::collections::BTreeMap;
use std::sync::RwLock;
use zeroize::Zeroizing;

/// Hard cap on one pure-Ed25519 message accepted by software dispatch.
pub const MAX_SOFTWARE_MESSAGE_BYTES: u64 = 1_048_576;
/// Maximum concurrently retained in-memory signing keys per provider instance.
pub const MAX_SOFTWARE_KEYS: usize = 1_024;

const PROTOCOL: &str = "keymesh.software.ed25519.v1";
const REVISION: &str = "software.ed25519.v1";

fn ed25519_profile() -> AlgorithmProfile {
    AlgorithmProfile::EdDsa {
        variant: EdDsaVariant::Ed25519,
    }
}
fn denied(kind: ProviderErrorKind) -> ProviderError {
    ProviderError::not_dispatched(kind)
}
fn valid_software_host(
    instance: &ProviderInstanceId,
    namespace: &ProviderNamespace,
    scope: &HostScope,
    host: &HostValidatedCapabilities,
) -> bool {
    scope.provider() == instance
        && scope.namespace() == namespace
        && host.scope.as_ref() == Some(scope)
        && host.protection == Some(ProtectionClass::Software)
        && host.version_model == Some(VersionModel::ProviderVersion)
}
fn policy_result(
    verdict: Result<PolicyVerdict, ProviderError>,
) -> Result<(), ProviderError> {
    match verdict {
        Ok(PolicyVerdict::Permit) => Ok(()),
        Ok(PolicyVerdict::Deny) => Err(denied(ProviderErrorKind::PolicyDenied)),
        Ok(PolicyVerdict::Indeterminate) | Err(_) => {
            Err(denied(ProviderErrorKind::PolicyIndeterminate))
        }
    }
}
fn lower_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    output
}

/// Explicit, independently host-approved lifecycle action, not an alias
/// for KM-05 KeyProvider::lifecycle. A new key has no existing BoundKey.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SoftwareLifecycleAction {
    /// Create a new in-memory Ed25519 key under a unique concrete version.
    Generate,
    /// Irreversibly discard exactly one live in-memory key and its seed.
    Purge,
}

/// Safe metadata sent to the required host-defined creation/deletion policy.
/// It contains no seed, private key, signature, credential or RNG output.
pub struct SoftwareLifecycleContext<'a> {
    /// Independently host-approved provider and tenant namespace.
    pub scope: &'a HostScope,
    /// The tenant-qualified logical key.
    pub logical_key: &'a LogicalKeyId,
    /// Explicit operation (Generate or Purge).
    pub action: SoftwareLifecycleAction,
    /// Exact concrete version to purge, or None for targetless Generate.
    pub reference: Option<&'a KeyRef>,
}

/// Mandatory host-supplied lifecycle authorization for targetless creation and
/// exact-version disposal. Construction of HostScope alone is not IAM.
pub trait SoftwareLifecycleGate: Send + Sync {
    /// Permit/Deny/Indeterminate with no key mutation in the callback.
    fn authorize<'a>(
        &'a self,
        context: &'a SoftwareLifecycleContext<'_>,
    ) -> ProviderFuture<'a, PolicyVerdict>;
}

/// Targetless creation request. Requires explicit software provider, tenant,
/// a host corroborated Software custody and ProviderVersion semantics, and an
/// exact Ed25519 Generate operation. No untrusted alias is accepted.
pub struct SoftwareCreateRequest<'a> {
    /// The independent host-approved scope.
    pub scope: &'a HostScope,
    /// Host-established software protection and concrete version guarantees.
    pub host_assurance: &'a HostValidatedCapabilities,
    /// New logical key; duplicate names fail rather than rotating implicitly.
    pub logical_key: &'a LogicalKeyId,
    /// Must be Ed25519/Generate/None/ProviderVersion/Any/None.
    pub intent: &'a OperationIntent,
}

/// Exact-key deletion request; the caller MUST present the returned concrete
/// resource AND exact provider version, not Active/Latest/stable-only.
pub struct SoftwarePurgeRequest<'a> {
    /// Independently host-approved provider and namespace.
    pub scope: &'a HostScope,
    /// Independently established provider custody and version semantics.
    pub host_assurance: &'a HostValidatedCapabilities,
    /// Exact previously returned resource/provider version.
    pub reference: &'a KeyRef,
}

/// Public creation metadata; private signing seed is never returned.
pub struct CreatedSoftwareKey {
    reference: KeyRef,
    public_key: [u8; 32],
}
impl CreatedSoftwareKey {
    /// Exact scope-qualified key reference; no mutable alias or session handle.
    pub fn reference(&self) -> &KeyRef {
        &self.reference
    }
    /// RFC 8032 Ed25519 public-key bytes (not private seed bytes).
    pub fn public_key(&self) -> &[u8; 32] {
        &self.public_key
    }
}
impl fmt::Debug for CreatedSoftwareKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CreatedSoftwareKey(<redacted>)")
    }
}

struct StoredKey {
    target: DispatchTarget,
    public_key: [u8; 32],
    material: KeyMaterial,
}

/// In-memory provider with a fixed exact provider instance and one namespace.
/// Not Clone: callers may share the instance using an explicitly enrolled Arc.
/// No global software fallback or static master key exists.
///
/// The lock serializes sign/verify/export against key purge. A purge
/// cannot change the target while a sign holds its read lock; signing after
/// deletion or name reuse fails unless bound to the freshly issued target.
/// Dropping the provider drops all KeyMaterial owners, zeroizing their Vecs.
pub struct SoftwareProvider {
    instance: ProviderInstanceId,
    namespace: ProviderNamespace,
    keys: RwLock<BTreeMap<LogicalKeyId, StoredKey>>,
}
impl fmt::Debug for SoftwareProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SoftwareProvider(<redacted>)")
    }
}
impl SoftwareProvider {
    /// Construct an empty provider without any keys or implicit host authority.
    /// The host must independently authenticate scope and explicitly register
    /// this provider in KM-06. No key is generated during construction.
    pub fn new(instance: ProviderInstanceId, namespace: ProviderNamespace) -> Self {
        Self {
            instance,
            namespace,
            keys: RwLock::new(BTreeMap::new()),
        }
    }

    /// Construct a typed Generate intent suitable for this exact provider.
    /// It does NOT, by itself, authorize or execute key creation.
    pub fn create_intent() -> OperationIntent {
        OperationIntent {
            operation: CryptoOperation::Generate,
            profile: ed25519_profile(),
            payload: PayloadDescriptor::None,
            binding: VersionRequirement::ProviderVersion,
            protection: ProtectionRequirement::Any,
            export: ExportRequirement::None,
        }
    }

    /// Create exactly one key after a separate mandatory host policy Permit.
    /// RNG and key allocation occur **after** all scope/profile/policy checks.
    /// OS entropy failure is a no-dispatch error, not a success or fallback.
    /// Duplicate logical keys fail; use KM-09 for version-safe rotation.
    pub async fn create(
        &self,
        policy: &dyn SoftwareLifecycleGate,
        request: SoftwareCreateRequest<'_>,
    ) -> Result<CreatedSoftwareKey, ProviderError> {
        if !valid_software_host(
            &self.instance,
            &self.namespace,
            request.scope,
            request.host_assurance,
        ) {
            return Err(denied(ProviderErrorKind::ScopeMismatch));
        }
        if request.intent != &Self::create_intent() || request.intent.validate().is_err() {
            return Err(denied(ProviderErrorKind::UnsupportedOperationOrProfile));
        }
        {
            let keys = self
                .keys
                .read()
                .map_err(|_| denied(ProviderErrorKind::Unavailable))?;
            if keys.contains_key(request.logical_key) || keys.len() >= MAX_SOFTWARE_KEYS {
                return Err(denied(ProviderErrorKind::InvalidInput));
            }
        }
        let context = SoftwareLifecycleContext {
            scope: request.scope,
            logical_key: request.logical_key,
            action: SoftwareLifecycleAction::Generate,
            reference: None,
        };
        policy_result(policy.authorize(&context).await)?;

        // Do not hold a std lock across a future; the lock below is acquired
        // only after host policy. OS CSPRNG is the sole production entropy source.
        let mut seed = Zeroizing::new(vec![0_u8; 32]);
        getrandom::getrandom(&mut seed).map_err(|_| denied(ProviderErrorKind::Unavailable))?;
        let mut nonce = Zeroizing::new([0_u8; 16]);
        getrandom::getrandom(&mut *nonce).map_err(|_| denied(ProviderErrorKind::Unavailable))?;
        let unique = lower_hex(&*nonce);
        let resource = ProviderResourceId::parse(&format!("memory:ed25519:{unique}"))
            .map_err(|_| denied(ProviderErrorKind::InvalidInput))?;
        let version = ProviderVersionId::parse(&format!("v{unique}"))
            .map_err(|_| denied(ProviderErrorKind::InvalidInput))?;
        let public_key = {
            let seed_bytes = <&[u8; 32]>::try_from(seed.as_slice())
                .map_err(|_| denied(ProviderErrorKind::InvalidInput))?;
            SigningKey::from_bytes(seed_bytes).verifying_key().to_bytes()
        };
        // Own one KeyMaterial; the scratch seed zeroizes independently at Drop.
        let material = KeyMaterial::from_vec(std::mem::take(&mut *seed))
            .map_err(|_| denied(ProviderErrorKind::InvalidInput))?;
        let target = DispatchTarget::ProviderVersion {
            resource: resource.clone(),
            version: version.clone(),
        };
        let mut keys = self
            .keys
            .write()
            .map_err(|_| denied(ProviderErrorKind::Unavailable))?;
        if keys.contains_key(request.logical_key) || keys.len() >= MAX_SOFTWARE_KEYS {
            return Err(denied(ProviderErrorKind::InvalidInput));
        }
        keys.insert(
            request.logical_key.clone(),
            StoredKey {
                target,
                public_key,
                material,
            },
        );
        Ok(CreatedSoftwareKey {
            reference: KeyRef::new(
                self.instance.clone(),
                self.namespace.clone(),
                request.logical_key.clone(),
                KeySelector::ExactProviderVersion { resource, version },
            ),
            public_key,
        })
    }

    /// Purge exactly the currently pinned key after host lifecycle policy.
    /// No alias is accepted and no other provider/tenant is modified.
    /// The stored KeyMaterial is zeroized by Drop after removal. A concurrent
    /// sign either finishes before purge or fails because its target vanished.
    /// A purge does not prove erasure of OS memory or downstream copies.
    pub async fn purge(
        &self,
        policy: &dyn SoftwareLifecycleGate,
        request: SoftwarePurgeRequest<'_>,
    ) -> Result<(), ProviderError> {
        if !valid_software_host(
            &self.instance,
            &self.namespace,
            request.scope,
            request.host_assurance,
        ) || request.reference.provider() != &self.instance
            || request.reference.namespace() != &self.namespace
        {
            return Err(denied(ProviderErrorKind::ScopeMismatch));
        }
        let (resource, version) = match request.reference.selector() {
            KeySelector::ExactProviderVersion { resource, version } => (resource, version),
            _ => return Err(denied(ProviderErrorKind::UnsupportedVersionAssurance)),
        };
        {
            let keys = self
                .keys
                .read()
                .map_err(|_| denied(ProviderErrorKind::Unavailable))?;
            let key = keys.get(request.reference.logical_key())
                .ok_or_else(|| denied(ProviderErrorKind::UnsupportedVersionAssurance))?;
            if key.target != (DispatchTarget::ProviderVersion {
                resource: resource.clone(),
                version: version.clone(),
            }) {
                return Err(denied(ProviderErrorKind::UnsupportedVersionAssurance));
            }
        }
        let context = SoftwareLifecycleContext {
            scope: request.scope,
            logical_key: request.reference.logical_key(),
            action: SoftwareLifecycleAction::Purge,
            reference: Some(request.reference),
        };
        policy_result(policy.authorize(&context).await)?;
        let mut keys = self
            .keys
            .write()
            .map_err(|_| denied(ProviderErrorKind::Unavailable))?;
        let stored = keys
            .get(request.reference.logical_key())
            .ok_or_else(|| denied(ProviderErrorKind::UnsupportedVersionAssurance))?;
        if stored.target != (DispatchTarget::ProviderVersion {
            resource: resource.clone(),
            version: version.clone(),
        }) {
            return Err(denied(ProviderErrorKind::UnsupportedVersionAssurance));
        }
        keys.remove(request.reference.logical_key());
        Ok(())
    }

    fn matches_scope(&self, scope: &HostScope) -> bool {
        scope.provider() == &self.instance && scope.namespace() == &self.namespace
    }

    fn checked_entry<'a>(
        &'a self,
        request: &PreparedDispatch<'_>,
        keys: &'a BTreeMap<LogicalKeyId, StoredKey>,
    ) -> Result<&'a StoredKey, ProviderError> {
        if request.provider() != &self.instance || request.namespace() != &self.namespace {
            return Err(denied(ProviderErrorKind::ScopeMismatch));
        }
        if request.feature_revision() != REVISION || request.protocol_revision() != PROTOCOL {
            return Err(denied(ProviderErrorKind::UnverifiedCapability));
        }
        let entry = keys
            .get(request.logical_key())
            .ok_or_else(|| denied(ProviderErrorKind::UnsupportedVersionAssurance))?;
        if &entry.target != request.target() || !matches!(entry.target, DispatchTarget::ProviderVersion { .. }) {
            return Err(denied(ProviderErrorKind::UnsupportedVersionAssurance));
        }
        Ok(entry)
    }

    fn operation_valid(request: &PreparedDispatch<'_>, desired: CryptoOperation) -> bool {
        request.intent().operation == desired && request.intent().profile == ed25519_profile()
    }
}

impl KeyProvider for SoftwareProvider {
    fn instance(&self) -> &ProviderInstanceId {
        &self.instance
    }

    fn capabilities<'a>(&'a self, scope: &'a HostScope) -> ProviderFuture<'a, ProviderCapabilities> {
        Box::pin(async move {
            if !self.matches_scope(scope) {
                return Err(denied(ProviderErrorKind::ScopeMismatch));
            }
            let profile = ed25519_profile();
            Ok(ProviderCapabilities {
                schema_version: CAPABILITY_SCHEMA_VERSION,
                provider_instance: self.instance.as_str().to_owned(),
                namespace: self.namespace.as_str().to_owned(),
                protocol_revision: PROTOCOL.to_owned(),
                feature_revision: REVISION.to_owned(),
                reported_protection: ProtectionClass::Software,
                reported_version_model: VersionModel::ProviderVersion,
                reported_exportability: Exportability::PublicOnly,
                attestation_claims: Vec::new(),
                entries: vec![
                    CapabilityEntry {
                        operation: CryptoOperation::SignMessage,
                        profile: profile.clone(),
                        support: SupportStatus::Supported,
                        max_input_bytes: Some(MAX_SOFTWARE_MESSAGE_BYTES),
                    },
                    CapabilityEntry {
                        operation: CryptoOperation::VerifyMessage,
                        profile: profile.clone(),
                        support: SupportStatus::Supported,
                        max_input_bytes: Some(MAX_SOFTWARE_MESSAGE_BYTES),
                    },
                    CapabilityEntry {
                        operation: CryptoOperation::ExportPublic,
                        profile,
                        support: SupportStatus::Supported,
                        max_input_bytes: Some(0),
                    },
                ],
            })
        })
    }

    fn resolve<'a>(
        &'a self,
        scope: &'a HostScope,
        reference: &'a KeyRef,
    ) -> ProviderFuture<'a, ResolvedKey> {
        Box::pin(async move {
            if !self.matches_scope(scope)
                || reference.provider() != &self.instance
                || reference.namespace() != &self.namespace
            {
                return Err(denied(ProviderErrorKind::ScopeMismatch));
            }
            let (resource, version) = match reference.selector() {
                KeySelector::ExactProviderVersion { resource, version } => (resource, version),
                _ => return Err(denied(ProviderErrorKind::UnsupportedVersionAssurance)),
            };
            let keys = self
                .keys
                .read()
                .map_err(|_| denied(ProviderErrorKind::Unavailable))?;
            let key = keys
                .get(reference.logical_key())
                .ok_or_else(|| denied(ProviderErrorKind::UnsupportedVersionAssurance))?;
            if key.target != (DispatchTarget::ProviderVersion {
                resource: resource.clone(),
                version: version.clone(),
            }) {
                return Err(denied(ProviderErrorKind::UnsupportedVersionAssurance));
            }
            Ok(ResolvedKey::new(
                self.instance.clone(),
                self.namespace.clone(),
                reference.logical_key().clone(),
                key.target.clone(),
            ))
        })
    }

    fn sign<'a>(
        &'a self,
        request: &'a PreparedDispatch<'_>,
        input: &'a OperationInput<'_>,
    ) -> ProviderFuture<'a, ProviderReply> {
        Box::pin(async move {
            if !Self::operation_valid(request, CryptoOperation::SignMessage) {
                return Err(denied(ProviderErrorKind::UnsupportedOperationOrProfile));
            }
            let message = match input {
                OperationInput::Message { bytes, authenticator: None }
                    if bytes.len() as u64 <= MAX_SOFTWARE_MESSAGE_BYTES => *bytes,
                _ => return Err(denied(ProviderErrorKind::InvalidInput)),
            };
            // Synchronous lock is held only during native signing; no await
            // allows purge/rebind to interleave with this exact key operation.
            let keys = self
                .keys
                .read()
                .map_err(|_| denied(ProviderErrorKind::Unavailable))?;
            let entry = self.checked_entry(request, &keys)?;
            let mut signature = None;
            entry.material.with_exposed(|secret| {
                if let Ok(seed) = <&[u8; 32]>::try_from(secret) {
                    let signer = SigningKey::from_bytes(seed);
                    signature = Some(signer.sign(message).to_bytes().to_vec());
                }
            });
            let signature = signature
                .ok_or_else(|| denied(ProviderErrorKind::Unavailable))?;
            Ok(ProviderReply::new(
                request.target().clone(),
                ProviderOutput::Signature(signature),
                None,
            ))
        })
    }

    fn verify<'a>(
        &'a self,
        request: &'a PreparedDispatch<'_>,
        input: &'a OperationInput<'_>,
    ) -> ProviderFuture<'a, ProviderReply> {
        Box::pin(async move {
            if !Self::operation_valid(request, CryptoOperation::VerifyMessage) {
                return Err(denied(ProviderErrorKind::UnsupportedOperationOrProfile));
            }
            let (message, raw_signature) = match input {
                OperationInput::Message { bytes, authenticator: Some(sig) }
                    if bytes.len() as u64 <= MAX_SOFTWARE_MESSAGE_BYTES
                        && sig.len() == 64 => (*bytes, *sig),
                _ => return Err(denied(ProviderErrorKind::InvalidInput)),
            };
            let keys = self
                .keys
                .read()
                .map_err(|_| denied(ProviderErrorKind::Unavailable))?;
            let entry = self.checked_entry(request, &keys)?;
            let signature = Signature::try_from(raw_signature)
                .map_err(|_| denied(ProviderErrorKind::InvalidInput))?;
            let verifying_key = VerifyingKey::from_bytes(&entry.public_key)
                .map_err(|_| denied(ProviderErrorKind::InvalidInput))?;
            // Strict Ed25519 verification rejects small-order points and
            // noncanonical signatures; invalid cryptographic proof => false.
            let valid = verifying_key.verify_strict(message, &signature).is_ok();
            Ok(ProviderReply::new(
                request.target().clone(),
                ProviderOutput::Verification(valid),
                None,
            ))
        })
    }

    fn lifecycle<'a>(
        &'a self,
        request: &'a PreparedDispatch<'_>,
        input: &'a OperationInput<'_>,
    ) -> ProviderFuture<'a, ProviderReply> {
        Box::pin(async move {
            if !Self::operation_valid(request, CryptoOperation::ExportPublic)
                || !matches!(input, OperationInput::None)
                || request.intent().export != ExportRequirement::Public
            {
                return Err(denied(ProviderErrorKind::UnsupportedOperationOrProfile));
            }
            let keys = self
                .keys
                .read()
                .map_err(|_| denied(ProviderErrorKind::Unavailable))?;
            let entry = self.checked_entry(request, &keys)?;
            Ok(ProviderReply::new(
                request.target().clone(),
                ProviderOutput::PublicKey(entry.public_key.to_vec()),
                None,
            ))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex32(s: &str) -> [u8; 32] {
        assert_eq!(s.len(), 64);
        let mut out = [0_u8; 32];
        for (i, b) in out.iter_mut().enumerate() {
            *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)
                .unwrap_or_else(|_| panic!("invalid hex test fixture"));
        }
        out
    }
    fn unhex64(s: &str) -> [u8; 64] {
        assert_eq!(s.len(), 128);
        let mut out = [0_u8; 64];
        for (i, b) in out.iter_mut().enumerate() {
            *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)
                .unwrap_or_else(|_| panic!("invalid hex test fixture"));
        }
        out
    }
    #[test]
    fn rfc8032_ed25519_pure_vectors_empty_and_one_byte_message() {
        // Seeds are public RFC 8032 known-answer fixtures ONLY, never used
        // by production SoftwareProvider::create.
        let cases = [
            (
                "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
                "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
                &b""[..],
                "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
            ),
            (
                "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
                "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
                &b"\x72"[..],
                "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
            ),
        ];
        for (seed, public, message, expected) in cases {
            let seed = Zeroizing::new(unhex32(seed));
            let signer = SigningKey::from_bytes(&seed);
            assert_eq!(signer.verifying_key().to_bytes(), unhex32(public));
            let sig = signer.sign(message);
            assert_eq!(sig.to_bytes(), unhex64(expected));
            assert!(signer.verifying_key().verify_strict(message, &sig).is_ok());
            let mut changed = message.to_vec();
            changed.push(0xff);
            assert!(signer.verifying_key().verify_strict(&changed, &sig).is_err());
        }
    }
}
