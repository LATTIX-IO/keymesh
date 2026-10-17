//! Typed provider capability declarations and conservative admission decisions.
//!
//! All provider claims are untrusted metadata until corroborated by the
//! independently authenticated host. No admission executes cryptography.

use crate::algorithm::{
    AlgorithmProfile, CryptoOperation, ExportRequirement, OperationIntent, ProfileError,
    ProtectionRequirement, VersionRequirement,
};
use crate::binding::HostScope;
use crate::identity::{ProviderInstanceId, ProviderNamespace};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Version of the stable JSON capability document.
pub const CAPABILITY_SCHEMA_VERSION: u16 = 1;
/// Upper bound on entries to avoid untrusted provider metadata exhaustion.
pub const MAX_CAPABILITY_ENTRIES: usize = 256;

/// Provider-reported support is three-valued, not an implicit boolean.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SupportStatus {
    /// Provider explicitly claims this exact profile and operation are supported.
    Supported,
    /// Provider explicitly claims the exact profile and operation are unsupported.
    Unsupported,
    /// Provider does not know or cannot report reliable support.
    Unknown,
}
impl SupportStatus {
    /// Conservative conjunction used for reproducible capability intersection.
    pub const fn intersection(self, other: Self) -> Self {
        match (self, other) {
            (Self::Unsupported, _) | (_, Self::Unsupported) => Self::Unsupported,
            (Self::Supported, Self::Supported) => Self::Supported,
            _ => Self::Unknown,
        }
    }
}

/// Key custody reported by provider, **not** proof of HSM certification.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtectionClass {
    /// No trustworthy custody information.
    Unknown,
    /// Software-held private material.
    Software,
    /// Trusted execution environment; not automatically an HSM.
    Tee,
    /// HSM custody reported by provider.
    Hsm,
}

/// Claimed version selectability, not a proof of physical material version.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VersionModel {
    /// No selectable guarantee was reported.
    Unknown,
    /// A stable resource ID is selectable, potentially with rotating material.
    StableResource,
    /// The provider exposes a concrete selectable provider version.
    ProviderVersion,
    /// The provider supports selecting an exact cryptographic material revision.
    MaterialRevision,
}
impl VersionModel {
    /// Whether the reported guarantee covers the requested binding strength.
    pub const fn supports(self, requirement: VersionRequirement) -> bool {
        match requirement {
            VersionRequirement::StableResource => !matches!(self, Self::Unknown),
            VersionRequirement::ProviderVersion => {
                matches!(self, Self::ProviderVersion | Self::MaterialRevision)
            }
            VersionRequirement::MaterialRevision => matches!(self, Self::MaterialRevision),
        }
    }
}

/// Provider-reported export ability; this does not grant permission to export.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Exportability {
    /// No reliable export capability was reported.
    Unknown,
    /// No material is exportable.
    None,
    /// Public keys only; private material never exportable.
    PublicOnly,
    /// Provider says private material may be exported; require separate host approval.
    Private,
}
impl Exportability {
    /// Whether the reported capability covers an exact export request.
    pub const fn supports(self, requirement: ExportRequirement) -> bool {
        match requirement {
            ExportRequirement::None => true,
            ExportRequirement::Public => matches!(self, Self::PublicOnly | Self::Private),
            ExportRequirement::Private => matches!(self, Self::Private),
        }
    }
}

/// Opaque attestation metadata. This is NOT verified evidence or a certificate.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttestationClaim {
    /// Short claim type or format ID.
    pub kind: String,
    /// Source system identifier, not a credential or authority proof.
    pub source: String,
    /// Safe opaque claim reference, not the attestation body or secret.
    pub reference: String,
}

/// One exact algorithm/operation capability, never a whole family wildcard.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityEntry {
    /// Exact operation including sign input/digest classification.
    pub operation: CryptoOperation,
    /// Exact algorithm and parameterization.
    pub profile: AlgorithmProfile,
    /// Supported, unsupported, or unknown.
    pub support: SupportStatus,
    /// Explicit upper limit on input size; None means no reported bound.
    pub max_input_bytes: Option<u64>,
}

/// Schema-versioned, provider-reported capability catalog. It is never proof
/// of identity, authorisation, HSM attestation, or use of a particular key.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderCapabilities {
    /// Must match CAPABILITY_SCHEMA_VERSION.
    pub schema_version: u16,
    /// Provider instance associated with this specific report (not self-authenticating).
    pub provider_instance: String,
    /// Tenant/account/partition namespace associated with this specific report.
    pub namespace: String,
    /// Provider protocol name/version, bounded printable metadata only.
    pub protocol_revision: String,
    /// Provider feature revision or generation; distinct from key version.
    pub feature_revision: String,
    /// Provider's reported key protection.
    pub reported_protection: ProtectionClass,
    /// Provider's reported version selection model.
    pub reported_version_model: VersionModel,
    /// Provider's reported exportability.
    pub reported_exportability: Exportability,
    /// Optional, unverified opaque attestations.
    pub attestation_claims: Vec<AttestationClaim>,
    /// Exact individual capability entries.
    pub entries: Vec<CapabilityEntry>,
}

/// Host-asserted, independently established capabilities. Creating this
/// struct does not authenticate a caller or verify an attestation: only a
/// trusted host boundary may populate it after its own verification.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct HostValidatedCapabilities {
    /// Host-approved provider and namespace; must not come from the reported catalog.
    pub scope: Option<HostScope>,
    /// Custody evidence independently verified by the host.
    pub protection: Option<ProtectionClass>,
    /// Version semantics independently corroborated by provider-specific tests.
    pub version_model: Option<VersionModel>,
    /// Explicit allowlist decision for the vendor extension family.
    pub permit_extensions: bool,
    /// Separate deliberate approval for private material export.
    pub permit_private_export: bool,
}

/// A deterministic, no-dispatch admission decision. It does not attest
/// key custody, confirm provider-side authorization or pin a dispatch target.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Admission {
    /// Exact matched capability.
    pub capability: CapabilityEntry,
    /// Agreed maximum payload size.
    pub max_input_bytes: Option<u64>,
}

/// Fail-closed capability negotiation errors; never print payloads or tokens.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CapabilityError {
    /// Unsupported capability schema version or unsafe metadata.
    InvalidCatalog,
    /// Conflicting or duplicate exact entries must not be selected.
    DuplicateCapability,
    /// Requested operation/profile/payload is structurally invalid.
    InvalidIntent(ProfileError),
    /// No exact operation plus profile was declared.
    MissingCapability,
    /// Provider explicitly does not support this exact operation/profile.
    UnsupportedCapability,
    /// Provider support could not be determined.
    UnknownCapability,
    /// A nonempty input has no reported safe provider-side size limit.
    PayloadLimitUnknown,
    /// Provider's bound is smaller than the requested payload.
    PayloadTooLarge,
    /// Protection claim alone cannot satisfy an HSM or TEE requirement.
    UnverifiedProtection,
    /// Version selectability not confirmed by both provider and host.
    UnverifiedVersion,
    /// A public or private export is unsupported or not approved.
    ExportNotPermitted,
    /// Nonstandard extension requires explicit host opt-in.
    ExtensionNotPermitted,
    /// Capability report or host assurance belongs to a different provider/tenant.
    ScopeMismatch,
}
impl std::fmt::Display for CapabilityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::InvalidCatalog => "invalid provider capability catalog",
            Self::DuplicateCapability => "duplicate exact provider capability",
            Self::InvalidIntent(_) => "invalid algorithm operation request",
            Self::MissingCapability => "exact capability not declared",
            Self::UnsupportedCapability => "provider reports operation unsupported",
            Self::UnknownCapability => "provider operation support unknown",
            Self::PayloadLimitUnknown => "provider payload upper bound unknown",
            Self::PayloadTooLarge => "provider payload limit exceeded",
            Self::UnverifiedProtection => "required provider custody is unverified",
            Self::UnverifiedVersion => "required version selectability is unverified",
            Self::ExportNotPermitted => "key export capability or approval missing",
            Self::ExtensionNotPermitted => "extension not authorized",
            Self::ScopeMismatch => "provider capability scope mismatch",
        };
        f.write_str(s)
    }
}
impl std::error::Error for CapabilityError {}

fn revision_safe(s: &str) -> bool {
    let lower = s.to_ascii_lowercase();
    !s.is_empty()
        && s.len() <= 96
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b':'))
        && ![
            "token",
            "secret",
            "password",
            "credential",
            "bearer",
            "authorization",
            "api_key",
            "apikey",
            "access_key",
        ]
        .iter()
        .any(|needle| lower.contains(needle))
}
fn claim_safe(claim: &AttestationClaim) -> bool {
    revision_safe(&claim.kind) && revision_safe(&claim.source) && revision_safe(&claim.reference)
}

/// Capability schema checks; provider claims remain untrusted after this.
impl ProviderCapabilities {
    /// Reject malformed, oversized, or ambiguous provider metadata.
    pub fn validate(&self) -> Result<(), CapabilityError> {
        if self.schema_version != CAPABILITY_SCHEMA_VERSION
            || ProviderInstanceId::parse(&self.provider_instance).is_err()
            || ProviderNamespace::parse(&self.namespace).is_err()
            || !revision_safe(&self.protocol_revision)
            || !revision_safe(&self.feature_revision)
            || self.entries.len() > MAX_CAPABILITY_ENTRIES
            || self.attestation_claims.len() > 8
            || self
                .attestation_claims
                .iter()
                .any(|claim| !claim_safe(claim))
        {
            return Err(CapabilityError::InvalidCatalog);
        }
        let mut seen = BTreeSet::new();
        for entry in &self.entries {
            entry
                .profile
                .validate()
                .map_err(CapabilityError::InvalidIntent)?;
            if !seen.insert((entry.operation.clone(), entry.profile.clone())) {
                return Err(CapabilityError::DuplicateCapability);
            }
            if entry.support != SupportStatus::Supported && entry.max_input_bytes.is_some() {
                // Unknown/unsupported entries must not silently advertise
                // an apparently actionable input budget.
                return Err(CapabilityError::InvalidCatalog);
            }
        }
        Ok(())
    }

    /// Authorize a precise operation profile *without* selecting a key or
    /// performing dispatch. Unknown support, version and protection fail
    /// closed. A future adapter MUST still run preflight_bind and enforce
    /// the returned concrete BoundKey target before doing crypto.
    pub fn admit(
        &self,
        intent: &OperationIntent,
        host: &HostValidatedCapabilities,
    ) -> Result<Admission, CapabilityError> {
        self.validate()?;
        // A valid catalog is only data. Host corroboration MUST be bound to
        // the very same instance and namespace, not reusable across providers.
        let scope = host.scope.as_ref().ok_or(CapabilityError::ScopeMismatch)?;
        if scope.provider().as_str() != self.provider_instance
            || scope.namespace().as_str() != self.namespace
        {
            return Err(CapabilityError::ScopeMismatch);
        }
        intent.validate().map_err(CapabilityError::InvalidIntent)?;
        if (matches!(intent.profile, AlgorithmProfile::Extension(_))
            || matches!(intent.operation, CryptoOperation::Extension { .. }))
            && !host.permit_extensions
        {
            return Err(CapabilityError::ExtensionNotPermitted);
        }
        if !self.reported_version_model.supports(intent.binding)
            || !host
                .version_model
                .unwrap_or(VersionModel::Unknown)
                .supports(intent.binding)
        {
            return Err(CapabilityError::UnverifiedVersion);
        }
        match intent.protection {
            ProtectionRequirement::Any => {}
            ProtectionRequirement::Hsm => {
                if self.reported_protection != ProtectionClass::Hsm
                    || host.protection != Some(ProtectionClass::Hsm)
                {
                    return Err(CapabilityError::UnverifiedProtection);
                }
            }
            ProtectionRequirement::Tee => {
                if self.reported_protection != ProtectionClass::Tee
                    || host.protection != Some(ProtectionClass::Tee)
                {
                    return Err(CapabilityError::UnverifiedProtection);
                }
            }
        }
        if !self.reported_exportability.supports(intent.export)
            || (intent.export == ExportRequirement::Private && !host.permit_private_export)
        {
            return Err(CapabilityError::ExportNotPermitted);
        }
        let entry = self
            .entries
            .iter()
            .find(|cap| cap.operation == intent.operation && cap.profile == intent.profile)
            .ok_or(CapabilityError::MissingCapability)?;
        match entry.support {
            SupportStatus::Unsupported => return Err(CapabilityError::UnsupportedCapability),
            SupportStatus::Unknown => return Err(CapabilityError::UnknownCapability),
            SupportStatus::Supported => {}
        }
        let bytes = match intent.payload {
            crate::algorithm::PayloadDescriptor::None => 0,
            crate::algorithm::PayloadDescriptor::Message { bytes }
            | crate::algorithm::PayloadDescriptor::Ciphertext { bytes }
            | crate::algorithm::PayloadDescriptor::KeyMaterial { bytes } => bytes,
            crate::algorithm::PayloadDescriptor::Digest { bytes, .. }
            | crate::algorithm::PayloadDescriptor::ExternalMu { bytes } => u64::from(bytes),
            crate::algorithm::PayloadDescriptor::Derivation {
                info_bytes,
                output_bytes,
            } => info_bytes.saturating_add(output_bytes),
        };
        if bytes > 0 {
            match entry.max_input_bytes {
                Some(limit) if bytes <= limit => {}
                Some(_) => return Err(CapabilityError::PayloadTooLarge),
                None => return Err(CapabilityError::PayloadLimitUnknown),
            }
        }
        Ok(Admission {
            capability: entry.clone(),
            max_input_bytes: entry.max_input_bytes,
        })
    }

    /// Deterministically intersect exact operation/profile support with
    /// no fallback, no attestation inheritance, and no implied HSM status.
    ///
    /// Entries absent on either side are not common capabilities. The stable
    /// order comes from a BTreeMap keyed by operation + full algorithm profile.
    pub fn intersection(&self, other: &Self) -> Result<Self, CapabilityError> {
        self.validate()?;
        other.validate()?;
        // Intersection is a report for a *single* independently identified
        // provider/tenant scope, not a vehicle for laundering HSM metadata.
        if self.provider_instance != other.provider_instance || self.namespace != other.namespace {
            return Err(CapabilityError::ScopeMismatch);
        }
        let right: BTreeMap<_, _> = other
            .entries
            .iter()
            .map(|e| ((e.operation.clone(), e.profile.clone()), e))
            .collect();
        let mut common = BTreeMap::new();
        for left in &self.entries {
            let key = (left.operation.clone(), left.profile.clone());
            if let Some(rhs) = right.get(&key) {
                let max_input_bytes = match (left.max_input_bytes, rhs.max_input_bytes) {
                    (Some(a), Some(b))
                        if left.support == SupportStatus::Supported
                            && rhs.support == SupportStatus::Supported =>
                    {
                        Some(a.min(b))
                    }
                    _ => None,
                };
                common.insert(
                    key,
                    CapabilityEntry {
                        operation: left.operation.clone(),
                        profile: left.profile.clone(),
                        support: left.support.intersection(rhs.support),
                        max_input_bytes,
                    },
                );
            }
        }
        let version = if self.reported_version_model <= other.reported_version_model {
            self.reported_version_model
        } else {
            other.reported_version_model
        };
        let result = Self {
            schema_version: CAPABILITY_SCHEMA_VERSION,
            provider_instance: self.provider_instance.clone(),
            namespace: self.namespace.clone(),
            protocol_revision: "intersection".into(),
            feature_revision: "intersection".into(),
            reported_protection: if self.reported_protection == other.reported_protection {
                self.reported_protection
            } else {
                ProtectionClass::Unknown
            },
            reported_version_model: version,
            reported_exportability: if self.reported_exportability == other.reported_exportability {
                self.reported_exportability
            } else {
                Exportability::Unknown
            },
            attestation_claims: Vec::new(),
            entries: common.into_values().collect(),
        };
        result.validate()?;
        Ok(result)
    }
}
