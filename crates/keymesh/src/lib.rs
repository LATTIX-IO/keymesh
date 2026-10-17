//! Provider-neutral key identity and pre-dispatch binding contracts.
//!
//! This initial API does **not** perform cryptographic operations or
//! authenticate callers. It validates identifiers and proposed bindings. See
//! `THREAT_MODEL.md` and ADR-0001/0002 in the repository for the trust model.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod algorithm;
mod binding;
mod capability;
mod identity;
mod uri;

pub use binding::{
    BindingAssurance, BindingError, BoundKey, DispatchTarget, HostScope, KeyRef, KeySelector,
    RequiredAssurance, ResolvedKey, preflight_bind,
};
pub use identity::{
    IdentityError, KeyVersionId, LogicalKeyId, MAX_IDENTIFIER_BYTES, MAX_RESOURCE_BYTES,
    MaterialRevisionId, ProviderInstanceId, ProviderNamespace, ProviderResourceId,
    ProviderVersionId,
};

pub use uri::{KeyRefUriError, MAX_KEY_REF_URI_BYTES};

pub use algorithm::{
    AesWrapVariant, AlgorithmProfile, CryptoOperation, DigestAlgorithm, EcCurve, EcdsaEncoding,
    EdDsaVariant, ExportRequirement, ExtensionProfile, MlDsaInput, MlDsaVariant, MlKemVariant,
    OperationIntent, PayloadDescriptor, ProfileError, ProtectionRequirement, SlhDsaVariant,
    VersionRequirement,
};
pub use capability::{
    Admission, AttestationClaim, CapabilityEntry, CapabilityError, Exportability,
    HostValidatedCapabilities, ProtectionClass, ProviderCapabilities, SupportStatus,
    VersionModel, CAPABILITY_SCHEMA_VERSION, MAX_CAPABILITY_ENTRIES,
};
