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
mod credential;
mod execution;
mod identity;
mod provider;
mod registry;
mod secret;
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
    Admission, AttestationClaim, CAPABILITY_SCHEMA_VERSION, CapabilityEntry, CapabilityError,
    Exportability, HostValidatedCapabilities, MAX_CAPABILITY_ENTRIES, ProtectionClass,
    ProviderCapabilities, SupportStatus, VersionModel,
};

pub use execution::{
    MAX_VERIFICATION_PROOF_BYTES, OperationCompletion, OperationEvidence, OperationInput,
    OperationRequest, PolicyContext, PolicyGate, PolicyVerdict, execute_checked,
};
pub use provider::{
    CorrelationId, KeyProvider, OperationState, PreparedDispatch, ProtectedResultRef,
    ProviderError, ProviderErrorKind, ProviderFuture, ProviderOutput, ProviderReply,
    RetryDisposition,
};

pub use registry::{
    MAX_REGISTERED_PROVIDERS, ProviderHealth, ProviderRegistry, ProviderRequirements,
    ProviderSelection, RegistrationError, RejectionReason, RouteError, RouteTrace, RoutedProvider,
    RoutingFailure,
};

pub use credential::{
    CredentialAuthorization, CredentialError, CredentialFuture, CredentialPurpose,
    CredentialRequest, CredentialSource, ScopedCredential, acquire_scoped_credential,
};
pub use secret::{KeyMaterial, MAX_SECRET_BYTES, SecretBytes, SecretError};
