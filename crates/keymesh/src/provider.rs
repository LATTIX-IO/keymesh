//! Runtime-neutral provider trait, classified outcomes, and safe operation evidence.
//! This crate performs no cryptographic operations and uses no async runtime.

use crate::{
    BindingAssurance, BoundKey, CryptoOperation, DispatchTarget, HostScope, KeyRef, LogicalKeyId,
    OperationIntent, ProviderCapabilities, ProviderInstanceId, ProviderNamespace, ResolvedKey,
};
use core::fmt;
use core::future::Future;
use core::pin::Pin;

/// Object-safe async method return type using only stable Rust futures.
pub type ProviderFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, ProviderError>> + Send + 'a>>;

/// Remote operation state. Dropping a future does not prove remote cancellation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperationState {
    /// No operation was dispatched.
    NotDispatched,
    /// Provider confirmed successful completion (not an HSM attestation).
    ConfirmedSuccess,
    /// Provider confirmed an unsuccessful operation with no commit.
    ConfirmedFailure,
    /// Submission may have committed even though no acknowledgement arrived.
    UnknownCommitState,
}

/// Conservative retry guidance, never an automatic retry instruction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetryDisposition {
    /// A corrected, separately authorized request may be issued.
    SafeAfterCorrection,
    /// Do not automatically repeat an operation.
    DoNotAutoRetry,
    /// First reconcile remote state before taking another action.
    ReconcileBeforeRetry,
}

/// Static, non-sensitive error classifications.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderErrorKind {
    /// Payload bytes or form do not match typed operation metadata.
    InvalidInput,
    /// Exact operation/profile not supported.
    UnsupportedOperationOrProfile,
    /// Provider authentication credentials unavailable or rejected.
    Unauthenticated,
    /// Provider declined authorization.
    AuthorizationDenied,
    /// Mandatory host policy denied.
    PolicyDenied,
    /// Mandatory host policy missing, unknown, errored or timed out.
    PolicyIndeterminate,
    /// Provider instance, tenant or key target was substituted.
    ScopeMismatch,
    /// Required exact provider/material binding cannot be guaranteed.
    UnsupportedVersionAssurance,
    /// Capability or assurance evidence is insufficient.
    UnverifiedCapability,
    /// Provider unavailable; do not infer remote commit state.
    Unavailable,
    /// Provider result/target evidence was invalid or substituted.
    InvalidOperationEvidence,
    /// Provider confirmed an operation failure.
    ProviderRejected,
    /// A remote commit may have occurred.
    UnknownCommitState,
}

/// Redacted structured error: never retains SDK errors, provider messages,
/// credentials, raw URLs, plaintext, key bytes, or arbitrary metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderError {
    kind: ProviderErrorKind,
    state: OperationState,
}
impl ProviderError {
    /// Adapter is certain an operation was not dispatched.
    pub const fn not_dispatched(kind: ProviderErrorKind) -> Self {
        if matches!(kind, ProviderErrorKind::UnknownCommitState) {
            return Self::unknown_commit_state();
        }
        Self {
            kind,
            state: OperationState::NotDispatched,
        }
    }
    /// Provider positively confirmed a failure without remote commit.
    pub const fn confirmed_failure(kind: ProviderErrorKind) -> Self {
        if matches!(kind, ProviderErrorKind::UnknownCommitState) {
            return Self::unknown_commit_state();
        }
        Self {
            kind,
            state: OperationState::ConfirmedFailure,
        }
    }
    /// Remote commit state is unknown; never blindly retry a mutation.
    pub const fn unknown_commit_state() -> Self {
        Self {
            kind: ProviderErrorKind::UnknownCommitState,
            state: OperationState::UnknownCommitState,
        }
    }
    /// Sanitized error kind.
    pub const fn kind(self) -> ProviderErrorKind {
        self.kind
    }
    /// Operation state as classified by the adapter.
    pub const fn state(self) -> OperationState {
        self.state
    }
    /// Conservative retry advice.
    pub const fn retry(self) -> RetryDisposition {
        match self.state {
            OperationState::NotDispatched => RetryDisposition::SafeAfterCorrection,
            OperationState::ConfirmedSuccess => RetryDisposition::DoNotAutoRetry,
            OperationState::ConfirmedFailure => RetryDisposition::DoNotAutoRetry,
            OperationState::UnknownCommitState => RetryDisposition::ReconcileBeforeRetry,
        }
    }
}
impl fmt::Display for ProviderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self.kind {
            ProviderErrorKind::InvalidInput => "invalid provider operation input",
            ProviderErrorKind::UnsupportedOperationOrProfile => "provider operation unsupported",
            ProviderErrorKind::Unauthenticated => "provider authentication unavailable",
            ProviderErrorKind::AuthorizationDenied => "provider authorization denied",
            ProviderErrorKind::PolicyDenied => "mandatory policy denied",
            ProviderErrorKind::PolicyIndeterminate => "mandatory policy indeterminate",
            ProviderErrorKind::ScopeMismatch => "provider scope or key mismatch",
            ProviderErrorKind::UnsupportedVersionAssurance => {
                "required version assurance unavailable"
            }
            ProviderErrorKind::UnverifiedCapability => "provider capability unverified",
            ProviderErrorKind::Unavailable => "provider unavailable",
            ProviderErrorKind::InvalidOperationEvidence => "invalid provider operation evidence",
            ProviderErrorKind::ProviderRejected => "provider operation rejected",
            ProviderErrorKind::UnknownCommitState => "remote commit state unknown",
        })
    }
}
impl std::error::Error for ProviderError {}

/// A strictly bounded safe audit label, NOT authentication or authorization.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd)]
pub struct CorrelationId(String);
impl CorrelationId {
    /// Only 1–64 ASCII alphanumeric, hyphen, underscore or period bytes.
    pub fn parse(value: &str) -> Result<Self, ProviderError> {
        if value.is_empty()
            || value.len() > 64
            || !value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        {
            return Err(ProviderError::not_dispatched(
                ProviderErrorKind::InvalidInput,
            ));
        }
        Ok(Self(value.to_string()))
    }
    /// Non-secret audit identifier supplied by the trusted host.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
impl fmt::Debug for CorrelationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CorrelationId(<redacted>)")
    }
}

/// Opaque provider-managed sensitive result reference, NOT raw key material.
/// Keymesh cannot retrieve its bytes until KM-07 defines sensitive wrappers.
#[derive(Clone, Eq, PartialEq)]
pub struct ProtectedResultRef(CorrelationId);
impl ProtectedResultRef {
    /// Store an adapter-validated non-secret result reference.
    pub fn new(reference: CorrelationId) -> Self {
        Self(reference)
    }
}
impl fmt::Debug for ProtectedResultRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ProtectedResultRef(<redacted>)")
    }
}

/// Typed operation result. Public artifacts are not key material; secret
/// outputs MUST use the opaque Protected form, never raw Vec bytes.
pub enum ProviderOutput {
    /// Public signature.
    Signature(Vec<u8>),
    /// Verification truth value.
    Verification(bool),
    /// Public ciphertext.
    Ciphertext(Vec<u8>),
    /// Ciphertext containing a wrapped key.
    WrappedKey(Vec<u8>),
    /// Authentication tag; not an HMAC key.
    Mac(Vec<u8>),
    /// Public KEM ciphertext and opaque shared secret reference.
    Encapsulation {
        /// Encapsulation ciphertext.
        ciphertext: Vec<u8>,
        /// Secret held inside a provider-managed boundary.
        shared_secret: ProtectedResultRef,
    },
    /// No direct secret material exposed by decrypt/unwrap/decap/derive/export.
    Protected(ProtectedResultRef),
    /// Public key material.
    PublicKey(Vec<u8>),
    /// Lifecycle action committed without returned key bytes.
    Acknowledged,
}
impl fmt::Debug for ProviderOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Signature(_) => "ProviderOutput::Signature(<redacted>)",
            Self::Verification(_) => "ProviderOutput::Verification(<redacted>)",
            Self::Ciphertext(_) => "ProviderOutput::Ciphertext(<redacted>)",
            Self::WrappedKey(_) => "ProviderOutput::WrappedKey(<redacted>)",
            Self::Mac(_) => "ProviderOutput::Mac(<redacted>)",
            Self::Encapsulation { .. } => "ProviderOutput::Encapsulation(<redacted>)",
            Self::Protected(_) => "ProviderOutput::Protected(<redacted>)",
            Self::PublicKey(_) => "ProviderOutput::PublicKey(<redacted>)",
            Self::Acknowledged => "ProviderOutput::Acknowledged",
        })
    }
}
impl ProviderOutput {
    pub(crate) fn matches_operation(&self, operation: &CryptoOperation) -> bool {
        use CryptoOperation as O;
        match (operation, self) {
            (O::SignMessage | O::SignDigest { .. } | O::SignExternalMu, Self::Signature(v))
            | (O::Encrypt, Self::Ciphertext(v))
            | (O::WrapKey, Self::WrappedKey(v))
            | (O::MacMessage, Self::Mac(v))
            | (O::ExportPublic, Self::PublicKey(v)) => !v.is_empty(),
            (
                O::VerifyMessage
                | O::VerifyDigest { .. }
                | O::VerifyExternalMu
                | O::VerifyMacMessage,
                Self::Verification(_),
            ) => true,
            (O::Encapsulate, Self::Encapsulation { ciphertext, .. }) => !ciphertext.is_empty(),
            (
                O::Decrypt | O::UnwrapKey | O::Decapsulate | O::DeriveKey | O::ExportPrivate,
                Self::Protected(_),
            ) => true,
            (
                O::Generate
                | O::Import
                | O::Rotate
                | O::Enable
                | O::Disable
                | O::ScheduleDelete
                | O::Recover
                | O::Purge,
                Self::Acknowledged,
            ) => true,
            _ => false,
        }
    }
}

/// Provider-reported operation reply; its claimed target must match the
/// preflight binding exactly, but this is NOT hardware attestation.
pub struct ProviderReply {
    observed_target: DispatchTarget,
    output: ProviderOutput,
    provider_request_id: Option<CorrelationId>,
}
impl ProviderReply {
    /// Adapter declares its actual target and sanitized receipt ID.
    pub fn new(
        observed_target: DispatchTarget,
        output: ProviderOutput,
        provider_request_id: Option<CorrelationId>,
    ) -> Self {
        Self {
            observed_target,
            output,
            provider_request_id,
        }
    }
    pub(crate) fn into_parts(self) -> (DispatchTarget, ProviderOutput, Option<CorrelationId>) {
        (self.observed_target, self.output, self.provider_request_id)
    }
}
impl fmt::Debug for ProviderReply {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ProviderReply(<redacted>)")
    }
}

/// Only the checked dispatcher constructs this immutable, scope-bound token.
/// A provider adapter MUST use exactly its concrete target without alias
/// substitution or reselecting versions after policy/admission.
pub struct PreparedDispatch<'a> {
    pub(crate) bound: BoundKey<'a>,
    pub(crate) intent: &'a OperationIntent,
    pub(crate) correlation: &'a CorrelationId,
    pub(crate) feature_revision: &'a str,
}
impl PreparedDispatch<'_> {
    /// Concrete pinned provider target.
    pub fn target(&self) -> &DispatchTarget {
        self.bound.dispatch_target()
    }
    /// Configured provider instance.
    pub fn provider(&self) -> &ProviderInstanceId {
        self.bound.provider()
    }
    /// Host-approved namespace.
    pub fn namespace(&self) -> &ProviderNamespace {
        self.bound.namespace()
    }
    /// Logical key being operated on.
    pub fn logical_key(&self) -> &LogicalKeyId {
        self.bound.logical_key()
    }
    /// Preflight claimed assurance level, not independent attestation.
    pub fn assurance(&self) -> BindingAssurance {
        self.bound.assurance()
    }
    /// Exact immutable typed operation intent.
    pub fn intent(&self) -> &OperationIntent {
        self.intent
    }
    /// Bounded safe host correlation label.
    pub fn correlation(&self) -> &CorrelationId {
        self.correlation
    }
    /// Versioned provider feature snapshot; adapters re-check at dispatch.
    pub fn feature_revision(&self) -> &str {
        self.feature_revision
    }
}

macro_rules! optional_method {
    ($(#[$doc:meta] $name:ident;)+) => {
        $(
            #[$doc]
            fn $name<'a>(
                &'a self,
                _request: &'a PreparedDispatch<'_>,
                _payload: &'a crate::OperationInput<'_>,
            ) -> ProviderFuture<'a, ProviderReply> {
                Box::pin(async {
                    Err(ProviderError::not_dispatched(
                        ProviderErrorKind::UnsupportedOperationOrProfile,
                    ))
                })
            }
        )+
    };
}

/// Runtime-neutral, object-safe adapter contract. Query and resolution methods
/// are read-only and must not perform crypto or lifecycle mutations.
/// Optional methods default to no-dispatch Unsupported. Native blocking APIs
/// MUST run on an adapter-selected dedicated blocking executor (KM-06+).
///
/// All methods accept a PreparedDispatch that callers cannot construct.
pub trait KeyProvider: Send + Sync {
    /// Provider instance immutable identity configured by the host.
    fn instance(&self) -> &ProviderInstanceId;
    /// Read provider-scoped capability metadata with no mutating side effects.
    fn capabilities<'a>(&'a self, scope: &'a HostScope)
    -> ProviderFuture<'a, ProviderCapabilities>;
    /// Resolve a logical reference to an exact native target, read-only.
    fn resolve<'a>(
        &'a self,
        scope: &'a HostScope,
        reference: &'a KeyRef,
    ) -> ProviderFuture<'a, ResolvedKey>;

    optional_method! {
        /// SignMessage, SignDigest, and specialized SignExternalMu only.
        sign;
        /// Exact VerifyMessage, VerifyDigest, and VerifyExternalMu only.
        verify;
        /// Encrypt, never implicitly WrapKey.
        encrypt;
        /// Decrypt into an opaque protected result.
        decrypt;
        /// WrapKey distinct from Encrypt.
        wrap_key;
        /// UnwrapKey distinct from Decrypt.
        unwrap_key;
        /// HMAC generation and verification, never a public-key signature.
        mac;
        /// Exact ML-KEM encapsulation or decapsulation.
        kem;
        /// Derive into an opaque protected result reference.
        derive_key;
        /// Individual typed lifecycle actions and public/private export.
        lifecycle;
    }
}
