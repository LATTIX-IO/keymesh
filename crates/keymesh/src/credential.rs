//! Explicit, runtime-neutral host credential boundary.
//!
//! Credential retrieval is a separate HOST callback, never network discovery,
//! KMS secret storage, policy evaluation, key import, or crypto dispatch. The
//! checked gate refuses provider/tenant/operation mismatches before callbacks
//! and a policy denial before consulting the credential source.

use crate::{
    CryptoOperation, HostScope, OperationIntent, PolicyVerdict, ProviderInstanceId,
    ProviderNamespace, SecretBytes,
};
use core::fmt;
use core::future::Future;
use core::pin::Pin;

/// Runtime-agnostic asynchronous credential callback result.
pub type CredentialFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, CredentialError>> + Send + 'a>>;

/// Credential use must be explicit, not inferred from provider metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialPurpose {
    /// Authentication to the exact configured provider/tenant partition.
    ProviderAuthentication,
    /// Operation-specific host or provider authorization.
    OperationAuthorization,
}

/// Fixed error categories only; never hold SDK causes, tokens or paths.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialError {
    /// Host scope, configured provider, namespace, purpose or intent mismatch.
    ScopeMismatch,
    /// Requested operation/profile is structurally invalid.
    InvalidIntent,
    /// Mandatory independent authorization explicitly denied.
    PolicyDenied,
    /// Mandatory authorization errored, was missing, or returned unknown.
    PolicyIndeterminate,
    /// Credential source could not supply material; no fallback occurs.
    Unavailable,
    /// Callback returned an unusable or explicitly erased credential.
    InvalidMaterial,
}
impl fmt::Display for CredentialError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::ScopeMismatch => "credential scope mismatch",
            Self::InvalidIntent => "credential operation intent invalid",
            Self::PolicyDenied => "credential access denied",
            Self::PolicyIndeterminate => "credential authorization indeterminate",
            Self::Unavailable => "credential provider unavailable",
            Self::InvalidMaterial => "credential material unusable",
        })
    }
}
impl std::error::Error for CredentialError {}

/// A request with separately host-established scope and intended operation.
///
/// This struct is not an authentication token. The caller MUST authenticate
/// and authorize its request context before creating it. The checked gate
/// enforces exact consistency among the fields but cannot attest host claims.
pub struct CredentialRequest<'a> {
    /// Host-authenticated tenant/provider scope.
    pub host_scope: &'a HostScope,
    /// Independently configured target provider identity.
    pub expected_provider: &'a ProviderInstanceId,
    /// Independently configured target namespace.
    pub expected_namespace: &'a ProviderNamespace,
    /// Explicit operation being authorized.
    pub operation: &'a CryptoOperation,
    /// Exact typed operation/profile used for authorization.
    pub intent: &'a OperationIntent,
    /// Context for which this credential may be used.
    pub purpose: CredentialPurpose,
}
impl CredentialRequest<'_> {
    fn structurally_valid(&self) -> Result<(), CredentialError> {
        if self.host_scope.provider() != self.expected_provider
            || self.host_scope.namespace() != self.expected_namespace
            || &self.intent.operation != self.operation
        {
            return Err(CredentialError::ScopeMismatch);
        }
        self.intent
            .validate()
            .map_err(|_| CredentialError::InvalidIntent)
    }
}

/// Mandatory policy callback, provided and configured by the authenticated
/// host. This is NOT KM-05's cryptographic PolicyGate: KM-05 policy is still
/// required separately for every operation dispatched to a KeyProvider.
pub trait CredentialAuthorization: Send + Sync {
    /// Return Permit only with independent authority for this exact context.
    fn authorize<'a>(
        &'a self,
        request: &'a CredentialRequest<'_>,
    ) -> CredentialFuture<'a, PolicyVerdict>;
}

/// Host-injected secret callback for one immutable provider and namespace.
/// It does NOT store or manage credentials, perform IAM, or invoke crypto.
///
/// A source's credentials must not be pre-exported to global logs, copied to
/// unmanaged buffers, or retrieved outside the explicit scope. The host is
/// responsible for independently verifying those claims.
pub trait CredentialSource: Send + Sync {
    /// The one concrete configured provider instance this callback serves.
    fn provider(&self) -> &ProviderInstanceId;
    /// The one host-authorized account/tenant partition.
    fn namespace(&self) -> &ProviderNamespace;
    /// Fetch owned, short-lived sensitive credentials, without strings/errors
    /// containing the secret. The callback MUST obey request.operation/purpose.
    fn acquire<'a>(
        &'a self,
        request: &'a CredentialRequest<'_>,
    ) -> CredentialFuture<'a, ScopedCredential>;
}

/// A move-only owned credential bound to its provider, namespace, operation
/// and intended purpose. Debug is redacted; no Clone, Serialize, Display,
/// Deref, AsRef or public raw byte buffer.
///
/// Construction is only an untrusted callback claim; the checked acquisition
/// helper validates these identifiers against independently supplied context.
#[must_use = "credential must be used only in its scoped lifetime"]
pub struct ScopedCredential {
    scope: HostScope,
    operation: CryptoOperation,
    purpose: CredentialPurpose,
    secret: SecretBytes,
}
impl ScopedCredential {
    /// Construct a credential with explicit claim scope and purpose.
    pub fn new(
        scope: HostScope,
        operation: CryptoOperation,
        purpose: CredentialPurpose,
        secret: SecretBytes,
    ) -> Self {
        Self {
            scope,
            operation,
            purpose,
            secret,
        }
    }

    /// Host-authorized provider/namespace claim; not standalone proof.
    pub fn scope(&self) -> &HostScope {
        &self.scope
    }
    /// Exact operation claim.
    pub fn operation(&self) -> &CryptoOperation {
        &self.operation
    }
    /// Approved purpose.
    pub fn purpose(&self) -> CredentialPurpose {
        self.purpose
    }
    /// Number of sensitive bytes without exposing contents.
    pub fn len(&self) -> usize {
        self.secret.len()
    }
    /// Whether the owned bytes have already been erased.
    pub fn is_empty(&self) -> bool {
        self.secret.is_empty()
    }
    /// Wipe owned bytes early; Drop wipes on all exit paths as well.
    pub fn erase(&mut self) {
        self.secret.erase();
    }

    /// Deliberately expose bytes only to a synchronous **trusted** adapter
    /// callback. No general raw-slice trait is implemented. The closure
    /// cannot return a borrowed slice, but may deliberately copy bytes:
    /// treat callbacks as privileged, audited code and never log material.
    pub fn with_exposed(&self, consume: impl FnOnce(&[u8])) {
        self.secret.with_exposed(consume);
    }
}
impl fmt::Debug for ScopedCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ScopedCredential(<redacted>)")
    }
}

/// A fail-closed, one-shot credential acquisition gate.
///
/// Gate order: verify independently supplied provider/tenant/operation,
/// verify source's configured identity, evaluate host authorization,
/// then invoke exactly one credential callback, finally validate the
/// returned provider/tenant/operation/purpose and non-erased material.
///
/// Denied/unknown policy, mismatched scope or invalid intent => **zero**
/// CredentialSource::acquire calls. Mismatched returned material is dropped,
/// triggering owned-buffer zeroization. No automatic retries or fallback.
///
/// KM-05's execute_checked still denies raw key material and still requires
/// its separate mandatory PolicyGate on any actual cryptographic dispatch.
pub async fn acquire_scoped_credential(
    source: &dyn CredentialSource,
    authorization: &dyn CredentialAuthorization,
    request: CredentialRequest<'_>,
) -> Result<ScopedCredential, CredentialError> {
    request.structurally_valid()?;
    if source.provider() != request.expected_provider
        || source.namespace() != request.expected_namespace
    {
        return Err(CredentialError::ScopeMismatch);
    }

    match authorization.authorize(&request).await {
        Ok(PolicyVerdict::Permit) => {}
        Ok(PolicyVerdict::Deny) => return Err(CredentialError::PolicyDenied),
        Ok(PolicyVerdict::Indeterminate) | Err(_) => {
            return Err(CredentialError::PolicyIndeterminate);
        }
    }

    // Recheck source identity following a potentially asynchronous policy.
    if source.provider() != request.expected_provider
        || source.namespace() != request.expected_namespace
    {
        return Err(CredentialError::ScopeMismatch);
    }
    let result = source.acquire(&request).await?;
    if result.scope() != request.host_scope
        || result.operation() != request.operation
        || result.purpose() != request.purpose
    {
        return Err(CredentialError::ScopeMismatch);
    }
    if result.is_empty() {
        return Err(CredentialError::InvalidMaterial);
    }
    Ok(result)
}
