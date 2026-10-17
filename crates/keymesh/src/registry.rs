//! Explicit, fail-closed provider registration and capability routing.
//!
//! Only the host enrolls provider instances and independently establishes
//! scope, custody/version assurance and health. No network discovery, SDK,
//! automatic fallback, policy evaluator or cryptographic primitive is included.

use crate::{
    Admission, CapabilityError, HostScope, HostValidatedCapabilities, KeyProvider,
    OperationCompletion, OperationIntent, OperationRequest, PolicyContext, PolicyGate,
    PolicyVerdict, ProviderError, ProviderErrorKind, ProviderFuture, ProviderInstanceId,
    ProviderNamespace, execute_checked,
};
use core::fmt;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Arc, RwLock};

/// Maximum configured provider instances in a single local registry.
pub const MAX_REGISTERED_PROVIDERS: usize = 128;

/// Host-asserted provider health; not automatic proof of KMS or HSM reachability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderHealth {
    /// No independent host health decision; never route an operation.
    Unknown,
    /// The host has independently allowed this provider for new routing.
    Healthy,
    /// Provider is explicitly unavailable for new routing.
    Unavailable,
}
impl ProviderHealth {
    const fn encode(self) -> u8 {
        match self {
            Self::Unknown => 0,
            Self::Healthy => 1,
            Self::Unavailable => 2,
        }
    }
    const fn decode(byte: u8) -> Self {
        match byte {
            1 => Self::Healthy,
            2 => Self::Unavailable,
            _ => Self::Unknown,
        }
    }
}

/// Registration or health-change errors never echo provider/tenant strings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegistrationError {
    /// Same provider instance already has an active registration.
    DuplicateInstance,
    /// The host-authorized provider/tenant scope does not match the adapter.
    ScopeMismatch,
    /// Registry has reached its hard limit on provider instances.
    CapacityExceeded,
    /// The instance/scope is no longer present.
    NotRegistered,
    /// Internal lock could not be safely acquired.
    RegistryUnavailable,
}
impl fmt::Display for RegistrationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::DuplicateInstance => "provider already registered",
            Self::ScopeMismatch => "provider registration scope mismatch",
            Self::CapacityExceeded => "provider registry capacity exceeded",
            Self::NotRegistered => "provider not registered in authorized scope",
            Self::RegistryUnavailable => "provider registry unavailable",
        })
    }
}
impl std::error::Error for RegistrationError {}

/// Selection must be explicitly scoped to one provider or explicitly opt in
/// to considering any provider with **all** hard requirements satisfied.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProviderSelection {
    /// No substitution or fallback when this instance is unavailable.
    Instance(ProviderInstanceId),
    /// The caller deliberately opts in to capability-based matching.
    AnyCompatible,
}

/// Borrowed hard requirements. The host supplies an explicit list of
/// independently approved provider/tenant scopes. This enables opt-in
/// AnyCompatible without inventing authority over otherwise unapproved
/// providers. Every listed scope MUST be authenticated by the host.
pub struct ProviderRequirements<'a> {
    /// The provider/tenant scopes explicitly authorized by the host.
    pub authorized_scopes: &'a [HostScope],
    /// Exact FOSS-403 algorithm, operation, payload/assurance/export request.
    pub intent: &'a OperationIntent,
    /// Exact instance or explicit capability-routing opt-in.
    pub selection: &'a ProviderSelection,
}

/// Sanitized reason for not choosing a registered candidate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RejectionReason {
    /// Candidate host scope, instance or tenant does not match.
    ScopeMismatch,
    /// Provider was deregistered or replaced during evaluation.
    Deregistered,
    /// Host health is Unknown or Unavailable.
    NotHealthy,
    /// Capability read was unavailable/failed; no crypto was dispatched.
    CapabilityReadFailure,
    /// Exact algorithm/operation or payload limit not met.
    CapabilityMismatch,
    /// Custody, version or export assurance cannot be verified.
    AssuranceMismatch,
}

/// Bounded, secret-free diagnostic summary. No backend SDK error,
/// credential, native key path, tenant label or provider handle is stored.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouteTrace {
    /// Number of explicit candidates evaluated (bounded by registry limit).
    pub examined: usize,
    /// Number of candidates rejected without provider operation dispatch.
    pub rejected: usize,
    /// Rejection counts by fixed static category.
    pub reason_counts: [usize; 6],
}
impl RouteTrace {
    fn new() -> Self {
        Self {
            examined: 0,
            rejected: 0,
            reason_counts: [0; 6],
        }
    }
    fn reject(&mut self, reason: RejectionReason) {
        self.rejected += 1;
        let index = match reason {
            RejectionReason::ScopeMismatch => 0,
            RejectionReason::Deregistered => 1,
            RejectionReason::NotHealthy => 2,
            RejectionReason::CapabilityReadFailure => 3,
            RejectionReason::CapabilityMismatch => 4,
            RejectionReason::AssuranceMismatch => 5,
        };
        self.reason_counts[index] += 1;
    }
    /// Number of rejections for a specific non-sensitive category.
    pub fn count(&self, reason: RejectionReason) -> usize {
        let i = match reason {
            RejectionReason::ScopeMismatch => 0,
            RejectionReason::Deregistered => 1,
            RejectionReason::NotHealthy => 2,
            RejectionReason::CapabilityReadFailure => 3,
            RejectionReason::CapabilityMismatch => 4,
            RejectionReason::AssuranceMismatch => 5,
        };
        self.reason_counts[i]
    }
}

/// Routing failure; no other provider will be tried after operation dispatch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RouteError {
    /// The requested intent is structurally invalid.
    InvalidRequirements,
    /// No registered candidate met all required security properties.
    NoCompatibleProvider,
    /// Returned lease or pending request was revoked/replaced.
    StaleRegistration,
    /// Internal registry lock was unavailable or poisoned.
    RegistryUnavailable,
}
impl fmt::Display for RouteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidRequirements => "invalid provider routing requirements",
            Self::NoCompatibleProvider => "no compatible authorized provider",
            Self::StaleRegistration => "provider registration revoked",
            Self::RegistryUnavailable => "provider registry unavailable",
        })
    }
}
impl std::error::Error for RouteError {}

/// Safe diagnostics for a failed route, including only *authorized* candidate
/// counts and fixed static reason categories. No tenant/provider labels.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoutingFailure {
    /// Static routing error kind.
    pub kind: RouteError,
    /// Bounded rejection counts, never raw backend diagnostics.
    pub trace: RouteTrace,
}
impl RoutingFailure {
    fn new(kind: RouteError, trace: RouteTrace) -> Self {
        Self { kind, trace }
    }
}
impl fmt::Display for RoutingFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.kind.fmt(f)
    }
}
impl std::error::Error for RoutingFailure {}

struct Registration {
    provider: Arc<dyn KeyProvider>,
    scope: HostScope,
    host: HostValidatedCapabilities,
    active: AtomicBool,
    health: AtomicU8,
}
impl Registration {
    fn is_live(&self) -> bool {
        self.active.load(Ordering::Acquire)
    }
    fn health(&self) -> ProviderHealth {
        ProviderHealth::decode(self.health.load(Ordering::Acquire))
    }
}

#[derive(Default)]
struct State {
    entries: BTreeMap<ProviderInstanceId, Arc<Registration>>,
}

/// A local, explicit registry. Clones share a thread-safe registration map.
/// Read/write locks are NEVER held during an asynchronous provider method.
#[derive(Clone, Default)]
pub struct ProviderRegistry {
    inner: Arc<RwLock<State>>,
}
impl fmt::Debug for ProviderRegistry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ProviderRegistry(<redacted>)")
    }
}
impl ProviderRegistry {
    /// Create an empty registry; there is no global provider default.
    pub fn new() -> Self {
        Self::default()
    }

    /// Enroll a host-approved provider/tenant scope. A registration represents
    /// exactly one independently approved scope for this ProviderInstanceId.
    /// Multi-tenant hosts need separately configured provider instances.
    pub fn register(
        &self,
        provider: Arc<dyn KeyProvider>,
        scope: HostScope,
        host: HostValidatedCapabilities,
        health: ProviderHealth,
    ) -> Result<(), RegistrationError> {
        if provider.instance() != scope.provider() || host.scope.as_ref() != Some(&scope) {
            return Err(RegistrationError::ScopeMismatch);
        }
        let mut state = self
            .inner
            .write()
            .map_err(|_| RegistrationError::RegistryUnavailable)?;
        if state.entries.contains_key(scope.provider()) {
            return Err(RegistrationError::DuplicateInstance);
        }
        if state.entries.len() >= MAX_REGISTERED_PROVIDERS {
            return Err(RegistrationError::CapacityExceeded);
        }
        state.entries.insert(
            scope.provider().clone(),
            Arc::new(Registration {
                provider,
                scope,
                host,
                health: AtomicU8::new(health.encode()),
                active: AtomicBool::new(true),
            }),
        );
        Ok(())
    }

    /// Change health only for the exact registered provider/tenant. An Unknown
    /// status never authorizes dispatch, and this is a host assertion only.
    pub fn set_health(
        &self,
        scope: &HostScope,
        status: ProviderHealth,
    ) -> Result<(), RegistrationError> {
        let state = self
            .inner
            .read()
            .map_err(|_| RegistrationError::RegistryUnavailable)?;
        let entry = state
            .entries
            .get(scope.provider())
            .ok_or(RegistrationError::NotRegistered)?;
        if &entry.scope != scope || !entry.is_live() {
            return Err(RegistrationError::ScopeMismatch);
        }
        entry.health.store(status.encode(), Ordering::Release);
        Ok(())
    }

    /// Revoke enrollment. Any route still reading async capabilities observes
    /// the revoked flag before successful handoff. Existing native operations
    /// already dispatched CANNOT be rolled back by deregistration.
    pub fn unregister(&self, scope: &HostScope) -> Result<(), RegistrationError> {
        let mut state = self
            .inner
            .write()
            .map_err(|_| RegistrationError::RegistryUnavailable)?;
        let entry = state
            .entries
            .get(scope.provider())
            .ok_or(RegistrationError::NotRegistered)?;
        if &entry.scope != scope {
            return Err(RegistrationError::ScopeMismatch);
        }
        entry.active.store(false, Ordering::Release);
        state.entries.remove(scope.provider());
        Ok(())
    }

    /// Read-only candidate selection. No cryptographic or lifecycle method is
    /// called here. Candidate order is deterministic by ProviderInstanceId.
    /// An unavailable explicit instance NEVER falls back to AnyCompatible.
    pub async fn route(
        &self,
        requirements: ProviderRequirements<'_>,
    ) -> Result<RoutedProvider, RouteError> {
        self.route_diagnostic(requirements).await.map_err(|failure| failure.kind)
    }

    /// Like route(), but also returns a bounded, redacted rejection summary
    /// on failure. Counts cover only host-authorized candidates.
    pub async fn route_diagnostic(
        &self,
        requirements: ProviderRequirements<'_>,
    ) -> Result<RoutedProvider, RoutingFailure> {
        let mut trace = RouteTrace::new();
        requirements
            .intent
            .validate()
            .map_err(|_| RoutingFailure::new(RouteError::InvalidRequirements, trace.clone()))?;
        // Every provider is independently authorized for the same tenant.
        // A caller cannot substitute a different tenant during AnyCompatible.
        let Some(first) = requirements.authorized_scopes.first() else {
            return Err(RoutingFailure::new(RouteError::InvalidRequirements, trace));
        };
        if requirements.authorized_scopes.len() > MAX_REGISTERED_PROVIDERS
            || requirements
                .authorized_scopes
                .iter()
                .any(|scope| scope.namespace() != first.namespace())
        {
            return Err(RoutingFailure::new(RouteError::InvalidRequirements, trace));
        }
        let candidates = {
            let state = self
                .inner
                .read()
                .map_err(|_| RoutingFailure::new(RouteError::RegistryUnavailable, trace.clone()))?;
            match requirements.selection {
                ProviderSelection::Instance(id) => state
                    .entries
                    .get(id)
                    .filter(|entry| requirements.authorized_scopes.contains(&entry.scope))
                    .cloned()
                    .into_iter()
                    .collect::<Vec<_>>(),
                ProviderSelection::AnyCompatible => state
                    .entries
                    .values()
                    .filter(|entry| requirements.authorized_scopes.contains(&entry.scope))
                    .cloned()
                    .collect::<Vec<_>>(),
            }
        };
        for entry in candidates {
            trace.examined += 1;
            if !entry.is_live() {
                trace.reject(RejectionReason::Deregistered);
                continue;
            }
            if !requirements
                .authorized_scopes
                .iter()
                .any(|authorized| authorized == &entry.scope)
                || entry.provider.instance() != entry.scope.provider()
                || entry.host.scope.as_ref() != Some(&entry.scope)
            {
                trace.reject(RejectionReason::ScopeMismatch);
                continue;
            }
            if entry.health() != ProviderHealth::Healthy {
                trace.reject(RejectionReason::NotHealthy);
                continue;
            }
            let catalog = match entry.provider.capabilities(&entry.scope).await {
                Ok(catalog) => catalog,
                Err(_) => {
                    trace.reject(RejectionReason::CapabilityReadFailure);
                    continue;
                }
            };
            if !entry.is_live() {
                trace.reject(RejectionReason::Deregistered);
                continue;
            }
            let admitted = match catalog.admit(requirements.intent, &entry.host) {
                Ok(admission) => admission,
                Err(error) => {
                    let reason = match error {
                        CapabilityError::UnverifiedVersion
                        | CapabilityError::UnverifiedProtection
                        | CapabilityError::ExportNotPermitted => RejectionReason::AssuranceMismatch,
                        CapabilityError::ScopeMismatch => RejectionReason::ScopeMismatch,
                        _ => RejectionReason::CapabilityMismatch,
                    };
                    trace.reject(reason);
                    continue;
                }
            };
            // Double-check provider membership, rather than returning a stale
            // Arc after an await with a concurrent unregister/re-register.
            if !entry.is_live() {
                trace.reject(RejectionReason::Deregistered);
                continue;
            }
            return Ok(RoutedProvider {
                entry,
                intent: requirements.intent.clone(),
                admission: admitted,
                trace,
            });
        }
        Err(RoutingFailure::new(RouteError::NoCompatibleProvider, trace))
    }
}

/// An exact, scoped provider decision. It cannot be used with a different
/// operation intent or host scope. Debug redacts provider/tenant/key values.
pub struct RoutedProvider {
    entry: Arc<Registration>,
    intent: OperationIntent,
    admission: Admission,
    trace: RouteTrace,
}
impl fmt::Debug for RoutedProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RoutedProvider(<redacted>)")
    }
}
impl RoutedProvider {
    /// Provider name selected by deterministic capability matching (safe only
    /// in permissioned audit contexts; Debug intentionally redacts it).
    pub fn instance(&self) -> &ProviderInstanceId {
        self.entry.scope.provider()
    }

    /// Tenant namespace selected by host authority, not untrusted caller data.
    pub fn namespace(&self) -> &ProviderNamespace {
        self.entry.scope.namespace()
    }

    /// Accepted exact algorithm/operation entry.
    pub fn admission(&self) -> &Admission {
        &self.admission
    }

    /// Sanitized, bounded summary of selection criteria.
    pub fn trace(&self) -> &RouteTrace {
        &self.trace
    }

    /// Check the registration lease immediately before a new operation. A
    /// revoked route is never a valid authority after unregister.
    pub fn ensure_live(&self) -> Result<(), RouteError> {
        if self.entry.is_live() && self.entry.health() == ProviderHealth::Healthy {
            Ok(())
        } else {
            Err(RouteError::StaleRegistration)
        }
    }

    /// Execute with original mandatory FOSS-404 policy and input checks.
    /// A guarded policy rechecks registration *after* await and immediately
    /// before operation dispatch. A route never bypasses execute_checked.
    /// Deregistration cannot cancel native calls already dispatched.
    pub async fn execute(
        &self,
        policy: &dyn PolicyGate,
        request: OperationRequest<'_>,
    ) -> Result<OperationCompletion, ProviderError> {
        let denied = || ProviderError::not_dispatched(ProviderErrorKind::ScopeMismatch);
        self.ensure_live().map_err(|_| denied())?;
        if request.scope != &self.entry.scope
            || request.host_assurance != &self.entry.host
            || request.intent != &self.intent
            || request.reference.provider() != self.entry.scope.provider()
            || request.reference.namespace() != self.entry.scope.namespace()
        {
            return Err(denied());
        }
        let guard = RegistryPolicy {
            inner: policy,
            entry: &self.entry,
        };
        execute_checked(self.entry.provider.as_ref(), &guard, request).await
    }
}
struct RegistryPolicy<'a> {
    inner: &'a dyn PolicyGate,
    entry: &'a Registration,
}
impl PolicyGate for RegistryPolicy<'_> {
    fn evaluate<'a>(&'a self, ctx: &'a PolicyContext<'_>) -> ProviderFuture<'a, PolicyVerdict> {
        Box::pin(async move {
            if !self.entry.is_live() || self.entry.health() != ProviderHealth::Healthy {
                return Ok(PolicyVerdict::Indeterminate);
            }
            let decision = self.inner.evaluate(ctx).await?;
            if !self.entry.is_live() || self.entry.health() != ProviderHealth::Healthy {
                return Ok(PolicyVerdict::Indeterminate);
            }
            Ok(decision)
        })
    }
}
