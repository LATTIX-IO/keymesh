//! Exact-version, process-local Ed25519 lifecycle with CAS-protected mutation.
//!
//! Host IAM and policy evaluation are **external**. Mutations never await
//! while holding an in-memory lock. This is NOT durable key-management.

use super::*;
use crate::CorrelationId;
use zeroize::Zeroizing;

/// Hard per-logical-key bound on retained signing or verification versions.
pub const MAX_SOFTWARE_VERSIONS_PER_KEY: usize = 32;

/// Transition types intentionally distinct from generic KM-05 lifecycle verbs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SoftwareTransitionAction {
    /// Stop all cryptographic use of an active or retired version.
    Disable,
    /// Reactivate a disabled version only if no other version is active.
    Enable,
    /// Mark an inactive version for explicit deletion; no background timer.
    ScheduleDelete,
}
impl SoftwareTransitionAction {
    fn policy_action(self) -> SoftwareLifecycleAction {
        match self {
            Self::Disable => SoftwareLifecycleAction::Disable,
            Self::Enable => SoftwareLifecycleAction::Enable,
            Self::ScheduleDelete => SoftwareLifecycleAction::ScheduleDelete,
        }
    }
}

/// Rotate only from an exact currently active provider version, comparing the
/// caller's observed monotonic record generation before and after host policy.
pub struct SoftwareRotateRequest<'a> {
    /// Authenticated host tenant/provider scope.
    pub scope: &'a HostScope,
    /// Independently verified Software/ProviderVersion capabilities.
    pub host_assurance: &'a HostValidatedCapabilities,
    /// Exact currently active resource/version, never Active/Latest.
    pub previous: &'a KeyRef,
    /// Snapshot generation, rejected if another lifecycle mutation committed.
    pub expected_generation: u64,
    /// Exact Ed25519 Generate intent, not arbitrary provider key material.
    pub intent: &'a OperationIntent,
    /// Optional host-generated, bounded safe correlation ID.
    pub correlation: Option<&'a CorrelationId>,
}

/// Change the state of an exact, existing provider version without changing
/// its immutable identity or signing material.
pub struct SoftwareTransitionRequest<'a> {
    /// Authenticated host scope.
    pub scope: &'a HostScope,
    /// Independent host corroboration.
    pub host_assurance: &'a HostValidatedCapabilities,
    /// Exact resource/version selector.
    pub reference: &'a KeyRef,
    /// Compare-and-swap generation of the logical key record.
    pub expected_generation: u64,
    /// Only explicitly enumerated state transitions are supported.
    pub action: SoftwareTransitionAction,
    /// Optional host-generated correlation label.
    pub correlation: Option<&'a CorrelationId>,
}

/// Non-secret lifecycle event evidence. No key bytes, external SDK errors or
/// credentials are retained. Debug is redacted to prevent accidental logging.
#[derive(Clone, Eq, PartialEq)]
pub struct SoftwareLifecycleEvidence {
    action: SoftwareLifecycleAction,
    scope: HostScope,
    logical_key: LogicalKeyId,
    previous: Option<KeyRef>,
    current: Option<KeyRef>,
    from: Option<SoftwareVersionState>,
    to: Option<SoftwareVersionState>,
    generation: u64,
    correlation: Option<CorrelationId>,
}
impl fmt::Debug for SoftwareLifecycleEvidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SoftwareLifecycleEvidence(<redacted>)")
    }
}
impl SoftwareLifecycleEvidence {
    /// The separately policy-approved state machine action.
    pub fn action(&self) -> SoftwareLifecycleAction {
        self.action
    }
    /// Authorized, exact tenant/provider scope.
    pub fn scope(&self) -> &HostScope {
        &self.scope
    }
    /// Logical name; metadata only, never a credential.
    pub fn logical_key(&self) -> &LogicalKeyId {
        &self.logical_key
    }
    /// Exact previous provider version, where applicable.
    pub fn previous(&self) -> Option<&KeyRef> {
        self.previous.as_ref()
    }
    /// New/existing affected exact provider version, if not purged.
    pub fn current(&self) -> Option<&KeyRef> {
        self.current.as_ref()
    }
    /// Status prior to the committed action, where applicable.
    pub fn from(&self) -> Option<SoftwareVersionState> {
        self.from
    }
    /// Status after the committed action, if retained.
    pub fn to(&self) -> Option<SoftwareVersionState> {
        self.to
    }
    /// Strictly increasing in-process lifecycle generation.
    pub fn generation(&self) -> u64 {
        self.generation
    }
    /// Optional safe, host-issued correlation label.
    pub fn correlation(&self) -> Option<&CorrelationId> {
        self.correlation.as_ref()
    }
}

/// Public metadata for one independently selectable provider key version.
/// Never includes private KeyMaterial. Debug is redacted.
pub struct SoftwareVersionSnapshot {
    reference: KeyRef,
    status: SoftwareVersionState,
    issued_generation: u64,
}
impl SoftwareVersionSnapshot {
    /// Immutable concrete version/ID.
    pub fn reference(&self) -> &KeyRef {
        &self.reference
    }
    /// Mutable authorization state, never evidence of hardware custody.
    pub fn status(&self) -> SoftwareVersionState {
        self.status
    }
    /// Monotonic version creation order (not a wall clock).
    pub fn issued_generation(&self) -> u64 {
        self.issued_generation
    }
}
impl fmt::Debug for SoftwareVersionSnapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SoftwareVersionSnapshot(<redacted>)")
    }
}

/// A bounded, process-local logical-key snapshot for optimistic concurrency.
/// Constructing HostScope does not authenticate a caller; host access policy
/// must separately govern whether this metadata can be requested.
pub struct SoftwareLogicalSnapshot {
    generation: u64,
    active: Option<KeyRef>,
    latest: Option<KeyRef>,
    versions: Vec<SoftwareVersionSnapshot>,
}
impl SoftwareLogicalSnapshot {
    /// CAS generation to send back with a specific state-changing operation.
    pub fn generation(&self) -> u64 {
        self.generation
    }
    /// Exact active version, if one exists.
    pub fn active(&self) -> Option<&KeyRef> {
        self.active.as_ref()
    }
    /// Most recently generated retained version, not necessarily active.
    pub fn latest(&self) -> Option<&KeyRef> {
        self.latest.as_ref()
    }
    /// Bound on retained historical versions (max 32 per logical key).
    pub fn versions(&self) -> &[SoftwareVersionSnapshot] {
        &self.versions
    }
}
impl fmt::Debug for SoftwareLogicalSnapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SoftwareLogicalSnapshot(<redacted>)")
    }
}

/// Newly generated version and its associated non-secret lifecycle receipt.
pub struct SoftwareRotation {
    created: CreatedSoftwareKey,
    evidence: SoftwareLifecycleEvidence,
}
impl SoftwareRotation {
    /// Exact new target and public Ed25519 verification key.
    pub fn created(&self) -> &CreatedSoftwareKey {
        &self.created
    }
    /// Monotonic lifecycle receipt, redacted under Debug.
    pub fn evidence(&self) -> &SoftwareLifecycleEvidence {
        &self.evidence
    }
}
impl fmt::Debug for SoftwareRotation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SoftwareRotation(<redacted>)")
    }
}

impl SoftwareProvider {
    fn require_scope(
        &self,
        scope: &HostScope,
        host: &HostValidatedCapabilities,
    ) -> Result<(), ProviderError> {
        if valid_software_host(&self.instance, &self.namespace, scope, host) {
            Ok(())
        } else {
            Err(denied(ProviderErrorKind::ScopeMismatch))
        }
    }

    fn require_exact<'a>(
        &self,
        reference: &'a KeyRef,
    ) -> Result<(&'a ProviderResourceId, &'a ProviderVersionId), ProviderError> {
        if reference.provider() != &self.instance || reference.namespace() != &self.namespace {
            return Err(denied(ProviderErrorKind::ScopeMismatch));
        }
        match reference.selector() {
            KeySelector::ExactProviderVersion { resource, version } => Ok((resource, version)),
            _ => Err(denied(ProviderErrorKind::UnsupportedVersionAssurance)),
        }
    }

    fn next_generation(state: &SoftwareState) -> Result<u64, ProviderError> {
        state
            .next_generation
            .checked_add(1)
            .ok_or_else(|| denied(ProviderErrorKind::Unavailable))
    }

    fn make_reference(&self, name: &LogicalKeyId, entry: &StoredKey) -> KeyRef {
        let (resource, version) = match &entry.target {
            DispatchTarget::ProviderVersion { resource, version } => {
                (resource.clone(), version.clone())
            }
            _ => unreachable!("SoftwareProvider only stores exact provider versions"),
        };
        KeyRef::new(
            self.instance.clone(),
            self.namespace.clone(),
            name.clone(),
            KeySelector::ExactProviderVersion { resource, version },
        )
    }

    // OS randomness is sampled only after a lifecycle Permit, while under
    // the final mutation lock. A failure leaves state untouched.
    fn fresh_material(
        &self,
        generation: u64,
    ) -> Result<(StoredKey, ProviderResourceId, ProviderVersionId), ProviderError> {
        let mut seed = Zeroizing::new(vec![0u8; 32]);
        getrandom::getrandom(&mut seed).map_err(|_| denied(ProviderErrorKind::Unavailable))?;
        let mut nonce = Zeroizing::new([0u8; 16]);
        getrandom::getrandom(&mut *nonce).map_err(|_| denied(ProviderErrorKind::Unavailable))?;
        let unique = lower_hex(&*nonce);
        let resource = ProviderResourceId::parse(&format!("memory:ed25519:{unique}"))
            .map_err(|_| denied(ProviderErrorKind::Unavailable))?;
        let version = ProviderVersionId::parse(&format!("v{unique}"))
            .map_err(|_| denied(ProviderErrorKind::Unavailable))?;
        let seed_ref = <&[u8; 32]>::try_from(seed.as_slice())
            .map_err(|_| denied(ProviderErrorKind::Unavailable))?;
        let public_key = SigningKey::from_bytes(seed_ref).verifying_key().to_bytes();
        let material = KeyMaterial::from_vec(std::mem::take(&mut *seed))
            .map_err(|_| denied(ProviderErrorKind::Unavailable))?;
        Ok((
            StoredKey {
                target: DispatchTarget::ProviderVersion {
                    resource: resource.clone(),
                    version: version.clone(),
                },
                public_key,
                material,
                status: SoftwareVersionState::Active,
                issued_order: generation,
            },
            resource,
            version,
        ))
    }

    fn check_current(
        &self,
        record: &LogicalRecord,
        reference: &KeyRef,
    ) -> Result<ProviderVersionId, ProviderError> {
        let (resource, version) = self.require_exact(reference)?;
        let existing = record
            .versions
            .get(version)
            .ok_or_else(|| denied(ProviderErrorKind::UnsupportedVersionAssurance))?;
        if existing.target.resource() != resource {
            return Err(denied(ProviderErrorKind::UnsupportedVersionAssurance));
        }
        Ok(version.clone())
    }

    fn check_generation(record: &LogicalRecord, expected: u64) -> Result<(), ProviderError> {
        if record.generation == expected {
            Ok(())
        } else {
            Err(denied(ProviderErrorKind::UnsupportedVersionAssurance))
        }
    }

    /// Scope-bounded snapshot. This is metadata only and is NOT an IAM policy
    /// decision; the host must authenticate metadata access independently.
    pub fn snapshot(
        &self,
        scope: &HostScope,
        host_assurance: &HostValidatedCapabilities,
        logical: &LogicalKeyId,
    ) -> Result<SoftwareLogicalSnapshot, ProviderError> {
        self.require_scope(scope, host_assurance)?;
        let state = self
            .keys
            .read()
            .map_err(|_| denied(ProviderErrorKind::Unavailable))?;
        let record = state
            .records
            .get(logical)
            .ok_or_else(|| denied(ProviderErrorKind::UnsupportedVersionAssurance))?;
        let versions = record
            .versions
            .values()
            .map(|entry| SoftwareVersionSnapshot {
                reference: self.make_reference(logical, entry),
                status: entry.status,
                issued_generation: entry.issued_order,
            })
            .collect();
        let to_ref = |version: &ProviderVersionId| {
            record
                .versions
                .get(version)
                .map(|entry| self.make_reference(logical, entry))
        };
        Ok(SoftwareLogicalSnapshot {
            generation: record.generation,
            active: record.active.as_ref().and_then(to_ref),
            latest: record.latest.as_ref().and_then(to_ref),
            versions,
        })
    }

    /// KM-08 backwards-compatible initial creation. No old version is
    /// overwritten; an existing logical key remains a hard conflict.
    pub(super) async fn create_initial(
        &self,
        policy: &dyn SoftwareLifecycleGate,
        request: SoftwareCreateRequest<'_>,
    ) -> Result<CreatedSoftwareKey, ProviderError> {
        self.require_scope(request.scope, request.host_assurance)?;
        if request.intent != &Self::create_intent() || request.intent.validate().is_err() {
            return Err(denied(ProviderErrorKind::UnsupportedOperationOrProfile));
        }
        {
            let state = self
                .keys
                .read()
                .map_err(|_| denied(ProviderErrorKind::Unavailable))?;
            if state.records.contains_key(request.logical_key)
                || state.total_versions >= MAX_SOFTWARE_KEYS
            {
                return Err(denied(ProviderErrorKind::InvalidInput));
            }
        }
        let ctx = SoftwareLifecycleContext {
            scope: request.scope,
            logical_key: request.logical_key,
            action: SoftwareLifecycleAction::Generate,
            reference: None,
            expected_generation: None,
        };
        policy_result(policy.authorize(&ctx).await)?;
        let mut state = self
            .keys
            .write()
            .map_err(|_| denied(ProviderErrorKind::Unavailable))?;
        if state.records.contains_key(request.logical_key)
            || state.total_versions >= MAX_SOFTWARE_KEYS
        {
            return Err(denied(ProviderErrorKind::InvalidInput));
        }
        let generation = Self::next_generation(&state)?;
        let (stored, resource, version) = self.fresh_material(generation)?;
        let public_key = stored.public_key;
        let mut versions = BTreeMap::new();
        versions.insert(version.clone(), stored);
        state.records.insert(
            request.logical_key.clone(),
            LogicalRecord {
                versions,
                active: Some(version.clone()),
                latest: Some(version.clone()),
                generation,
            },
        );
        state.total_versions += 1;
        state.next_generation = generation;
        Ok(CreatedSoftwareKey {
            reference: KeyRef::new(
                self.instance.clone(),
                self.namespace.clone(),
                request.logical_key.clone(),
                KeySelector::ExactProviderVersion { resource, version },
            ),
            public_key,
            generation,
        })
    }

    /// Authorize then atomically retire the old active version and mint a
    /// fresh, immutable CSPRNG-backed active version. No fallback, overwrite,
    /// implicit alias dispatch or key-material copy occurs.
    pub async fn rotate(
        &self,
        policy: &dyn SoftwareLifecycleGate,
        request: SoftwareRotateRequest<'_>,
    ) -> Result<SoftwareRotation, ProviderError> {
        self.require_scope(request.scope, request.host_assurance)?;
        let (_, prior_version) = self.require_exact(request.previous)?;
        if request.intent != &Self::create_intent() || request.intent.validate().is_err() {
            return Err(denied(ProviderErrorKind::UnsupportedOperationOrProfile));
        }
        {
            let state = self
                .keys
                .read()
                .map_err(|_| denied(ProviderErrorKind::Unavailable))?;
            let record = state
                .records
                .get(request.previous.logical_key())
                .ok_or_else(|| denied(ProviderErrorKind::UnsupportedVersionAssurance))?;
            Self::check_generation(record, request.expected_generation)?;
            self.check_current(record, request.previous)?;
            if record.active.as_ref() != Some(prior_version)
                || record.versions.get(prior_version).map(|v| v.status)
                    != Some(SoftwareVersionState::Active)
            {
                return Err(denied(ProviderErrorKind::AuthorizationDenied));
            }
            if state.total_versions >= MAX_SOFTWARE_KEYS
                || record.versions.len() >= MAX_SOFTWARE_VERSIONS_PER_KEY
            {
                return Err(denied(ProviderErrorKind::InvalidInput));
            }
        }
        let ctx = SoftwareLifecycleContext {
            scope: request.scope,
            logical_key: request.previous.logical_key(),
            action: SoftwareLifecycleAction::Rotate,
            reference: Some(request.previous),
            expected_generation: Some(request.expected_generation),
        };
        policy_result(policy.authorize(&ctx).await)?;
        let mut state = self
            .keys
            .write()
            .map_err(|_| denied(ProviderErrorKind::Unavailable))?;
        let generation = Self::next_generation(&state)?;
        {
            let record = state
                .records
                .get(request.previous.logical_key())
                .ok_or_else(|| denied(ProviderErrorKind::UnsupportedVersionAssurance))?;
            Self::check_generation(record, request.expected_generation)?;
            self.check_current(record, request.previous)?;
            if record.active.as_ref() != Some(prior_version)
                || record.versions.get(prior_version).map(|v| v.status)
                    != Some(SoftwareVersionState::Active)
            {
                return Err(denied(ProviderErrorKind::AuthorizationDenied));
            }
            if state.total_versions >= MAX_SOFTWARE_KEYS
                || record.versions.len() >= MAX_SOFTWARE_VERSIONS_PER_KEY
            {
                return Err(denied(ProviderErrorKind::InvalidInput));
            }
        }
        let (stored, resource, version) = self.fresh_material(generation)?;
        let public_key = stored.public_key;
        let record = state
            .records
            .get_mut(request.previous.logical_key())
            .ok_or_else(|| denied(ProviderErrorKind::UnsupportedVersionAssurance))?;
        if record.versions.contains_key(&version) {
            return Err(denied(ProviderErrorKind::Unavailable));
        }
        if let Some(previous) = record.versions.get_mut(prior_version) {
            previous.status = SoftwareVersionState::Retired;
        }
        record.versions.insert(version.clone(), stored);
        record.active = Some(version.clone());
        record.latest = Some(version.clone());
        record.generation = generation;
        state.total_versions += 1;
        state.next_generation = generation;
        let reference = KeyRef::new(
            self.instance.clone(),
            self.namespace.clone(),
            request.previous.logical_key().clone(),
            KeySelector::ExactProviderVersion { resource, version },
        );
        Ok(SoftwareRotation {
            created: CreatedSoftwareKey {
                reference: reference.clone(),
                public_key,
                generation,
            },
            evidence: SoftwareLifecycleEvidence {
                action: SoftwareLifecycleAction::Rotate,
                scope: request.scope.clone(),
                logical_key: request.previous.logical_key().clone(),
                previous: Some(request.previous.clone()),
                current: Some(reference),
                from: Some(SoftwareVersionState::Active),
                to: Some(SoftwareVersionState::Active),
                generation,
                correlation: request.correlation.cloned(),
            },
        })
    }

    fn permitted_transition(
        record: &LogicalRecord,
        version: &ProviderVersionId,
        action: SoftwareTransitionAction,
    ) -> Result<(SoftwareVersionState, SoftwareVersionState), ProviderError> {
        let prior = record
            .versions
            .get(version)
            .ok_or_else(|| denied(ProviderErrorKind::UnsupportedVersionAssurance))?
            .status;
        let next = match (prior, action) {
            (
                SoftwareVersionState::Active | SoftwareVersionState::Retired,
                SoftwareTransitionAction::Disable,
            ) => SoftwareVersionState::Disabled,
            (SoftwareVersionState::Disabled, SoftwareTransitionAction::Enable)
                if record.active.is_none() =>
            {
                SoftwareVersionState::Active
            }
            (
                SoftwareVersionState::Retired | SoftwareVersionState::Disabled,
                SoftwareTransitionAction::ScheduleDelete,
            ) => SoftwareVersionState::PendingDeletion,
            _ => return Err(denied(ProviderErrorKind::AuthorizationDenied)),
        };
        Ok((prior, next))
    }

    /// Transition one pinned version with post-policy generation CAS.
    /// Invalid transitions perform zero mutation. No background timer or
    /// automatic key-resurrection is implemented.
    pub async fn transition(
        &self,
        policy: &dyn SoftwareLifecycleGate,
        request: SoftwareTransitionRequest<'_>,
    ) -> Result<SoftwareLifecycleEvidence, ProviderError> {
        self.require_scope(request.scope, request.host_assurance)?;
        let (_, version) = self.require_exact(request.reference)?;
        {
            let state = self
                .keys
                .read()
                .map_err(|_| denied(ProviderErrorKind::Unavailable))?;
            let record = state
                .records
                .get(request.reference.logical_key())
                .ok_or_else(|| denied(ProviderErrorKind::UnsupportedVersionAssurance))?;
            Self::check_generation(record, request.expected_generation)?;
            self.check_current(record, request.reference)?;
            Self::permitted_transition(record, version, request.action)?;
        }
        let ctx = SoftwareLifecycleContext {
            scope: request.scope,
            logical_key: request.reference.logical_key(),
            action: request.action.policy_action(),
            reference: Some(request.reference),
            expected_generation: Some(request.expected_generation),
        };
        policy_result(policy.authorize(&ctx).await)?;
        let mut state = self
            .keys
            .write()
            .map_err(|_| denied(ProviderErrorKind::Unavailable))?;
        let generation = Self::next_generation(&state)?;
        let record = state
            .records
            .get_mut(request.reference.logical_key())
            .ok_or_else(|| denied(ProviderErrorKind::UnsupportedVersionAssurance))?;
        Self::check_generation(record, request.expected_generation)?;
        self.check_current(record, request.reference)?;
        let (prior, next) = Self::permitted_transition(record, version, request.action)?;
        if let Some(entry) = record.versions.get_mut(version) {
            entry.status = next;
        }
        if prior == SoftwareVersionState::Active && next != SoftwareVersionState::Active {
            record.active = None;
        }
        if next == SoftwareVersionState::Active {
            record.active = Some(version.clone());
        }
        record.generation = generation;
        state.next_generation = generation;
        Ok(SoftwareLifecycleEvidence {
            action: request.action.policy_action(),
            scope: request.scope.clone(),
            logical_key: request.reference.logical_key().clone(),
            previous: Some(request.reference.clone()),
            current: Some(request.reference.clone()),
            from: Some(prior),
            to: Some(next),
            generation,
            correlation: request.correlation.cloned(),
        })
    }

    /// Exact-version purge with a returned redacted, monotonic lifecycle
    /// receipt. Purging an active version remains explicitly allowed to
    /// preserve KM-08 behavior; production hosts should disable first.
    pub async fn purge_with_evidence(
        &self,
        policy: &dyn SoftwareLifecycleGate,
        request: SoftwarePurgeRequest<'_>,
    ) -> Result<SoftwareLifecycleEvidence, ProviderError> {
        self.require_scope(request.scope, request.host_assurance)?;
        let (_, version) = self.require_exact(request.reference)?;
        let (expected_generation, prior_status) = {
            let state = self
                .keys
                .read()
                .map_err(|_| denied(ProviderErrorKind::Unavailable))?;
            let record = state
                .records
                .get(request.reference.logical_key())
                .ok_or_else(|| denied(ProviderErrorKind::UnsupportedVersionAssurance))?;
            let selected = self.check_current(record, request.reference)?;
            (
                record.generation,
                record
                    .versions
                    .get(&selected)
                    .ok_or_else(|| denied(ProviderErrorKind::UnsupportedVersionAssurance))?
                    .status,
            )
        };
        let ctx = SoftwareLifecycleContext {
            scope: request.scope,
            logical_key: request.reference.logical_key(),
            action: SoftwareLifecycleAction::Purge,
            reference: Some(request.reference),
            expected_generation: Some(expected_generation),
        };
        policy_result(policy.authorize(&ctx).await)?;
        let mut state = self
            .keys
            .write()
            .map_err(|_| denied(ProviderErrorKind::Unavailable))?;
        let generation = Self::next_generation(&state)?;
        let record = state
            .records
            .get_mut(request.reference.logical_key())
            .ok_or_else(|| denied(ProviderErrorKind::UnsupportedVersionAssurance))?;
        Self::check_generation(record, expected_generation)?;
        self.check_current(record, request.reference)?;
        record.versions.remove(version);
        if record.active.as_ref() == Some(version) {
            record.active = None;
        }
        if record.latest.as_ref() == Some(version) {
            record.latest = record
                .versions
                .iter()
                .max_by_key(|(_, v)| v.issued_order)
                .map(|(id, _)| id.clone());
        }
        record.generation = generation;
        if record.versions.is_empty() {
            state.records.remove(request.reference.logical_key());
        }
        state.total_versions -= 1;
        state.next_generation = generation;
        Ok(SoftwareLifecycleEvidence {
            action: SoftwareLifecycleAction::Purge,
            scope: request.scope.clone(),
            logical_key: request.reference.logical_key().clone(),
            previous: Some(request.reference.clone()),
            current: None,
            from: Some(prior_status),
            to: None,
            generation,
            correlation: None,
        })
    }

    pub(super) async fn purge_exact(
        &self,
        policy: &dyn SoftwareLifecycleGate,
        request: SoftwarePurgeRequest<'_>,
    ) -> Result<(), ProviderError> {
        self.purge_with_evidence(policy, request).await.map(|_| ())
    }
}
