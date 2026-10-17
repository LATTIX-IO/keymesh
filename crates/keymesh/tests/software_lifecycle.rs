//! KM-09 version-safe logical key state machine and concurrent race tests.
//! All test seeds come from the OS CSPRNG; no production credentials are used.

use keymesh::{
    AlgorithmProfile, CorrelationId, CryptoOperation, EdDsaVariant, ExportRequirement,
    HostScope, HostValidatedCapabilities, KeyRef, KeySelector, LogicalKeyId,
    OperationInput, OperationIntent, OperationRequest, OperationState, PayloadDescriptor,
    PolicyContext, PolicyGate, PolicyVerdict, ProtectionClass, ProtectionRequirement,
    ProviderError, ProviderErrorKind, ProviderFuture, ProviderInstanceId, ProviderNamespace,
    ProviderOutput, SoftwareCreateRequest, SoftwareLifecycleAction, SoftwareLifecycleContext,
    SoftwareLifecycleGate, SoftwareLogicalSnapshot, SoftwareProvider, SoftwarePurgeRequest,
    SoftwareRotateRequest, SoftwareTransitionAction, SoftwareTransitionRequest,
    SoftwareVersionState, VersionModel, VersionRequirement, MAX_SOFTWARE_VERSIONS_PER_KEY,
    execute_checked,
};
use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::{Context, Poll, Waker};

fn drive<F: Future>(future: F) -> F::Output {
    let mut future = Box::pin(future);
    let mut ctx = Context::from_waker(Waker::noop());
    loop {
        if let Poll::Ready(value) = future.as_mut().poll(&mut ctx) {
            return value;
        }
        std::thread::yield_now();
    }
}
fn name(s: &str) -> LogicalKeyId {
    LogicalKeyId::parse(s).unwrap_or_else(|e| panic!("{e}"))
}
fn intent(op: CryptoOperation, bytes: usize) -> OperationIntent {
    OperationIntent {
        operation: op,
        profile: AlgorithmProfile::EdDsa { variant: EdDsaVariant::Ed25519 },
        payload: PayloadDescriptor::Message { bytes: bytes as u64 },
        binding: VersionRequirement::ProviderVersion,
        protection: ProtectionRequirement::Any,
        export: ExportRequirement::None,
    }
}
struct Gate {
    verdict: PolicyVerdict,
    fail: bool,
    pause: AtomicBool,
    lifecycle_calls: AtomicUsize,
    operation_calls: AtomicUsize,
}
impl Gate {
    fn permit() -> Self {
        Self {
            verdict: PolicyVerdict::Permit,
            fail: false,
            pause: AtomicBool::new(false),
            lifecycle_calls: AtomicUsize::new(0),
            operation_calls: AtomicUsize::new(0),
        }
    }
}
impl SoftwareLifecycleGate for Gate {
    fn authorize<'a>(
        &'a self, _: &'a SoftwareLifecycleContext<'_>,
    ) -> ProviderFuture<'a, PolicyVerdict> {
        self.lifecycle_calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {
            poll_fn(|_| {
                if self.pause.load(Ordering::Acquire) { Poll::Pending }
                else { Poll::Ready(()) }
            }).await;
            if self.fail {
                Err(ProviderError::not_dispatched(ProviderErrorKind::Unavailable))
            } else { Ok(self.verdict) }
        })
    }
}
impl PolicyGate for Gate {
    fn evaluate<'a>(&'a self, _: &'a PolicyContext<'_>)
        -> ProviderFuture<'a, PolicyVerdict> {
        self.operation_calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {
            poll_fn(|_| {
                if self.pause.load(Ordering::Acquire) { Poll::Pending }
                else { Poll::Ready(()) }
            }).await;
            if self.fail {
                Err(ProviderError::not_dispatched(ProviderErrorKind::Unavailable))
            } else { Ok(self.verdict) }
        })
    }
}
struct Fixture {
    provider: Arc<SoftwareProvider>,
    scope: HostScope,
    host: HostValidatedCapabilities,
    key: LogicalKeyId,
    permit: Gate,
}
impl Fixture {
    fn new() -> Self {
        let scope = HostScope::new(
            ProviderInstanceId::parse("lifecycle-provider").unwrap_or_else(|e| panic!("{e}")),
            ProviderNamespace::parse("tenant-a").unwrap_or_else(|e| panic!("{e}")),
        );
        Self {
            provider: Arc::new(SoftwareProvider::new(
                scope.provider().clone(), scope.namespace().clone(),
            )),
            host: HostValidatedCapabilities {
                scope: Some(scope.clone()), protection: Some(ProtectionClass::Software),
                version_model: Some(VersionModel::ProviderVersion), permit_extensions: false,
                permit_private_export: false,
            },
            scope,
            key: name("alpha"),
            permit: Gate::permit(),
        }
    }
    fn create(&self) -> keymesh::CreatedSoftwareKey {
        let exact = SoftwareProvider::create_intent();
        drive(self.provider.create(&self.permit, SoftwareCreateRequest {
            scope: &self.scope, host_assurance: &self.host,
            logical_key: &self.key, intent: &exact,
        })).unwrap_or_else(|e| panic!("{e}"))
    }
    fn snapshot(&self) -> SoftwareLogicalSnapshot {
        self.provider.snapshot(&self.scope, &self.host, &self.key)
            .unwrap_or_else(|e| panic!("{e}"))
    }
    fn rotate(&self, key: &KeyRef, generation: u64, gate: &Gate)
        -> Result<keymesh::SoftwareRotation, ProviderError>
    {
        let exact = SoftwareProvider::create_intent();
        let trace = CorrelationId::parse("km09-rotate").unwrap_or_else(|e| panic!("{e}"));
        drive(self.provider.rotate(gate, SoftwareRotateRequest {
            scope: &self.scope, host_assurance: &self.host,
            previous: key, expected_generation: generation,
            intent: &exact, correlation: Some(&trace),
        }))
    }
    fn transition(
        &self, key: &KeyRef, generation: u64,
        action: SoftwareTransitionAction, gate: &Gate,
    ) -> Result<keymesh::SoftwareLifecycleEvidence, ProviderError> {
        drive(self.provider.transition(gate, SoftwareTransitionRequest {
            scope: &self.scope, host_assurance: &self.host, reference: key,
            expected_generation: generation, action, correlation: None,
        }))
    }
    fn purge(&self, reference: &KeyRef)
        -> Result<keymesh::SoftwareLifecycleEvidence, ProviderError> {
        drive(self.provider.purge_with_evidence(&self.permit, SoftwarePurgeRequest {
            scope: &self.scope, host_assurance: &self.host, reference,
        }))
    }
    fn exec(&self, reference: &KeyRef, op: CryptoOperation, message: &[u8],
        signature: Option<&[u8]>, gate: &Gate,
    ) -> Result<keymesh::OperationCompletion, ProviderError> {
        let trace = CorrelationId::parse("km09-test").unwrap_or_else(|e| panic!("{e}"));
        let i = intent(op, message.len());
        drive(execute_checked(self.provider.as_ref(), gate, OperationRequest {
            scope: &self.scope, reference, host_assurance: &self.host,
            intent: &i, input: OperationInput::Message {
                bytes: message, authenticator: signature,
            }, correlation: &trace,
        }))
    }
    fn signature(&self, reference: &KeyRef, message: &[u8])
        -> Result<Vec<u8>, ProviderError> {
        match self.exec(reference, CryptoOperation::SignMessage, message, None, &self.permit)?.output {
            ProviderOutput::Signature(signature) => Ok(signature),
            _ => panic!("unexpected provider output"),
        }
    }
    fn verified(&self, reference: &KeyRef, message: &[u8], signature: &[u8])
        -> Result<bool, ProviderError> {
        match self.exec(reference, CryptoOperation::VerifyMessage, message, Some(signature), &self.permit)?.output {
            ProviderOutput::Verification(valid) => Ok(valid),
            _ => panic!("unexpected verification output"),
        }
    }
    fn alias(&self, selector: KeySelector) -> KeyRef {
        KeyRef::new(self.scope.provider().clone(), self.scope.namespace().clone(), self.key.clone(), selector)
    }
}
fn rejected<T>(result: Result<T, ProviderError>, kind: ProviderErrorKind) {
    match result {
        Err(error) => {
            assert_eq!(error.kind(), kind);
            assert_eq!(error.state(), OperationState::NotDispatched);
        }
        Ok(_) => panic!("unexpected accepted lifecycle or signature operation"),
    }
}

#[test]
fn rotation_changes_active_pointer_preserves_prior_verification_without_reusing_private_identity() {
    let f = Fixture::new();
    let old = f.create();
    let before = f.snapshot();
    assert_eq!(before.generation(), old.generation());
    assert_eq!(before.versions().len(), 1);
    let original_message = b"old signed audit event";
    let signed = f.signature(old.reference(), original_message)
        .unwrap_or_else(|e| panic!("{e}"));
    let receipt = f.rotate(old.reference(), before.generation(), &f.permit)
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(receipt.evidence().action(), SoftwareLifecycleAction::Rotate);
    assert_eq!(receipt.evidence().previous(), Some(old.reference()));
    assert_eq!(receipt.evidence().current(), Some(receipt.created().reference()));
    assert_eq!(receipt.evidence().generation(), receipt.created().generation());
    assert_eq!(receipt.evidence().correlation().map(|x| x.as_str()), Some("km09-rotate"));
    assert_ne!(receipt.created().reference().selector(), old.reference().selector());
    assert_ne!(receipt.created().public_key(), old.public_key());
    let after = f.snapshot();
    assert!(after.generation() > before.generation());
    assert_eq!(after.active(), Some(receipt.created().reference()));
    assert_eq!(after.latest(), Some(receipt.created().reference()));
    assert_eq!(after.versions().len(), 2);
    assert!(after.versions().iter().any(|v| v.reference() == old.reference()
        && v.status() == SoftwareVersionState::Retired));
    assert!(f.verified(old.reference(), original_message, &signed)
        .unwrap_or_else(|e| panic!("{e}")));
    rejected(f.signature(old.reference(), b"new unauthorized signature"),
        ProviderErrorKind::AuthorizationDenied);
    let fresh = f.signature(receipt.created().reference(), b"new signed event")
        .unwrap_or_else(|e| panic!("{e}"));
    assert!(f.verified(receipt.created().reference(), b"new signed event", &fresh)
        .unwrap_or_else(|e| panic!("{e}")));
}

#[test]
fn active_and_latest_resolve_to_pinned_target_not_mutable_dispatch_alias() {
    let f = Fixture::new();
    let old = f.create();
    let active = f.alias(KeySelector::Active);
    let latest = f.alias(KeySelector::Latest);
    assert!(f.signature(&active, b"before").is_ok());
    assert!(f.signature(&latest, b"before").is_ok());
    let rotated = f.rotate(old.reference(), f.snapshot().generation(), &f.permit)
        .unwrap_or_else(|e| panic!("{e}"));
    assert!(f.signature(&active, b"after").is_ok());
    assert!(f.signature(&latest, b"after").is_ok());
    assert_eq!(f.snapshot().active(), Some(rotated.created().reference()));
    rejected(f.signature(old.reference(), b"historical"), ProviderErrorKind::AuthorizationDenied);
}

#[test]
fn disable_enable_and_schedule_delete_enforce_exact_state_machine() {
    let f = Fixture::new();
    let key = f.create();
    let sig = f.signature(key.reference(), b"keep")
        .unwrap_or_else(|e| panic!("{e}"));
    let stopped = f.transition(key.reference(), f.snapshot().generation(),
        SoftwareTransitionAction::Disable, &f.permit)
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(stopped.from(), Some(SoftwareVersionState::Active));
    assert_eq!(stopped.to(), Some(SoftwareVersionState::Disabled));
    assert!(f.snapshot().active().is_none());
    rejected(f.signature(key.reference(), b"denied"), ProviderErrorKind::AuthorizationDenied);
    rejected(f.verified(key.reference(), b"keep", &sig), ProviderErrorKind::AuthorizationDenied);
    rejected(f.transition(key.reference(), stopped.generation(),
        SoftwareTransitionAction::Disable, &f.permit), ProviderErrorKind::AuthorizationDenied);
    let restored = f.transition(key.reference(), stopped.generation(),
        SoftwareTransitionAction::Enable, &f.permit)
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(restored.to(), Some(SoftwareVersionState::Active));
    assert!(f.verified(key.reference(), b"keep", &sig).unwrap_or_else(|e| panic!("{e}")));
    let disabled = f.transition(key.reference(), restored.generation(),
        SoftwareTransitionAction::Disable, &f.permit)
        .unwrap_or_else(|e| panic!("{e}"));
    let pending = f.transition(key.reference(), disabled.generation(),
        SoftwareTransitionAction::ScheduleDelete, &f.permit)
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(pending.to(), Some(SoftwareVersionState::PendingDeletion));
    rejected(f.transition(key.reference(), pending.generation(),
        SoftwareTransitionAction::Enable, &f.permit), ProviderErrorKind::AuthorizationDenied);
    let deleted = f.purge(key.reference()).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(deleted.action(), SoftwareLifecycleAction::Purge);
    assert_eq!(deleted.from(), Some(SoftwareVersionState::PendingDeletion));
    assert_eq!(deleted.to(), None);
    assert_eq!(deleted.current(), None);
    rejected(f.signature(key.reference(), b"purged"), ProviderErrorKind::UnsupportedVersionAssurance);
}

#[test]
fn generation_cas_prevents_mutation_after_other_policy_approved_state_change() {
    let f = Fixture::new();
    let original = f.create();
    let revision = f.snapshot().generation();
    let first = f.rotate(original.reference(), revision, &f.permit)
        .unwrap_or_else(|e| panic!("{e}"));
    rejected(f.rotate(original.reference(), revision, &f.permit),
        ProviderErrorKind::UnsupportedVersionAssurance);
    rejected(f.transition(first.created().reference(), revision,
        SoftwareTransitionAction::Disable, &f.permit),
        ProviderErrorKind::UnsupportedVersionAssurance);
    assert_eq!(f.snapshot().active(), Some(first.created().reference()));
}

#[test]
fn host_policy_denial_unknown_error_and_wrong_scope_are_mutation_free() {
    let f = Fixture::new();
    let old = f.create();
    let generation = f.snapshot().generation();
    for mode in 0..3 {
        let mut gate = Gate::permit();
        if mode == 0 { gate.verdict = PolicyVerdict::Deny; }
        if mode == 1 { gate.verdict = PolicyVerdict::Indeterminate; }
        if mode == 2 { gate.fail = true; }
        let kind = if mode == 0 { ProviderErrorKind::PolicyDenied }
            else { ProviderErrorKind::PolicyIndeterminate };
        rejected(f.rotate(old.reference(), generation, &gate), kind);
        rejected(f.transition(old.reference(), generation,
            SoftwareTransitionAction::Disable, &gate), kind);
        assert_eq!(gate.lifecycle_calls.load(Ordering::SeqCst), 2);
    }
    let wrong_scope = HostScope::new(f.scope.provider().clone(),
        ProviderNamespace::parse("tenant-other").unwrap_or_else(|e| panic!("{e}")));
    let create = SoftwareProvider::create_intent();
    rejected(drive(f.provider.rotate(&f.permit, SoftwareRotateRequest {
        scope: &wrong_scope, host_assurance: &f.host, previous: old.reference(),
        expected_generation: generation, intent: &create, correlation: None,
    })), ProviderErrorKind::ScopeMismatch);
    assert_eq!(f.snapshot().generation(), generation);
    assert_eq!(f.snapshot().versions().len(), 1);
}

#[test]
fn concurrent_cas_rotations_allow_only_one_fresh_active_version() {
    let f = Arc::new(Fixture::new());
    let old = f.create();
    let original = old.reference().clone();
    let generation = f.snapshot().generation();
    let workers: Vec<_> = (0..10).map(|_| {
        let f = Arc::clone(&f);
        let original = original.clone();
        std::thread::spawn(move || f.rotate(&original, generation, &f.permit).is_ok())
    }).collect();
    let successes = workers.into_iter().map(|w| w.join().unwrap_or_else(|_| panic!("worker panicked")))
        .filter(|committed| *committed).count();
    assert_eq!(successes, 1);
    let state = f.snapshot();
    assert_eq!(state.versions().len(), 2);
    assert_eq!(state.versions().iter().filter(|v| v.status() == SoftwareVersionState::Active).count(), 1);
}

#[test]
fn policy_pending_alias_resolution_does_not_follow_rotation_or_purge() {
    let f = Fixture::new();
    let old = f.create();
    let active = f.alias(KeySelector::Active);
    let gate = Gate::permit();
    gate.pause.store(true, Ordering::Release);
    let trace = CorrelationId::parse("km09-pinned-policy").unwrap_or_else(|e| panic!("{e}"));
    let intent = intent(CryptoOperation::SignMessage, 3);
    let mut pending = Box::pin(execute_checked(f.provider.as_ref(), &gate,
        OperationRequest {
            scope: &f.scope, reference: &active, host_assurance: &f.host,
            intent: &intent, input: OperationInput::Message {
                bytes: b"abc", authenticator: None,
            }, correlation: &trace,
        }));
    let mut cx = Context::from_waker(Waker::noop());
    assert!(matches!(Pin::as_mut(&mut pending).poll(&mut cx), Poll::Pending));
    assert_eq!(gate.operation_calls.load(Ordering::SeqCst), 1);
    let rotated = f.rotate(old.reference(), f.snapshot().generation(), &f.permit)
        .unwrap_or_else(|e| panic!("{e}"));
    gate.pause.store(false, Ordering::Release);
    match Pin::as_mut(&mut pending).poll(&mut cx) {
        Poll::Ready(Err(error)) => {
            assert_eq!(error.kind(), ProviderErrorKind::UnsupportedVersionAssurance);
            assert_eq!(error.state(), OperationState::NotDispatched);
        }
        _ => panic!("stale Active selection followed rotation during policy wait"),
    }
    assert!(f.signature(rotated.created().reference(), b"abc").is_ok());
}

#[test]
fn pending_rotate_fails_cas_after_concurrent_disable() {
    let f = Fixture::new();
    let old = f.create();
    let before = f.snapshot();
    let gate = Gate::permit();
    gate.pause.store(true, Ordering::Release);
    let generation = before.generation();
    let create = SoftwareProvider::create_intent();
    let mut pending = Box::pin(f.provider.rotate(&gate, SoftwareRotateRequest {
        scope: &f.scope, host_assurance: &f.host,
        previous: old.reference(), expected_generation: generation,
        intent: &create, correlation: None,
    }));
    let mut cx = Context::from_waker(Waker::noop());
    assert!(matches!(Pin::as_mut(&mut pending).poll(&mut cx), Poll::Pending));
    f.transition(old.reference(), generation,
        SoftwareTransitionAction::Disable, &f.permit).unwrap_or_else(|e| panic!("{e}"));
    gate.pause.store(false, Ordering::Release);
    rejected(match Pin::as_mut(&mut pending).poll(&mut cx) {
        Poll::Ready(result) => result,
        Poll::Pending => panic!("pending rotation did not settle"),
    }, ProviderErrorKind::UnsupportedVersionAssurance);
    assert!(f.snapshot().active().is_none());
    assert_eq!(f.snapshot().versions().len(), 1);
}

#[test]
fn invalid_reenable_of_retired_version_cannot_displace_new_active_version() {
    let f = Fixture::new();
    let old = f.create();
    let rotated = f.rotate(old.reference(), f.snapshot().generation(), &f.permit)
        .unwrap_or_else(|e| panic!("{e}"));
    let state = f.snapshot();
    rejected(f.transition(old.reference(), state.generation(),
        SoftwareTransitionAction::Enable, &f.permit), ProviderErrorKind::AuthorizationDenied);
    let disabled = f.transition(old.reference(), state.generation(),
        SoftwareTransitionAction::Disable, &f.permit)
        .unwrap_or_else(|e| panic!("{e}"));
    rejected(f.transition(old.reference(), disabled.generation(),
        SoftwareTransitionAction::Enable, &f.permit), ProviderErrorKind::AuthorizationDenied);
    assert_eq!(f.snapshot().active(), Some(rotated.created().reference()));
}

#[test]
fn historical_versions_are_bounded_and_released_only_after_exact_purge() {
    let f = Fixture::new();
    let initial = f.create();
    let mut previous = initial.reference().clone();
    for _ in 1..MAX_SOFTWARE_VERSIONS_PER_KEY {
        let next = f.rotate(&previous, f.snapshot().generation(), &f.permit)
            .unwrap_or_else(|e| panic!("{e}"));
        previous = next.created().reference().clone();
    }
    assert_eq!(f.snapshot().versions().len(), MAX_SOFTWARE_VERSIONS_PER_KEY);
    rejected(f.rotate(&previous, f.snapshot().generation(), &f.permit),
        ProviderErrorKind::InvalidInput);
    // Purging a retired version makes space without changing active target.
    f.purge(initial.reference()).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(f.snapshot().versions().len(), MAX_SOFTWARE_VERSIONS_PER_KEY - 1);
    let restored = f.rotate(&previous, f.snapshot().generation(), &f.permit)
        .unwrap_or_else(|e| panic!("{e}"));
    assert!(f.signature(restored.created().reference(), b"bounded").is_ok());
}

#[test]
fn old_exact_reference_remains_invalid_after_purge_and_recreation_and_generation_never_rewinds() {
    let f = Fixture::new();
    let first = f.create();
    let v1 = first.reference().clone();
    let start = first.generation();
    f.purge(&v1).unwrap_or_else(|e| panic!("{e}"));
    let second = f.create();
    assert!(second.generation() > start);
    assert_ne!(second.reference().selector(), v1.selector());
    rejected(f.signature(&v1, b"stale key"), ProviderErrorKind::UnsupportedVersionAssurance);
    assert!(f.signature(second.reference(), b"fresh").is_ok());
}

#[test]
fn snapshots_and_receipts_redact_structured_key_metadata_by_default() {
    let f = Fixture::new();
    let old = f.create();
    let snapshot = f.snapshot();
    let next = f.rotate(old.reference(), snapshot.generation(), &f.permit)
        .unwrap_or_else(|e| panic!("{e}"));
    let rendered = format!("{snapshot:?} {:?} {:?} {:?}",
        next.evidence(), next.created(), next);
    assert!(!rendered.contains("tenant-a"));
    assert!(!rendered.contains("lifecycle-provider"));
    assert!(!rendered.contains("alpha"));
    assert!(rendered.contains("<redacted>"));
    for version in f.snapshot().versions() {
        assert_eq!(format!("{version:?}"), "SoftwareVersionSnapshot(<redacted>)");
    }
}
