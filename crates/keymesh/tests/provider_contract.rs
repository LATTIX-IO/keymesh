//! KM-05 fake-provider integration harness. No cryptography or network calls.
use keymesh::{
    AlgorithmProfile, CapabilityEntry, CorrelationId, CryptoOperation, DigestAlgorithm,
    DispatchTarget, ExportRequirement, Exportability, HostScope, HostValidatedCapabilities,
    KeyProvider, KeyRef, KeySelector, LogicalKeyId, OperationCompletion, OperationInput,
    OperationIntent, OperationRequest, OperationState, PayloadDescriptor, PolicyContext,
    PolicyGate, PolicyVerdict, PreparedDispatch, ProtectionClass, ProtectionRequirement,
    ProviderCapabilities, ProviderError, ProviderErrorKind, ProviderFuture, ProviderInstanceId,
    ProviderNamespace, ProviderOutput, ProviderReply, ProviderResourceId, ProviderVersionId,
    RequiredAssurance, ResolvedKey, RetryDisposition, SupportStatus, VersionModel,
    VersionRequirement, CAPABILITY_SCHEMA_VERSION, execute_checked,
};
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll, Wake, Waker};

struct NoopWake;
impl Wake for NoopWake {
    fn wake(self: Arc<Self>) {}
}
fn block_on<F: Future>(future: F) -> F::Output {
    let waker = Waker::from(Arc::new(NoopWake));
    let mut cx = Context::from_waker(&waker);
    let mut future = Box::pin(future);
    loop {
        if let Poll::Ready(output) = future.as_mut().poll(&mut cx) {
            return output;
        }
        std::thread::yield_now();
    }
}
fn instance(s: &str) -> ProviderInstanceId {
    ProviderInstanceId::parse(s).unwrap_or_else(|e| panic!("{e}"))
}
fn namespace(s: &str) -> ProviderNamespace {
    ProviderNamespace::parse(s).unwrap_or_else(|e| panic!("{e}"))
}
fn logical(s: &str) -> LogicalKeyId {
    LogicalKeyId::parse(s).unwrap_or_else(|e| panic!("{e}"))
}
fn resource(s: &str) -> ProviderResourceId {
    ProviderResourceId::parse(s).unwrap_or_else(|e| panic!("{e}"))
}
fn version(s: &str) -> ProviderVersionId {
    ProviderVersionId::parse(s).unwrap_or_else(|e| panic!("{e}"))
}
fn correlation(s: &str) -> CorrelationId {
    CorrelationId::parse(s).unwrap_or_else(|e| panic!("{e}"))
}
#[derive(Clone, Copy)]
enum Scenario {
    Success,
    UnknownCommit,
    ConfirmedRejection,
    WrongTarget,
    WrongOutput,
    PendingAfterDispatch,
}
#[derive(Clone)]
struct SpyProvider {
    id: ProviderInstanceId,
    catalog: ProviderCapabilities,
    resolved: ResolvedKey,
    scenario: Scenario,
    reads: Arc<AtomicUsize>,
    dispatches: Arc<AtomicUsize>,
}
impl KeyProvider for SpyProvider {
    fn instance(&self) -> &ProviderInstanceId { &self.id }
    fn capabilities<'a>(
        &'a self,
        _scope: &'a HostScope,
    ) -> ProviderFuture<'a, ProviderCapabilities> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move { Ok(self.catalog.clone()) })
    }
    fn resolve<'a>(
        &'a self,
        _scope: &'a HostScope,
        _reference: &'a KeyRef,
    ) -> ProviderFuture<'a, ResolvedKey> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move { Ok(self.resolved.clone()) })
    }
    fn sign<'a>(
        &'a self,
        req: &'a PreparedDispatch<'_>,
        input: &'a OperationInput<'_>,
    ) -> ProviderFuture<'a, ProviderReply> {
        self.dispatches.fetch_add(1, Ordering::SeqCst);
        // This spy never hashes or signs; it only confirms request classification.
        let valid_form = matches!(input, OperationInput::Digest {
            algorithm: DigestAlgorithm::Sha256, bytes, authenticator: None
        } if bytes.len() == 32);
        if !valid_form {
            return Box::pin(async {
                Err(ProviderError::not_dispatched(ProviderErrorKind::InvalidInput))
            });
        }
        if req.feature_revision() != "fixture.r1" {
            return Box::pin(async { Err(ProviderError::unknown_commit_state()) });
        }
        let mut target = req.target().clone();
        let scenario = self.scenario;
        if matches!(scenario, Scenario::WrongTarget) {
            target = DispatchTarget::StableResource(resource("software:other-key:9"));
        }
        let reply = ProviderReply::new(
            target,
            if matches!(scenario, Scenario::WrongOutput) {
                ProviderOutput::Verification(true)
            } else {
                ProviderOutput::Signature(vec![0xAA, 0xBB, 0xCC])
            },
            Some(req.correlation().clone()),
        );
        Box::pin(async move {
            match scenario {
                Scenario::Success | Scenario::WrongTarget | Scenario::WrongOutput => Ok(reply),
                Scenario::UnknownCommit => Err(ProviderError::unknown_commit_state()),
                Scenario::ConfirmedRejection => Err(ProviderError::confirmed_failure(
                    ProviderErrorKind::ProviderRejected,
                )),
                Scenario::PendingAfterDispatch => {
                    std::future::pending::<Result<ProviderReply, ProviderError>>().await
                }
            }
        })
    }
}
#[derive(Clone, Copy)]
enum GateMode { Permit, Deny, Indeterminate, Error }
struct FakeGate {
    mode: GateMode,
    calls: AtomicUsize,
}
impl PolicyGate for FakeGate {
    fn evaluate<'a>(&'a self, context: &'a PolicyContext<'_>)
        -> ProviderFuture<'a, PolicyVerdict>
    {
        self.calls.fetch_add(1, Ordering::SeqCst);
        assert_eq!(context.scope.provider(), context.reference.provider());
        assert_eq!(context.catalog.provider_instance, context.scope.provider().as_str());
        let mode = self.mode;
        Box::pin(async move {
            match mode {
                GateMode::Permit => Ok(PolicyVerdict::Permit),
                GateMode::Deny => Ok(PolicyVerdict::Deny),
                GateMode::Indeterminate => Ok(PolicyVerdict::Indeterminate),
                GateMode::Error => Err(ProviderError::not_dispatched(
                    ProviderErrorKind::Unavailable,
                )),
            }
        })
    }
}
struct Fixture {
    provider: SpyProvider,
    policy: FakeGate,
    scope: HostScope,
    reference: KeyRef,
    trusted: HostValidatedCapabilities,
    intent: OperationIntent,
    corr: CorrelationId,
    message: Vec<u8>,
}
impl Fixture {
    fn new() -> Self {
        let id = instance("mock-hsm");
        let ns = namespace("tenant-a");
        let key = logical("payments");
        let native = resource("mock:payments:42");
        let revision = version("v7");
        let profile = AlgorithmProfile::RsaPss {
            modulus_bits: 3072, digest: DigestAlgorithm::Sha256,
            mgf1_digest: DigestAlgorithm::Sha256, salt_bytes: 32,
        };
        let operation = CryptoOperation::SignDigest { digest: DigestAlgorithm::Sha256 };
        let scope = HostScope::new(id.clone(), ns.clone());
        let catalog = ProviderCapabilities {
            schema_version: CAPABILITY_SCHEMA_VERSION,
            provider_instance: "mock-hsm".into(),
            namespace: "tenant-a".into(),
            protocol_revision: "mock.readonly.v1".into(),
            feature_revision: "fixture.r1".into(),
            reported_protection: ProtectionClass::Hsm,
            reported_version_model: VersionModel::ProviderVersion,
            reported_exportability: Exportability::None,
            attestation_claims: Vec::new(),
            entries: vec![CapabilityEntry {
                operation: operation.clone(),
                profile: profile.clone(),
                support: SupportStatus::Supported,
                max_input_bytes: Some(32),
            }],
        };
        let reference = KeyRef::new(
            id.clone(), ns.clone(), key.clone(),
            KeySelector::ExactProviderVersion {
                resource: native.clone(), version: revision.clone(),
            },
        );
        let resolved = ResolvedKey::new(
            id.clone(), ns.clone(), key,
            DispatchTarget::ProviderVersion {
                resource: native, version: revision,
            },
        );
        Self {
            provider: SpyProvider {
                id, catalog, resolved, scenario: Scenario::Success,
                reads: Arc::new(AtomicUsize::new(0)),
                dispatches: Arc::new(AtomicUsize::new(0)),
            },
            policy: FakeGate { mode: GateMode::Permit, calls: AtomicUsize::new(0) },
            scope: scope.clone(),
            reference,
            trusted: HostValidatedCapabilities {
                scope: Some(scope),
                protection: Some(ProtectionClass::Hsm),
                version_model: Some(VersionModel::ProviderVersion),
                permit_extensions: false,
                permit_private_export: false,
            },
            intent: OperationIntent {
                operation,
                profile,
                payload: PayloadDescriptor::Digest {
                    algorithm: DigestAlgorithm::Sha256, bytes: 32,
                },
                binding: VersionRequirement::ProviderVersion,
                protection: ProtectionRequirement::Hsm,
                export: ExportRequirement::None,
            },
            corr: correlation("trace-704"),
            message: vec![0xA5; 32],
        }
    }
    fn run(&self) -> Result<OperationCompletion, ProviderError> {
        self.run_with(OperationInput::Digest {
            algorithm: DigestAlgorithm::Sha256,
            bytes: &self.message, authenticator: None,
        })
    }
    fn run_with(&self, input: OperationInput<'_>)
        -> Result<OperationCompletion, ProviderError>
    {
        block_on(execute_checked(
            &self.provider, &self.policy,
            OperationRequest {
                scope: &self.scope,
                reference: &self.reference,
                host_assurance: &self.trusted,
                intent: &self.intent,
                input,
                correlation: &self.corr,
            },
        ))
    }
    fn dispatched(&self) -> usize {
        self.provider.dispatches.load(Ordering::SeqCst)
    }
    fn queried(&self) -> usize {
        self.provider.reads.load(Ordering::SeqCst)
    }
}
fn assert_pre_dispatch(error: Result<OperationCompletion, ProviderError>, kind: ProviderErrorKind) {
    match error {
        Err(e) => {
            assert_eq!(e.kind(), kind);
            assert_eq!(e.state(), OperationState::NotDispatched);
        }
        Ok(_) => panic!("unexpected successful dispatch"),
    }
}

#[test]
fn validated_digest_dispatch_reports_exact_scope_key_version_and_confirmation() {
    let t = Fixture::new();
    let completion = t.run().unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(t.queried(), 2);
    assert_eq!(t.dispatched(), 1);
    assert_eq!(t.policy.calls.load(Ordering::SeqCst), 1);
    assert_eq!(completion.evidence.provider, instance("mock-hsm"));
    assert_eq!(completion.evidence.namespace, namespace("tenant-a"));
    assert_eq!(completion.evidence.logical_key, logical("payments"));
    assert_eq!(completion.evidence.target.provider_version(), Some(&version("v7")));
    assert_eq!(completion.evidence.assurance, keymesh::BindingAssurance::ProviderVersionBound);
    assert_eq!(completion.evidence.outcome, OperationState::ConfirmedSuccess);
    assert_eq!(completion.evidence.correlation.as_str(), "trace-704");
    assert!(matches!(completion.output, ProviderOutput::Signature(_)));
}
#[test]
fn mismatched_tenant_or_provider_is_rejected_before_any_provider_query() {
    let mut t = Fixture::new();
    t.scope = HostScope::new(instance("mock-hsm"), namespace("tenant-b"));
    assert_pre_dispatch(t.run(), ProviderErrorKind::ScopeMismatch);
    assert_eq!(t.queried(), 0);
    assert_eq!(t.dispatched(), 0);
    let mut t = Fixture::new();
    t.provider.id = instance("other-hsm");
    assert_pre_dispatch(t.run(), ProviderErrorKind::ScopeMismatch);
    assert_eq!(t.queried(), 0);
}
#[test]
fn payload_mismatch_and_digest_length_fail_before_query_or_dispatch() {
    let t = Fixture::new();
    assert_pre_dispatch(
        t.run_with(OperationInput::Message { bytes: &t.message, authenticator: None }),
        ProviderErrorKind::InvalidInput,
    );
    assert_pre_dispatch(
        t.run_with(OperationInput::Digest {
            algorithm: DigestAlgorithm::Sha256, bytes: &t.message[0..31], authenticator: None,
        }),
        ProviderErrorKind::InvalidInput,
    );
    assert_pre_dispatch(
        t.run_with(OperationInput::Digest {
            algorithm: DigestAlgorithm::Sha3_256, bytes: &t.message, authenticator: None,
        }),
        ProviderErrorKind::InvalidInput,
    );
    assert_eq!(t.queried(), 0);
    assert_eq!(t.dispatched(), 0);
}
#[test]
fn verified_hsm_protection_is_not_replaced_by_provider_claim() {
    let mut t = Fixture::new();
    t.trusted.protection = None;
    assert_pre_dispatch(t.run(), ProviderErrorKind::UnverifiedCapability);
    assert_eq!(t.dispatched(), 0);
    let mut t = Fixture::new();
    t.provider.catalog.reported_protection = ProtectionClass::Software;
    assert_pre_dispatch(t.run(), ProviderErrorKind::UnverifiedCapability);
    assert_eq!(t.dispatched(), 0);
}
#[test]
fn unknown_capability_or_version_is_not_dispatched() {
    let mut t = Fixture::new();
    t.provider.catalog.entries[0].support = SupportStatus::Unknown;
    t.provider.catalog.entries[0].max_input_bytes = None;
    assert_pre_dispatch(t.run(), ProviderErrorKind::UnsupportedOperationOrProfile);
    assert_eq!(t.dispatched(), 0);
    let mut t = Fixture::new();
    t.trusted.version_model = Some(VersionModel::StableResource);
    assert_pre_dispatch(t.run(), ProviderErrorKind::UnsupportedVersionAssurance);
    assert_eq!(t.dispatched(), 0);
}
#[test]
fn catalog_provider_or_namespace_swap_is_not_dispatched() {
    let mut t = Fixture::new();
    t.provider.catalog.provider_instance = "other-hsm".into();
    assert_pre_dispatch(t.run(), ProviderErrorKind::ScopeMismatch);
    assert_eq!(t.dispatched(), 0);
    let mut t = Fixture::new();
    t.provider.catalog.namespace = "tenant-b".into();
    assert_pre_dispatch(t.run(), ProviderErrorKind::ScopeMismatch);
    assert_eq!(t.dispatched(), 0);
}
#[test]
fn stale_exact_version_or_rebound_resource_is_not_dispatched() {
    let mut t = Fixture::new();
    t.provider.resolved = ResolvedKey::new(
        instance("mock-hsm"), namespace("tenant-a"), logical("payments"),
        DispatchTarget::ProviderVersion {
            resource: resource("mock:payments:42"), version: version("v6"),
        },
    );
    assert_pre_dispatch(t.run(), ProviderErrorKind::UnsupportedVersionAssurance);
    assert_eq!(t.dispatched(), 0);
    let mut t = Fixture::new();
    t.provider.resolved = ResolvedKey::new(
        instance("mock-hsm"), namespace("tenant-a"), logical("payments"),
        DispatchTarget::ProviderVersion {
            resource: resource("mock:wrong:42"), version: version("v7"),
        },
    );
    assert_pre_dispatch(t.run(), ProviderErrorKind::ScopeMismatch);
    assert_eq!(t.dispatched(), 0);
}
#[test]
fn denied_indeterminate_or_failed_mandatory_policy_never_dispatches() {
    for mode in [GateMode::Deny, GateMode::Indeterminate, GateMode::Error] {
        let mut t = Fixture::new();
        t.policy.mode = mode;
        let wanted = if matches!(mode, GateMode::Deny) {
            ProviderErrorKind::PolicyDenied
        } else {
            ProviderErrorKind::PolicyIndeterminate
        };
        assert_pre_dispatch(t.run(), wanted);
        assert_eq!(t.dispatched(), 0);
        assert_eq!(t.policy.calls.load(Ordering::SeqCst), 1);
    }
}
#[test]
fn unknown_commit_requires_reconciliation_even_for_timeout_or_lost_ack() {
    let mut t = Fixture::new();
    t.provider.scenario = Scenario::UnknownCommit;
    match t.run() {
        Err(e) => {
            assert_eq!(e.state(), OperationState::UnknownCommitState);
            assert_eq!(e.retry(), RetryDisposition::ReconcileBeforeRetry);
            assert_eq!(e.kind(), ProviderErrorKind::UnknownCommitState);
        }
        Ok(_) => panic!("provider claimed success after lost acknowledgement"),
    }
    assert_eq!(t.dispatched(), 1);
}
#[test]
fn provider_confirmed_failure_does_not_auto_retry() {
    let mut t = Fixture::new();
    t.provider.scenario = Scenario::ConfirmedRejection;
    match t.run() {
        Err(e) => {
            assert_eq!(e.state(), OperationState::ConfirmedFailure);
            assert_eq!(e.retry(), RetryDisposition::DoNotAutoRetry);
        }
        Ok(_) => panic!("expected authoritative rejection"),
    }
    assert_eq!(t.dispatched(), 1);
}
#[test]
fn substituted_target_or_wrong_response_kind_after_dispatch_is_unknown_commit() {
    for scenario in [Scenario::WrongTarget, Scenario::WrongOutput] {
        let mut t = Fixture::new();
        t.provider.scenario = scenario;
        match t.run() {
            Err(e) => assert_eq!(e.state(), OperationState::UnknownCommitState),
            Ok(_) => panic!("mismatched provider evidence accepted"),
        }
        assert_eq!(t.dispatched(), 1);
    }
}
#[test]
fn future_dropped_before_first_poll_cannot_dispatch() {
    let t = Fixture::new();
    let future = execute_checked(
        &t.provider, &t.policy,
        OperationRequest {
            scope: &t.scope, reference: &t.reference, host_assurance: &t.trusted,
            intent: &t.intent,
            input: OperationInput::Digest {
                algorithm: DigestAlgorithm::Sha256, bytes: &t.message, authenticator: None,
            },
            correlation: &t.corr,
        },
    );
    drop(future);
    assert_eq!(t.dispatched(), 0);
    assert_eq!(t.queried(), 0);
}
#[test]
fn dropping_pending_future_after_dispatch_does_not_confirm_cancellation() {
    let mut t = Fixture::new();
    t.provider.scenario = Scenario::PendingAfterDispatch;
    let future = execute_checked(
        &t.provider, &t.policy,
        OperationRequest {
            scope: &t.scope, reference: &t.reference, host_assurance: &t.trusted,
            intent: &t.intent,
            input: OperationInput::Digest {
                algorithm: DigestAlgorithm::Sha256, bytes: &t.message, authenticator: None,
            },
            correlation: &t.corr,
        },
    );
    let mut future = Box::pin(future);
    let waker = Waker::from(Arc::new(NoopWake));
    let mut cx = Context::from_waker(&waker);
    assert!(matches!(Pin::as_mut(&mut future).poll(&mut cx), Poll::Pending));
    assert_eq!(t.dispatched(), 1);
    drop(future);
    // No success, failure or rollback is inferred from a local dropped future.
    assert_eq!(t.dispatched(), 1);
}
#[test]
fn simultaneous_requests_keep_scope_and_evidence_isolated() {
    let sample = Fixture::new();
    let mut handles = Vec::new();
    for _ in 0..32 {
        let p = sample.provider.clone();
        handles.push(std::thread::spawn(move || {
            let mut fixture = Fixture::new();
            fixture.provider = p;
            let evidence = fixture.run().unwrap_or_else(|e| panic!("{e}")).evidence;
            assert_eq!(evidence.namespace, namespace("tenant-a"));
            assert_eq!(evidence.outcome, OperationState::ConfirmedSuccess);
        }));
    }
    for handle in handles {
        handle.join().unwrap_or_else(|_| panic!("thread failed"));
    }
    assert_eq!(sample.dispatched(), 32);
}
#[test]
fn serialized_errors_outputs_and_correlation_are_redacted() {
    let correlation = correlation("PRIVATEKEY123");
    assert!(!format!("{correlation:?}").contains("PRIVATEKEY123"));
    assert!(!format!("{:?}", ProviderOutput::Signature(b"SECRET-PAYLOAD".to_vec()))
        .contains("SECRET-PAYLOAD"));
    let e = ProviderError::unknown_commit_state();
    assert!(!format!("{e:?} {e}").contains("SECRET-PAYLOAD"));
    let outcome = Fixture::new().run().unwrap_or_else(|e| panic!("{e}"));
    assert!(!format!("{outcome:?}").contains("mock:payments:42"));
}
#[test]
fn unsupported_optional_provider_method_is_not_implicitly_fallbacked() {
    let mut t = Fixture::new();
    let op = CryptoOperation::VerifyDigest { digest: DigestAlgorithm::Sha256 };
    t.intent.operation = op.clone();
    t.provider.catalog.entries[0].operation = op;
    let signed = [0x05u8; 64];
    let result = t.run_with(OperationInput::Digest {
        algorithm: DigestAlgorithm::Sha256, bytes: &t.message,
        authenticator: Some(&signed),
    });
    assert_pre_dispatch(result, ProviderErrorKind::UnsupportedOperationOrProfile);
    assert_eq!(t.dispatched(), 0);
}
#[test]
fn malformed_digest_proof_and_forbidden_signature_on_signing_are_rejected() {
    let t = Fixture::new();
    let data = [1u8; 4];
    assert_pre_dispatch(t.run_with(OperationInput::Digest {
        algorithm: DigestAlgorithm::Sha256, bytes: &t.message,
        authenticator: Some(&data),
    }), ProviderErrorKind::InvalidInput);
    assert_eq!(t.queried(), 0);
}
