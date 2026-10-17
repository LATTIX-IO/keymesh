//! FOSS-408 regression contract: no host-denied credential callback, no
//! cross-provider/tenant/operation credential reuse, no actual cloud/HSM calls.
use keymesh::{
    AlgorithmProfile, CredentialAuthorization, CredentialError, CredentialFuture,
    CredentialPurpose, CredentialRequest, CredentialSource, CryptoOperation, DigestAlgorithm,
    ExportRequirement, HostScope, OperationIntent, PayloadDescriptor, PolicyVerdict,
    ProtectionRequirement, ProviderInstanceId, ProviderNamespace, ScopedCredential, SecretBytes,
    VersionRequirement, acquire_scoped_credential,
};
use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::{Context, Poll, Waker};

fn instance(value: &str) -> ProviderInstanceId {
    ProviderInstanceId::parse(value).unwrap_or_else(|e| panic!("{e}"))
}
fn namespace(value: &str) -> ProviderNamespace {
    ProviderNamespace::parse(value).unwrap_or_else(|e| panic!("{e}"))
}
fn intent() -> OperationIntent {
    OperationIntent {
        operation: CryptoOperation::SignDigest {
            digest: DigestAlgorithm::Sha256,
        },
        profile: AlgorithmProfile::RsaPss {
            modulus_bits: 3072,
            digest: DigestAlgorithm::Sha256,
            mgf1_digest: DigestAlgorithm::Sha256,
            salt_bytes: 32,
        },
        payload: PayloadDescriptor::Digest {
            algorithm: DigestAlgorithm::Sha256,
            bytes: 32,
        },
        binding: VersionRequirement::ProviderVersion,
        protection: ProtectionRequirement::Hsm,
        export: ExportRequirement::None,
    }
}
fn drive<F: Future>(future: F) -> F::Output {
    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);
    let mut future = Box::pin(future);
    loop {
        if let Poll::Ready(result) = future.as_mut().poll(&mut cx) {
            return result;
        }
        std::thread::yield_now();
    }
}
#[derive(Clone, Copy)]
enum SourceBehavior {
    Correct,
    WrongTenant,
    WrongOperation,
    WrongPurpose,
    Erased,
    Unavailable,
}
struct FakeSource {
    provider: ProviderInstanceId,
    namespace: ProviderNamespace,
    calls: AtomicUsize,
    behavior: SourceBehavior,
}
impl FakeSource {
    fn new() -> Self {
        Self {
            provider: instance("mock-hsm"),
            namespace: namespace("tenant-a"),
            calls: AtomicUsize::new(0),
            behavior: SourceBehavior::Correct,
        }
    }
}
impl CredentialSource for FakeSource {
    fn provider(&self) -> &ProviderInstanceId {
        &self.provider
    }
    fn namespace(&self) -> &ProviderNamespace {
        &self.namespace
    }
    fn acquire<'a>(
        &'a self,
        request: &'a CredentialRequest<'_>,
    ) -> CredentialFuture<'a, ScopedCredential> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {
            if matches!(self.behavior, SourceBehavior::Unavailable) {
                return Err(CredentialError::Unavailable);
            }
            let scope = HostScope::new(
                self.provider.clone(),
                if matches!(self.behavior, SourceBehavior::WrongTenant) {
                    namespace("tenant-b")
                } else {
                    request.host_scope.namespace().clone()
                },
            );
            let operation = if matches!(self.behavior, SourceBehavior::WrongOperation) {
                CryptoOperation::Encrypt
            } else {
                request.operation.clone()
            };
            let purpose = if matches!(self.behavior, SourceBehavior::WrongPurpose) {
                CredentialPurpose::OperationAuthorization
            } else {
                request.purpose
            };
            let mut secret = SecretBytes::from_vec(b"fixture-credential-not-production".to_vec())
                .map_err(|_| CredentialError::InvalidMaterial)?;
            if matches!(self.behavior, SourceBehavior::Erased) {
                secret.erase();
            }
            Ok(ScopedCredential::new(scope, operation, purpose, secret))
        })
    }
}
struct FakeGate {
    calls: AtomicUsize,
    verdict: PolicyVerdict,
    fail: bool,
    blocked: Arc<AtomicBool>,
}
impl FakeGate {
    fn allow() -> Self {
        Self {
            calls: AtomicUsize::new(0),
            verdict: PolicyVerdict::Permit,
            fail: false,
            blocked: Arc::new(AtomicBool::new(false)),
        }
    }
}
impl CredentialAuthorization for FakeGate {
    fn authorize<'a>(
        &'a self,
        request: &'a CredentialRequest<'_>,
    ) -> CredentialFuture<'a, PolicyVerdict> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        assert_eq!(request.intent.operation, *request.operation);
        let blocked = self.blocked.clone();
        Box::pin(async move {
            poll_fn(|_| {
                if blocked.load(Ordering::Acquire) {
                    Poll::Pending
                } else {
                    Poll::Ready(())
                }
            })
            .await;
            if self.fail {
                Err(CredentialError::Unavailable)
            } else {
                Ok(self.verdict)
            }
        })
    }
}
struct Fixture {
    source: FakeSource,
    gate: FakeGate,
    scope: HostScope,
    target: ProviderInstanceId,
    tenant: ProviderNamespace,
    intent: OperationIntent,
    operation: CryptoOperation,
}
impl Fixture {
    fn new() -> Self {
        let provider = instance("mock-hsm");
        let tenant = namespace("tenant-a");
        let intent = intent();
        let operation = intent.operation.clone();
        Self {
            source: FakeSource::new(),
            gate: FakeGate::allow(),
            scope: HostScope::new(provider.clone(), tenant.clone()),
            target: provider,
            tenant,
            intent,
            operation,
        }
    }
    fn request(&self) -> CredentialRequest<'_> {
        CredentialRequest {
            host_scope: &self.scope,
            expected_provider: &self.target,
            expected_namespace: &self.tenant,
            intent: &self.intent,
            operation: &self.operation,
            purpose: CredentialPurpose::ProviderAuthentication,
        }
    }
    fn acquire(&self) -> Result<ScopedCredential, CredentialError> {
        drive(acquire_scoped_credential(
            &self.source,
            &self.gate,
            self.request(),
        ))
    }
    fn requested(&self) -> usize {
        self.source.calls.load(Ordering::SeqCst)
    }
}
#[test]
fn approved_scoped_secret_is_owned_redacted_and_cannot_be_implicitly_copied() {
    let fixture = Fixture::new();
    let credential = fixture.acquire().unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(credential.scope(), &fixture.scope);
    assert_eq!(credential.operation(), &fixture.operation);
    assert_eq!(
        credential.purpose(),
        CredentialPurpose::ProviderAuthentication
    );
    assert_eq!(credential.len(), b"fixture-credential-not-production".len());
    assert_eq!(fixture.gate.calls.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.requested(), 1);
    credential.with_exposed(|borrowed| {
        assert_eq!(borrowed, b"fixture-credential-not-production");
    });
    let rendered = format!("{credential:?} {:?}", CredentialError::Unavailable);
    assert!(!rendered.contains("fixture-credential-not-production"));
    assert!(!rendered.contains("mock-hsm"));
    assert!(!rendered.contains("tenant-a"));
}
#[test]
fn provider_and_tenant_mismatches_never_reach_policy_or_source() {
    for changed in 0..5 {
        let mut fixture = Fixture::new();
        match changed {
            0 => fixture.target = instance("another-hsm"),
            1 => fixture.tenant = namespace("tenant-b"),
            2 => fixture.scope = HostScope::new(instance("mock-hsm"), namespace("tenant-b")),
            3 => fixture.source.provider = instance("another-hsm"),
            4 => fixture.source.namespace = namespace("tenant-b"),
            _ => unreachable!(),
        }
        assert!(matches!(
            fixture.acquire(),
            Err(CredentialError::ScopeMismatch)
        ));
        assert_eq!(fixture.gate.calls.load(Ordering::SeqCst), 0);
        assert_eq!(fixture.requested(), 0);
    }
}
#[test]
fn operation_tampering_and_invalid_intent_never_trigger_credential_fetch() {
    let mut fixture = Fixture::new();
    fixture.operation = CryptoOperation::Encrypt;
    assert!(matches!(
        fixture.acquire(),
        Err(CredentialError::ScopeMismatch)
    ));
    assert_eq!(fixture.requested(), 0);
    assert_eq!(fixture.gate.calls.load(Ordering::SeqCst), 0);

    let mut fixture = Fixture::new();
    fixture.intent.payload = PayloadDescriptor::Digest {
        algorithm: DigestAlgorithm::Sha256,
        bytes: 31,
    };
    assert!(matches!(
        fixture.acquire(),
        Err(CredentialError::InvalidIntent)
    ));
    assert_eq!(fixture.gate.calls.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.requested(), 0);
}
#[test]
fn denied_unknown_or_failed_host_authorization_is_fail_closed() {
    for mode in 0..3 {
        let mut fixture = Fixture::new();
        match mode {
            0 => fixture.gate.verdict = PolicyVerdict::Deny,
            1 => fixture.gate.verdict = PolicyVerdict::Indeterminate,
            2 => fixture.gate.fail = true,
            _ => unreachable!(),
        }
        let wanted = if mode == 0 {
            CredentialError::PolicyDenied
        } else {
            CredentialError::PolicyIndeterminate
        };
        assert!(matches!(fixture.acquire(), Err(error) if error == wanted));
        assert_eq!(fixture.gate.calls.load(Ordering::SeqCst), 1);
        assert_eq!(fixture.requested(), 0);
    }
}
#[test]
fn mismatched_source_response_is_dropped_not_returned_as_credential() {
    for behavior in [
        SourceBehavior::WrongTenant,
        SourceBehavior::WrongOperation,
        SourceBehavior::WrongPurpose,
    ] {
        let mut fixture = Fixture::new();
        fixture.source.behavior = behavior;
        assert!(matches!(
            fixture.acquire(),
            Err(CredentialError::ScopeMismatch)
        ));
        assert_eq!(fixture.requested(), 1);
    }
    let mut fixture = Fixture::new();
    fixture.source.behavior = SourceBehavior::Erased;
    assert!(matches!(
        fixture.acquire(),
        Err(CredentialError::InvalidMaterial)
    ));
    assert_eq!(fixture.requested(), 1);
}
#[test]
fn unavailability_is_typed_and_does_not_trigger_fallback() {
    let mut fixture = Fixture::new();
    fixture.source.behavior = SourceBehavior::Unavailable;
    assert!(matches!(
        fixture.acquire(),
        Err(CredentialError::Unavailable)
    ));
    assert_eq!(fixture.requested(), 1);
    let formatted = format!(
        "{:?} {}",
        CredentialError::Unavailable,
        CredentialError::Unavailable
    );
    assert!(!formatted.contains("fixture-credential-not-production"));
}
#[test]
fn dropped_future_never_calls_credential_source_before_authorization_completes() {
    let fixture = Fixture::new();
    let future = acquire_scoped_credential(&fixture.source, &fixture.gate, fixture.request());
    drop(future);
    assert_eq!(fixture.requested(), 0);
    assert_eq!(fixture.gate.calls.load(Ordering::SeqCst), 0);

    fixture.gate.blocked.store(true, Ordering::Release);
    let future = acquire_scoped_credential(&fixture.source, &fixture.gate, fixture.request());
    let mut future = Box::pin(future);
    let mut cx = Context::from_waker(Waker::noop());
    assert!(matches!(
        Pin::as_mut(&mut future).poll(&mut cx),
        Poll::Pending
    ));
    assert_eq!(fixture.requested(), 0);
    drop(future);
    assert_eq!(fixture.requested(), 0);
}
#[test]
fn isolated_thread_requests_do_not_cross_tenant_scope() {
    let handles: Vec<_> = (0..20)
        .map(|_| {
            std::thread::spawn(|| {
                let fixture = Fixture::new();
                let mut credential = fixture.acquire().unwrap_or_else(|e| panic!("{e}"));
                assert_eq!(credential.scope(), &fixture.scope);
                credential.erase();
                assert!(credential.is_empty());
                assert_eq!(fixture.requested(), 1);
            })
        })
        .collect();
    for thread in handles {
        thread
            .join()
            .unwrap_or_else(|_| panic!("credential worker panicked"));
    }
}
