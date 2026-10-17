//! KM-08 real cryptographic integration, fail-closed security and lifecycle.
//! All provider secrets are ephemeral OS-RNG generated, never checked in.

use keymesh::{
    AlgorithmProfile, CorrelationId, CryptoOperation, EdDsaVariant, ExportRequirement, HostScope,
    HostValidatedCapabilities, KeyRef, KeySelector, LogicalKeyId, MAX_SOFTWARE_MESSAGE_BYTES,
    OperationCompletion, OperationInput, OperationIntent, OperationRequest, OperationState,
    PayloadDescriptor, PolicyContext, PolicyGate, PolicyVerdict, ProtectionClass,
    ProtectionRequirement, ProviderError, ProviderErrorKind, ProviderFuture, ProviderHealth,
    ProviderInstanceId, ProviderNamespace, ProviderOutput, ProviderRegistry, ProviderRequirements,
    ProviderSelection, RouteError, SoftwareCreateRequest, SoftwareLifecycleAction,
    SoftwareLifecycleContext, SoftwareLifecycleGate, SoftwareProvider, SoftwarePurgeRequest,
    VersionModel, VersionRequirement, execute_checked,
};
use std::future::Future;
use std::pin::Pin;
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use std::task::{Context, Poll, Waker};

fn id(v: &str) -> ProviderInstanceId {
    ProviderInstanceId::parse(v).unwrap_or_else(|e| panic!("{e}"))
}
fn ns(v: &str) -> ProviderNamespace {
    ProviderNamespace::parse(v).unwrap_or_else(|e| panic!("{e}"))
}
fn key(v: &str) -> LogicalKeyId {
    LogicalKeyId::parse(v).unwrap_or_else(|e| panic!("{e}"))
}
fn run<F: Future>(future: F) -> F::Output {
    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);
    let mut future = Box::pin(future);
    loop {
        if let Poll::Ready(value) = future.as_mut().poll(&mut cx) {
            return value;
        }
        std::thread::yield_now();
    }
}
struct Gate {
    verdict: PolicyVerdict,
    fail: bool,
    lifecycle_calls: AtomicUsize,
    operation_calls: AtomicUsize,
    pause_create: Arc<AtomicBool>,
    pause_operation: Arc<AtomicBool>,
}
impl Gate {
    fn permit() -> Self {
        Self {
            verdict: PolicyVerdict::Permit,
            fail: false,
            lifecycle_calls: AtomicUsize::new(0),
            operation_calls: AtomicUsize::new(0),
            pause_create: Arc::new(AtomicBool::new(false)),
            pause_operation: Arc::new(AtomicBool::new(false)),
        }
    }
}
impl SoftwareLifecycleGate for Gate {
    fn authorize<'a>(
        &'a self,
        context: &'a SoftwareLifecycleContext<'_>,
    ) -> ProviderFuture<'a, PolicyVerdict> {
        self.lifecycle_calls.fetch_add(1, Ordering::SeqCst);
        assert!(matches!(
            context.action,
            SoftwareLifecycleAction::Generate | SoftwareLifecycleAction::Purge
        ));
        let pause = Arc::clone(&self.pause_create);
        Box::pin(async move {
            std::future::poll_fn(|_| {
                if pause.load(Ordering::Acquire) {
                    Poll::Pending
                } else {
                    Poll::Ready(())
                }
            })
            .await;
            if self.fail {
                Err(ProviderError::not_dispatched(
                    ProviderErrorKind::Unavailable,
                ))
            } else {
                Ok(self.verdict)
            }
        })
    }
}
impl PolicyGate for Gate {
    fn evaluate<'a>(&'a self, _: &'a PolicyContext<'_>) -> ProviderFuture<'a, PolicyVerdict> {
        self.operation_calls.fetch_add(1, Ordering::SeqCst);
        let pause = Arc::clone(&self.pause_operation);
        Box::pin(async move {
            std::future::poll_fn(|_| {
                if pause.load(Ordering::Acquire) {
                    Poll::Pending
                } else {
                    Poll::Ready(())
                }
            })
            .await;
            if self.fail {
                Err(ProviderError::not_dispatched(
                    ProviderErrorKind::Unavailable,
                ))
            } else {
                Ok(self.verdict)
            }
        })
    }
}
struct Fixture {
    provider: Arc<SoftwareProvider>,
    scope: HostScope,
    host: HostValidatedCapabilities,
    policy: Gate,
    logical: LogicalKeyId,
}
impl Fixture {
    fn new() -> Self {
        let scope = HostScope::new(id("software-provider-a"), ns("tenant-a"));
        Self {
            provider: Arc::new(SoftwareProvider::new(
                scope.provider().clone(),
                scope.namespace().clone(),
            )),
            host: HostValidatedCapabilities {
                scope: Some(scope.clone()),
                protection: Some(ProtectionClass::Software),
                version_model: Some(VersionModel::ProviderVersion),
                permit_extensions: false,
                permit_private_export: false,
            },
            scope,
            policy: Gate::permit(),
            logical: key("payment-auth"),
        }
    }
    fn create_with(&self, gate: &Gate) -> Result<keymesh::CreatedSoftwareKey, ProviderError> {
        let intent = SoftwareProvider::create_intent();
        run(self.provider.create(
            gate,
            SoftwareCreateRequest {
                scope: &self.scope,
                host_assurance: &self.host,
                logical_key: &self.logical,
                intent: &intent,
            },
        ))
    }
    fn create(&self) -> keymesh::CreatedSoftwareKey {
        self.create_with(&self.policy)
            .unwrap_or_else(|e| panic!("{e}"))
    }
    fn execute(
        &self,
        reference: &KeyRef,
        gate: &Gate,
        intent: &OperationIntent,
        input: OperationInput<'_>,
    ) -> Result<OperationCompletion, ProviderError> {
        let corr = CorrelationId::parse("km08-test").unwrap_or_else(|e| panic!("{e}"));
        run(execute_checked(
            self.provider.as_ref(),
            gate,
            OperationRequest {
                scope: &self.scope,
                reference,
                host_assurance: &self.host,
                intent,
                input,
                correlation: &corr,
            },
        ))
    }
    fn purge(&self, reference: &KeyRef, gate: &Gate) -> Result<(), ProviderError> {
        run(self.provider.purge(
            gate,
            SoftwarePurgeRequest {
                scope: &self.scope,
                host_assurance: &self.host,
                reference,
            },
        ))
    }
}
fn ed_intent(op: CryptoOperation, msg_size: usize) -> OperationIntent {
    OperationIntent {
        operation: op,
        profile: AlgorithmProfile::EdDsa {
            variant: EdDsaVariant::Ed25519,
        },
        payload: PayloadDescriptor::Message {
            bytes: msg_size as u64,
        },
        binding: VersionRequirement::ProviderVersion,
        protection: ProtectionRequirement::Any,
        export: ExportRequirement::None,
    }
}
fn public_intent() -> OperationIntent {
    OperationIntent {
        operation: CryptoOperation::ExportPublic,
        profile: AlgorithmProfile::EdDsa {
            variant: EdDsaVariant::Ed25519,
        },
        payload: PayloadDescriptor::None,
        binding: VersionRequirement::ProviderVersion,
        protection: ProtectionRequirement::Any,
        export: ExportRequirement::Public,
    }
}
fn sign(f: &Fixture, reference: &KeyRef, message: &[u8]) -> Result<Vec<u8>, ProviderError> {
    match f
        .execute(
            reference,
            &f.policy,
            &ed_intent(CryptoOperation::SignMessage, message.len()),
            OperationInput::Message {
                bytes: message,
                authenticator: None,
            },
        )?
        .output
    {
        ProviderOutput::Signature(signature) => Ok(signature),
        _ => panic!("sign operation returned wrong output"),
    }
}
fn verify(
    f: &Fixture,
    reference: &KeyRef,
    message: &[u8],
    signature: &[u8],
) -> Result<bool, ProviderError> {
    match f
        .execute(
            reference,
            &f.policy,
            &ed_intent(CryptoOperation::VerifyMessage, message.len()),
            OperationInput::Message {
                bytes: message,
                authenticator: Some(signature),
            },
        )?
        .output
    {
        ProviderOutput::Verification(ok) => Ok(ok),
        _ => panic!("verify operation returned wrong output"),
    }
}
fn assert_predispatch(result: Result<impl Sized, ProviderError>, expected: ProviderErrorKind) {
    match result {
        Err(error) => {
            assert_eq!(error.kind(), expected);
            assert_eq!(error.state(), OperationState::NotDispatched);
        }
        Ok(_) => panic!("unexpected successful cryptographic operation"),
    }
}

#[test]
fn os_generated_key_real_ed25519_sign_verify_and_exact_public_export() {
    let f = Fixture::new();
    let created = f.create();
    let message = b"KM08 Ed25519 real signature";
    let signature = sign(&f, created.reference(), message).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(signature.len(), 64);
    assert!(verify(&f, created.reference(), message, &signature).unwrap_or_else(|e| panic!("{e}")));
    let public = f
        .execute(
            created.reference(),
            &f.policy,
            &public_intent(),
            OperationInput::None,
        )
        .unwrap_or_else(|e| panic!("{e}"));
    match public.output {
        ProviderOutput::PublicKey(bytes) => assert_eq!(bytes, created.public_key()),
        _ => panic!("public export used the wrong result kind"),
    }
    assert_eq!(public.evidence.provider, *f.scope.provider());
    assert_eq!(public.evidence.namespace, *f.scope.namespace());
    assert_eq!(public.evidence.outcome, OperationState::ConfirmedSuccess);
    assert_eq!(f.policy.lifecycle_calls.load(Ordering::SeqCst), 1);
    assert_eq!(f.policy.operation_calls.load(Ordering::SeqCst), 3);
    assert!(!format!("{created:?} {:?}", f.provider).contains("payment-auth"));
}

#[test]
fn empty_message_is_valid_pure_ed25519_not_prehash() {
    let f = Fixture::new();
    let created = f.create();
    let signature = sign(&f, created.reference(), b"").unwrap_or_else(|e| panic!("{e}"));
    assert!(verify(&f, created.reference(), b"", &signature).unwrap_or_else(|e| panic!("{e}")));
}

#[test]
fn changed_message_wrong_key_and_corrupted_proof_do_not_verify() {
    let f = Fixture::new();
    let created = f.create();
    let second_key_name = key("secondary");
    let second = {
        let intent = SoftwareProvider::create_intent();
        run(f.provider.create(
            &f.policy,
            SoftwareCreateRequest {
                scope: &f.scope,
                host_assurance: &f.host,
                logical_key: &second_key_name,
                intent: &intent,
            },
        ))
        .unwrap_or_else(|e| panic!("{e}"))
    };
    let sig = sign(&f, created.reference(), b"original").unwrap_or_else(|e| panic!("{e}"));
    assert!(!verify(&f, created.reference(), b"changed", &sig).unwrap_or_else(|e| panic!("{e}")));
    assert!(!verify(&f, second.reference(), b"original", &sig).unwrap_or_else(|e| panic!("{e}")));
    let mut corrupt = sig.clone();
    corrupt[0] ^= 0x80;
    assert!(
        !verify(&f, created.reference(), b"original", &corrupt).unwrap_or_else(|e| panic!("{e}"))
    );
    assert_predispatch(
        verify(&f, created.reference(), b"original", &sig[..63]),
        ProviderErrorKind::InvalidInput,
    );
}

#[test]
fn creation_requires_exact_host_assurance_and_policy_before_rng_or_key_store() {
    for mode in 0..4 {
        let mut f = Fixture::new();
        if mode == 0 {
            f.host.protection = Some(ProtectionClass::Hsm);
        } else if mode == 1 {
            f.host.scope = Some(HostScope::new(id("wrong"), ns("tenant-a")));
        } else if mode == 2 {
            f.host.version_model = None;
        }
        if mode == 3 {
            f.policy.verdict = PolicyVerdict::Deny;
        }
        let result = f.create_with(&f.policy);
        assert_predispatch(
            result,
            if mode == 3 {
                ProviderErrorKind::PolicyDenied
            } else {
                ProviderErrorKind::ScopeMismatch
            },
        );
        assert_eq!(
            f.policy.lifecycle_calls.load(Ordering::SeqCst),
            usize::from(mode == 3)
        );
    }
    let mut f = Fixture::new();
    f.policy.verdict = PolicyVerdict::Indeterminate;
    assert_predispatch(
        f.create_with(&f.policy),
        ProviderErrorKind::PolicyIndeterminate,
    );
    assert_eq!(f.policy.lifecycle_calls.load(Ordering::SeqCst), 1);
    let mut f = Fixture::new();
    f.policy.fail = true;
    assert_predispatch(
        f.create_with(&f.policy),
        ProviderErrorKind::PolicyIndeterminate,
    );
}

#[test]
fn creation_does_not_accept_other_algorithms_or_lifecycle_payloads() {
    let f = Fixture::new();
    for variant in [EdDsaVariant::Ed25519, EdDsaVariant::Ed448] {
        let mut intent = SoftwareProvider::create_intent();
        intent.profile = AlgorithmProfile::EdDsa { variant };
        if variant == EdDsaVariant::Ed25519 {
            intent.binding = VersionRequirement::StableResource;
        }
        assert_predispatch(
            run(f.provider.create(
                &f.policy,
                SoftwareCreateRequest {
                    scope: &f.scope,
                    host_assurance: &f.host,
                    logical_key: &f.logical,
                    intent: &intent,
                },
            )),
            ProviderErrorKind::UnsupportedOperationOrProfile,
        );
    }
    assert_eq!(f.policy.lifecycle_calls.load(Ordering::SeqCst), 0);
}

#[test]
fn duplicate_keys_and_invalid_native_selectors_fail_closed() {
    let f = Fixture::new();
    let _created = f.create();
    assert_predispatch(f.create_with(&f.policy), ProviderErrorKind::InvalidInput);
    let alias = KeyRef::new(
        f.scope.provider().clone(),
        f.scope.namespace().clone(),
        f.logical.clone(),
        KeySelector::Active,
    );
    assert_predispatch(
        sign(&f, &alias, b"message"),
        ProviderErrorKind::UnsupportedVersionAssurance,
    );
    assert_predispatch(
        f.purge(&alias, &f.policy),
        ProviderErrorKind::UnsupportedVersionAssurance,
    );
}

#[test]
fn wrong_provider_tenant_version_and_logical_key_never_sign() {
    let f = Fixture::new();
    let created = f.create();
    let original = created.reference();
    let (resource, version) = match original.selector() {
        KeySelector::ExactProviderVersion { resource, version } => (resource, version),
        _ => panic!("not exact"),
    };
    for index in 0..4 {
        let changed = KeyRef::new(
            if index == 0 {
                id("different")
            } else {
                original.provider().clone()
            },
            if index == 1 {
                ns("other-tenant")
            } else {
                original.namespace().clone()
            },
            if index == 2 {
                key("wrong-key")
            } else {
                original.logical_key().clone()
            },
            KeySelector::ExactProviderVersion {
                resource: resource.clone(),
                version: if index == 3 {
                    keymesh::ProviderVersionId::parse("wrong-v99").unwrap_or_else(|e| panic!("{e}"))
                } else {
                    version.clone()
                },
            },
        );
        assert!(sign(&f, &changed, b"msg").is_err());
    }
    assert_eq!(f.policy.operation_calls.load(Ordering::SeqCst), 0);
}

#[test]
fn neither_digest_signing_nor_other_algorithm_is_implicitly_mapped() {
    let f = Fixture::new();
    let created = f.create();
    let mut wrong = ed_intent(
        CryptoOperation::SignDigest {
            digest: keymesh::DigestAlgorithm::Sha256,
        },
        32,
    );
    wrong.payload = PayloadDescriptor::Digest {
        algorithm: keymesh::DigestAlgorithm::Sha256,
        bytes: 32,
    };
    let digest = [0x18_u8; 32];
    assert_predispatch(
        f.execute(
            created.reference(),
            &f.policy,
            &wrong,
            OperationInput::Digest {
                algorithm: keymesh::DigestAlgorithm::Sha256,
                bytes: &digest,
                authenticator: None,
            },
        ),
        ProviderErrorKind::InvalidInput,
    );
    for variant in [EdDsaVariant::Ed448] {
        let mut wrong = ed_intent(CryptoOperation::SignMessage, 3);
        wrong.profile = AlgorithmProfile::EdDsa { variant };
        assert_predispatch(
            f.execute(
                created.reference(),
                &f.policy,
                &wrong,
                OperationInput::Message {
                    bytes: b"msg",
                    authenticator: None,
                },
            ),
            ProviderErrorKind::UnsupportedOperationOrProfile,
        );
    }
}

#[test]
fn hsm_or_tee_requirement_never_routes_to_explicit_software_provider() {
    let f = Fixture::new();
    let created = f.create();
    let registry = ProviderRegistry::new();
    registry
        .register(
            f.provider.clone(),
            f.scope.clone(),
            f.host.clone(),
            ProviderHealth::Healthy,
        )
        .unwrap_or_else(|e| panic!("{e}"));
    let scopes = [f.scope.clone()];
    for protection in [ProtectionRequirement::Hsm, ProtectionRequirement::Tee] {
        let mut intent = ed_intent(CryptoOperation::SignMessage, 4);
        intent.protection = protection;
        assert!(matches!(
            run(registry.route(ProviderRequirements {
                authorized_scopes: &scopes,
                intent: &intent,
                selection: &ProviderSelection::AnyCompatible,
            })),
            Err(RouteError::NoCompatibleProvider)
        ));
        assert_predispatch(
            f.execute(
                created.reference(),
                &f.policy,
                &intent,
                OperationInput::Message {
                    bytes: b"data",
                    authenticator: None,
                },
            ),
            ProviderErrorKind::UnverifiedCapability,
        );
    }
    assert_eq!(f.policy.operation_calls.load(Ordering::SeqCst), 0);
    let intent = ed_intent(CryptoOperation::SignMessage, 4);
    let route = run(registry.route(ProviderRequirements {
        authorized_scopes: &scopes,
        intent: &intent,
        selection: &ProviderSelection::Instance(f.scope.provider().clone()),
    }))
    .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(route.instance(), f.scope.provider());
    assert!(sign(&f, created.reference(), b"data").is_ok());
}

#[test]
fn oversized_message_and_private_export_are_rejected() {
    let f = Fixture::new();
    let created = f.create();
    let bytes = vec![0x55; MAX_SOFTWARE_MESSAGE_BYTES as usize + 1];
    assert_predispatch(
        sign(&f, created.reference(), &bytes),
        ProviderErrorKind::InvalidInput,
    );
    let mut export = public_intent();
    export.operation = CryptoOperation::ExportPrivate;
    export.export = ExportRequirement::Private;
    assert_predispatch(
        f.execute(
            created.reference(),
            &f.policy,
            &export,
            OperationInput::None,
        ),
        ProviderErrorKind::AuthorizationDenied,
    );
}

#[test]
fn policy_denial_unknown_or_error_never_signs_or_exports() {
    let f = Fixture::new();
    let created = f.create();
    for mode in 0..3 {
        let mut gate = Gate::permit();
        if mode == 0 {
            gate.verdict = PolicyVerdict::Deny;
        }
        if mode == 1 {
            gate.verdict = PolicyVerdict::Indeterminate;
        }
        if mode == 2 {
            gate.fail = true;
        }
        let wanted = if mode == 0 {
            ProviderErrorKind::PolicyDenied
        } else {
            ProviderErrorKind::PolicyIndeterminate
        };
        assert_predispatch(
            f.execute(
                created.reference(),
                &gate,
                &ed_intent(CryptoOperation::SignMessage, 3),
                OperationInput::Message {
                    bytes: b"abc",
                    authenticator: None,
                },
            ),
            wanted,
        );
        assert_eq!(gate.operation_calls.load(Ordering::SeqCst), 1);
    }
}

#[test]
fn purged_version_fails_and_name_reuse_does_not_resurrect_old_target() {
    let f = Fixture::new();
    let old = f.create();
    let original = KeyRef::new(
        old.reference().provider().clone(),
        old.reference().namespace().clone(),
        old.reference().logical_key().clone(),
        old.reference().selector().clone(),
    );
    f.purge(&original, &f.policy)
        .unwrap_or_else(|e| panic!("{e}"));
    assert_predispatch(
        sign(&f, &original, b"never"),
        ProviderErrorKind::UnsupportedVersionAssurance,
    );
    let replacement = f.create();
    assert_ne!(replacement.reference().selector(), original.selector());
    assert_predispatch(
        sign(&f, &original, b"never"),
        ProviderErrorKind::UnsupportedVersionAssurance,
    );
    assert!(sign(&f, replacement.reference(), b"new").is_ok());
}

#[test]
fn deletion_during_async_policy_cannot_sign_replaced_or_purged_key() {
    let f = Fixture::new();
    let old = f.create();
    let intent = ed_intent(CryptoOperation::SignMessage, 3);
    let trace = CorrelationId::parse("policy-race").unwrap_or_else(|e| panic!("{e}"));
    let gate = Gate::permit();
    gate.pause_operation.store(true, Ordering::Release);
    let future = execute_checked(
        f.provider.as_ref(),
        &gate,
        OperationRequest {
            scope: &f.scope,
            reference: old.reference(),
            host_assurance: &f.host,
            intent: &intent,
            input: OperationInput::Message {
                bytes: b"abc",
                authenticator: None,
            },
            correlation: &trace,
        },
    );
    let mut future = Box::pin(future);
    let mut cx = Context::from_waker(Waker::noop());
    assert!(matches!(
        Pin::as_mut(&mut future).poll(&mut cx),
        Poll::Pending
    ));
    assert_eq!(gate.operation_calls.load(Ordering::SeqCst), 1);
    f.purge(old.reference(), &f.policy)
        .unwrap_or_else(|e| panic!("{e}"));
    let replacement = f.create();
    gate.pause_operation.store(false, Ordering::Release);
    match Pin::as_mut(&mut future).poll(&mut cx) {
        Poll::Ready(Err(err)) => {
            assert_eq!(err.kind(), ProviderErrorKind::UnsupportedVersionAssurance);
            assert_eq!(err.state(), OperationState::NotDispatched);
        }
        _ => panic!("stale concrete key was allowed to sign"),
    }
    assert!(sign(&f, replacement.reference(), b"abc").is_ok());
}

#[test]
fn cancelled_generation_before_or_while_policy_pending_never_creates() {
    let f = Fixture::new();
    let intent = SoftwareProvider::create_intent();
    let future = f.provider.create(
        &f.policy,
        SoftwareCreateRequest {
            scope: &f.scope,
            host_assurance: &f.host,
            logical_key: &f.logical,
            intent: &intent,
        },
    );
    drop(future);
    assert_eq!(f.policy.lifecycle_calls.load(Ordering::SeqCst), 0);
    f.policy.pause_create.store(true, Ordering::Release);
    let future = f.provider.create(
        &f.policy,
        SoftwareCreateRequest {
            scope: &f.scope,
            host_assurance: &f.host,
            logical_key: &f.logical,
            intent: &intent,
        },
    );
    let mut future = Box::pin(future);
    let mut cx = Context::from_waker(Waker::noop());
    assert!(matches!(future.as_mut().poll(&mut cx), Poll::Pending));
    drop(future);
    f.policy.pause_create.store(false, Ordering::Release);
    assert_eq!(f.policy.lifecycle_calls.load(Ordering::SeqCst), 1);
    assert!(f.create_with(&f.policy).is_ok());
}

#[test]
fn concurrent_same_name_generation_allows_only_one_stored_key() {
    let f = Arc::new(Fixture::new());
    let mut tasks = Vec::new();
    for _ in 0..8 {
        let f = Arc::clone(&f);
        tasks.push(std::thread::spawn(move || f.create_with(&f.policy).is_ok()));
    }
    let successes = tasks
        .into_iter()
        .map(|thread| thread.join().unwrap_or_else(|_| panic!("worker panicked")))
        .filter(|did_create| *did_create)
        .count();
    assert_eq!(successes, 1);
}
