//! FOSS-407 multi-provider routing, downgrade and removal regression harness.
//! Fake providers perform no cryptography, network access or IAM checks.

use keymesh::{
    AlgorithmProfile, CAPABILITY_SCHEMA_VERSION, CapabilityEntry, CorrelationId, CryptoOperation,
    DigestAlgorithm, DispatchTarget, ExportRequirement, Exportability, HostScope,
    HostValidatedCapabilities, KeyProvider, KeyRef, KeySelector, LogicalKeyId, OperationInput,
    OperationIntent, OperationRequest, PayloadDescriptor, PolicyContext, PolicyGate, PolicyVerdict,
    PreparedDispatch, ProtectionClass, ProtectionRequirement, ProviderCapabilities, ProviderError,
    ProviderErrorKind, ProviderFuture, ProviderHealth, ProviderInstanceId, ProviderNamespace,
    ProviderOutput, ProviderRegistry, ProviderReply, ProviderRequirements, ProviderResourceId,
    ProviderSelection, ProviderVersionId, RegistrationError, RejectionReason, ResolvedKey,
    RouteError, SupportStatus, VersionModel, VersionRequirement,
};
use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

fn instance(s: &str) -> ProviderInstanceId {
    ProviderInstanceId::parse(s).unwrap_or_else(|e| panic!("{e}"))
}
fn namespace(s: &str) -> ProviderNamespace {
    ProviderNamespace::parse(s).unwrap_or_else(|e| panic!("{e}"))
}
fn resource(s: &str) -> ProviderResourceId {
    ProviderResourceId::parse(s).unwrap_or_else(|e| panic!("{e}"))
}
fn target() -> DispatchTarget {
    DispatchTarget::ProviderVersion {
        resource: resource("mock:payments:42"),
        version: ProviderVersionId::parse("v7").unwrap_or_else(|e| panic!("{e}")),
    }
}
fn profile() -> AlgorithmProfile {
    AlgorithmProfile::RsaPss {
        modulus_bits: 3072,
        digest: DigestAlgorithm::Sha256,
        mgf1_digest: DigestAlgorithm::Sha256,
        salt_bytes: 32,
    }
}
fn operation() -> CryptoOperation {
    CryptoOperation::SignDigest {
        digest: DigestAlgorithm::Sha256,
    }
}
fn intent() -> OperationIntent {
    OperationIntent {
        operation: operation(),
        profile: profile(),
        payload: PayloadDescriptor::Digest {
            algorithm: DigestAlgorithm::Sha256,
            bytes: 32,
        },
        binding: VersionRequirement::ProviderVersion,
        protection: ProtectionRequirement::Hsm,
        export: ExportRequirement::None,
    }
}
fn scope(provider: &str, tenant: &str) -> HostScope {
    HostScope::new(instance(provider), namespace(tenant))
}
fn host(s: &HostScope, protection: ProtectionClass) -> HostValidatedCapabilities {
    HostValidatedCapabilities {
        scope: Some(s.clone()),
        protection: Some(protection),
        version_model: Some(VersionModel::ProviderVersion),
        permit_extensions: false,
        permit_private_export: false,
    }
}
fn drive<F: Future>(f: F) -> F::Output {
    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);
    let mut f = Box::pin(f);
    loop {
        if let Poll::Ready(v) = f.as_mut().poll(&mut cx) {
            return v;
        }
        std::thread::yield_now();
    }
}
struct Fake {
    provider: ProviderInstanceId,
    tenant: ProviderNamespace,
    catalog: Mutex<ProviderCapabilities>,
    reads: AtomicUsize,
    crypto_calls: AtomicUsize,
    hold_read: Arc<AtomicBool>,
}
impl Fake {
    fn new(provider: &str, tenant: &str, protection: ProtectionClass) -> Arc<Self> {
        Arc::new(Self {
            provider: instance(provider),
            tenant: namespace(tenant),
            catalog: Mutex::new(ProviderCapabilities {
                schema_version: CAPABILITY_SCHEMA_VERSION,
                provider_instance: provider.into(),
                namespace: tenant.into(),
                protocol_revision: "fixture.protocol.v1".into(),
                feature_revision: "fixture.features.v1".into(),
                reported_protection: protection,
                reported_version_model: VersionModel::ProviderVersion,
                reported_exportability: Exportability::None,
                attestation_claims: Vec::new(),
                entries: vec![CapabilityEntry {
                    operation: operation(),
                    profile: profile(),
                    support: SupportStatus::Supported,
                    max_input_bytes: Some(32),
                }],
            }),
            reads: AtomicUsize::new(0),
            crypto_calls: AtomicUsize::new(0),
            hold_read: Arc::new(AtomicBool::new(false)),
        })
    }
    fn change(&self, update: impl FnOnce(&mut ProviderCapabilities)) {
        let mut caps = self.catalog.lock().unwrap_or_else(|e| panic!("{e}"));
        update(&mut caps);
    }
}
impl KeyProvider for Fake {
    fn instance(&self) -> &ProviderInstanceId {
        &self.provider
    }
    fn capabilities<'a>(
        &'a self,
        _scope: &'a HostScope,
    ) -> ProviderFuture<'a, ProviderCapabilities> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        let release = self.hold_read.clone();
        Box::pin(async move {
            poll_fn(|_| {
                if release.load(Ordering::Acquire) {
                    Poll::Pending
                } else {
                    Poll::Ready(())
                }
            })
            .await;
            let catalog = self
                .catalog
                .lock()
                .map_err(|_| ProviderError::not_dispatched(ProviderErrorKind::Unavailable))?;
            Ok(catalog.clone())
        })
    }
    fn resolve<'a>(
        &'a self,
        _scope: &'a HostScope,
        _reference: &'a KeyRef,
    ) -> ProviderFuture<'a, ResolvedKey> {
        Box::pin(async move {
            Ok(ResolvedKey::new(
                self.provider.clone(),
                self.tenant.clone(),
                LogicalKeyId::parse("payments").unwrap_or_else(|e| panic!("{e}")),
                target(),
            ))
        })
    }
    fn sign<'a>(
        &'a self,
        request: &'a PreparedDispatch<'_>,
        _input: &'a OperationInput<'_>,
    ) -> ProviderFuture<'a, ProviderReply> {
        self.crypto_calls.fetch_add(1, Ordering::SeqCst);
        let reply = ProviderReply::new(
            request.target().clone(),
            ProviderOutput::Signature(vec![0xAA, 0xBB]),
            None,
        );
        Box::pin(async move { Ok(reply) })
    }
}
struct Policy {
    pending: Arc<AtomicBool>,
}
impl PolicyGate for Policy {
    fn evaluate<'a>(&'a self, _ctx: &'a PolicyContext<'_>) -> ProviderFuture<'a, PolicyVerdict> {
        let gate = self.pending.clone();
        Box::pin(async move {
            poll_fn(|_| {
                if gate.load(Ordering::Acquire) {
                    Poll::Pending
                } else {
                    Poll::Ready(())
                }
            })
            .await;
            Ok(PolicyVerdict::Permit)
        })
    }
}
fn allow() -> Policy {
    Policy {
        pending: Arc::new(AtomicBool::new(false)),
    }
}
fn register(
    reg: &ProviderRegistry,
    provider: &Arc<Fake>,
    tenant: &str,
    host_protection: ProtectionClass,
    health: ProviderHealth,
) {
    let s = HostScope::new(provider.provider.clone(), namespace(tenant));
    reg.register(
        provider.clone(),
        s.clone(),
        host(&s, host_protection),
        health,
    )
    .unwrap_or_else(|e| panic!("{e}"));
}
fn run_selected(
    routed: &keymesh::RoutedProvider,
    p: &Fake,
    tenant: &str,
    policy: &Policy,
) -> Result<keymesh::OperationCompletion, ProviderError> {
    let s = scope(p.provider.as_str(), tenant);
    let h = host(&s, ProtectionClass::Hsm);
    let intent = intent();
    let reference = KeyRef::new(
        p.provider.clone(),
        s.namespace().clone(),
        LogicalKeyId::parse("payments").unwrap_or_else(|e| panic!("{e}")),
        KeySelector::ExactProviderVersion {
            resource: resource("mock:payments:42"),
            version: ProviderVersionId::parse("v7").unwrap_or_else(|e| panic!("{e}")),
        },
    );
    let correlation = CorrelationId::parse("foss407-test").unwrap_or_else(|e| panic!("{e}"));
    let digest = [0x13; 32];
    drive(routed.execute(
        policy,
        OperationRequest {
            scope: &s,
            reference: &reference,
            host_assurance: &h,
            intent: &intent,
            input: OperationInput::Digest {
                algorithm: DigestAlgorithm::Sha256,
                bytes: &digest,
                authenticator: None,
            },
            correlation: &correlation,
        },
    ))
}
#[test]
fn explicit_provider_selects_exact_scoped_identity_without_crypto_dispatch() {
    let registry = ProviderRegistry::new();
    let a = Fake::new("a-hsm", "tenant-a", ProtectionClass::Hsm);
    let b = Fake::new("b-hsm", "tenant-a", ProtectionClass::Hsm);
    register(
        &registry,
        &a,
        "tenant-a",
        ProtectionClass::Hsm,
        ProviderHealth::Healthy,
    );
    register(
        &registry,
        &b,
        "tenant-a",
        ProtectionClass::Hsm,
        ProviderHealth::Healthy,
    );
    let scopes = [scope("a-hsm", "tenant-a"), scope("b-hsm", "tenant-a")];
    let wanted = ProviderSelection::Instance(instance("b-hsm"));
    let i = intent();
    let route = drive(registry.route(ProviderRequirements {
        authorized_scopes: &scopes,
        intent: &i,
        selection: &wanted,
    }))
    .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(route.instance(), &instance("b-hsm"));
    assert_eq!(route.namespace(), &namespace("tenant-a"));
    assert_eq!(route.trace().examined, 1);
    assert_eq!(a.crypto_calls.load(Ordering::SeqCst), 0);
    assert_eq!(b.crypto_calls.load(Ordering::SeqCst), 0);
}
#[test]
fn opt_in_multi_provider_tie_break_is_order_independent() {
    for reverse in [true, false] {
        let registry = ProviderRegistry::new();
        let a = Fake::new("a-hsm", "tenant-a", ProtectionClass::Hsm);
        let z = Fake::new("z-hsm", "tenant-a", ProtectionClass::Hsm);
        if reverse {
            register(
                &registry,
                &z,
                "tenant-a",
                ProtectionClass::Hsm,
                ProviderHealth::Healthy,
            );
            register(
                &registry,
                &a,
                "tenant-a",
                ProtectionClass::Hsm,
                ProviderHealth::Healthy,
            );
        } else {
            register(
                &registry,
                &a,
                "tenant-a",
                ProtectionClass::Hsm,
                ProviderHealth::Healthy,
            );
            register(
                &registry,
                &z,
                "tenant-a",
                ProtectionClass::Hsm,
                ProviderHealth::Healthy,
            );
        }
        let scopes = [scope("z-hsm", "tenant-a"), scope("a-hsm", "tenant-a")];
        let selection = ProviderSelection::AnyCompatible;
        let i = intent();
        let route = drive(registry.route(ProviderRequirements {
            authorized_scopes: &scopes,
            intent: &i,
            selection: &selection,
        }))
        .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(route.instance(), &instance("a-hsm"));
        assert_eq!(a.crypto_calls.load(Ordering::SeqCst), 0);
        assert_eq!(z.crypto_calls.load(Ordering::SeqCst), 0);
    }
}
#[test]
fn unknown_health_and_unavailable_explicit_instance_never_fall_back() {
    let registry = ProviderRegistry::new();
    let a = Fake::new("a-hsm", "tenant-a", ProtectionClass::Hsm);
    let b = Fake::new("b-hsm", "tenant-a", ProtectionClass::Hsm);
    register(
        &registry,
        &a,
        "tenant-a",
        ProtectionClass::Hsm,
        ProviderHealth::Unknown,
    );
    register(
        &registry,
        &b,
        "tenant-a",
        ProtectionClass::Hsm,
        ProviderHealth::Healthy,
    );
    let scopes = [scope("a-hsm", "tenant-a"), scope("b-hsm", "tenant-a")];
    let selected = ProviderSelection::Instance(instance("a-hsm"));
    let i = intent();
    let outcome = drive(registry.route(ProviderRequirements {
        authorized_scopes: &scopes,
        intent: &i,
        selection: &selected,
    }));
    assert!(matches!(outcome, Err(RouteError::NoCompatibleProvider)));
    assert_eq!(b.reads.load(Ordering::SeqCst), 0);
    registry
        .set_health(&scopes[0], ProviderHealth::Unavailable)
        .unwrap_or_else(|e| panic!("{e}"));
    assert!(matches!(
        drive(registry.route(ProviderRequirements {
            authorized_scopes: &scopes,
            intent: &i,
            selection: &selected,
        })),
        Err(RouteError::NoCompatibleProvider)
    ));
    let any = ProviderSelection::AnyCompatible;
    let routed = drive(registry.route(ProviderRequirements {
        authorized_scopes: &scopes,
        intent: &i,
        selection: &any,
    }))
    .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(routed.instance(), &instance("b-hsm"));
    assert_eq!(routed.trace().count(RejectionReason::NotHealthy), 1);
}
#[test]
fn hsm_requirements_never_downgrade_to_software_tee_or_unverified_hsm() {
    let registry = ProviderRegistry::new();
    let soft = Fake::new("a-software", "tenant-a", ProtectionClass::Software);
    let tee = Fake::new("b-tee", "tenant-a", ProtectionClass::Tee);
    let alleged = Fake::new("c-fake-hsm", "tenant-a", ProtectionClass::Hsm);
    register(
        &registry,
        &soft,
        "tenant-a",
        ProtectionClass::Software,
        ProviderHealth::Healthy,
    );
    register(
        &registry,
        &tee,
        "tenant-a",
        ProtectionClass::Tee,
        ProviderHealth::Healthy,
    );
    register(
        &registry,
        &alleged,
        "tenant-a",
        ProtectionClass::Software,
        ProviderHealth::Healthy,
    );
    let scopes = [
        scope("a-software", "tenant-a"),
        scope("b-tee", "tenant-a"),
        scope("c-fake-hsm", "tenant-a"),
    ];
    let select = ProviderSelection::AnyCompatible;
    let i = intent();
    let result = drive(registry.route(ProviderRequirements {
        authorized_scopes: &scopes,
        intent: &i,
        selection: &select,
    }));
    assert!(matches!(result, Err(RouteError::NoCompatibleProvider)));
    assert_eq!(soft.crypto_calls.load(Ordering::SeqCst), 0);
    assert_eq!(tee.crypto_calls.load(Ordering::SeqCst), 0);
    assert_eq!(alleged.crypto_calls.load(Ordering::SeqCst), 0);
}
#[test]
fn unknown_capabilities_and_variant_mismatch_never_authorize_routing() {
    let registry = ProviderRegistry::new();
    let fake = Fake::new("mock-hsm", "tenant-a", ProtectionClass::Hsm);
    register(
        &registry,
        &fake,
        "tenant-a",
        ProtectionClass::Hsm,
        ProviderHealth::Healthy,
    );
    let scopes = [scope("mock-hsm", "tenant-a")];
    let s = ProviderSelection::AnyCompatible;
    let i = intent();
    fake.change(|c| {
        c.entries[0].support = SupportStatus::Unknown;
        c.entries[0].max_input_bytes = None;
    });
    assert!(matches!(
        drive(registry.route(ProviderRequirements {
            authorized_scopes: &scopes,
            intent: &i,
            selection: &s,
        })),
        Err(RouteError::NoCompatibleProvider)
    ));
    fake.change(|c| {
        c.entries[0].support = SupportStatus::Supported;
        c.entries[0].max_input_bytes = Some(32);
        c.entries[0].profile = AlgorithmProfile::MlKem {
            variant: keymesh::MlKemVariant::MlKem1024,
        };
        c.entries[0].operation = CryptoOperation::Encapsulate;
    });
    assert!(matches!(
        drive(registry.route(ProviderRequirements {
            authorized_scopes: &scopes,
            intent: &i,
            selection: &s,
        })),
        Err(RouteError::NoCompatibleProvider)
    ));
    assert_eq!(fake.crypto_calls.load(Ordering::SeqCst), 0);
}
#[test]
fn registration_rejects_duplicate_instance_and_any_unauthorized_scope() {
    let registry = ProviderRegistry::new();
    let p = Fake::new("mock-hsm", "tenant-a", ProtectionClass::Hsm);
    register(
        &registry,
        &p,
        "tenant-a",
        ProtectionClass::Hsm,
        ProviderHealth::Healthy,
    );
    let s = scope("mock-hsm", "tenant-a");
    assert_eq!(
        registry.register(
            p.clone(),
            s.clone(),
            host(&s, ProtectionClass::Hsm),
            ProviderHealth::Healthy
        ),
        Err(RegistrationError::DuplicateInstance),
    );
    let wrong = scope("other-hsm", "tenant-a");
    assert_eq!(
        registry.register(
            p.clone(),
            wrong.clone(),
            host(&wrong, ProtectionClass::Hsm),
            ProviderHealth::Healthy
        ),
        Err(RegistrationError::ScopeMismatch),
    );
    let wrong_tenant = scope("mock-hsm", "tenant-b");
    assert_eq!(
        registry.register(
            p.clone(),
            wrong_tenant.clone(),
            host(&wrong_tenant, ProtectionClass::Hsm),
            ProviderHealth::Healthy
        ),
        Err(RegistrationError::DuplicateInstance),
    );
    assert_eq!(
        registry.unregister(&wrong_tenant),
        Err(RegistrationError::ScopeMismatch)
    );
}
#[test]
fn unauthorized_or_mixed_tenant_allowed_scope_list_is_rejected() {
    let registry = ProviderRegistry::new();
    let p = Fake::new("mock-hsm", "tenant-a", ProtectionClass::Hsm);
    register(
        &registry,
        &p,
        "tenant-a",
        ProtectionClass::Hsm,
        ProviderHealth::Healthy,
    );
    let selector = ProviderSelection::AnyCompatible;
    let i = intent();
    let mixed = [scope("mock-hsm", "tenant-a"), scope("another", "tenant-b")];
    assert!(matches!(
        drive(registry.route(ProviderRequirements {
            authorized_scopes: &mixed,
            intent: &i,
            selection: &selector,
        })),
        Err(RouteError::InvalidRequirements)
    ));
    assert!(matches!(
        drive(registry.route(ProviderRequirements {
            authorized_scopes: &[],
            intent: &i,
            selection: &selector,
        })),
        Err(RouteError::InvalidRequirements)
    ));
    let unauthorized = [scope("other-hsm", "tenant-a")];
    assert!(matches!(
        drive(registry.route(ProviderRequirements {
            authorized_scopes: &unauthorized,
            intent: &i,
            selection: &selector,
        })),
        Err(RouteError::NoCompatibleProvider)
    ));
    assert_eq!(p.crypto_calls.load(Ordering::SeqCst), 0);
}
#[test]
fn deregister_while_capabilities_read_pending_cannot_return_stale_route() {
    let registry = ProviderRegistry::new();
    let p = Fake::new("mock-hsm", "tenant-a", ProtectionClass::Hsm);
    register(
        &registry,
        &p,
        "tenant-a",
        ProtectionClass::Hsm,
        ProviderHealth::Healthy,
    );
    p.hold_read.store(true, Ordering::Release);
    let s = scope("mock-hsm", "tenant-a");
    let allowed = [s.clone()];
    let selector = ProviderSelection::Instance(instance("mock-hsm"));
    let i = intent();
    let future = registry.route(ProviderRequirements {
        authorized_scopes: &allowed,
        intent: &i,
        selection: &selector,
    });
    let mut future = Box::pin(future);
    let mut context = Context::from_waker(Waker::noop());
    assert!(matches!(
        Pin::as_mut(&mut future).poll(&mut context),
        Poll::Pending
    ));
    assert_eq!(p.reads.load(Ordering::SeqCst), 1);
    registry.unregister(&s).unwrap_or_else(|e| panic!("{e}"));
    p.hold_read.store(false, Ordering::Release);
    assert!(matches!(
        Pin::as_mut(&mut future).poll(&mut context),
        Poll::Ready(Err(RouteError::NoCompatibleProvider))
    ));
    assert_eq!(p.crypto_calls.load(Ordering::SeqCst), 0);
}
#[test]
fn old_lease_is_invalid_after_unregister_and_same_name_reregistration() {
    let registry = ProviderRegistry::new();
    let p = Fake::new("mock-hsm", "tenant-a", ProtectionClass::Hsm);
    register(
        &registry,
        &p,
        "tenant-a",
        ProtectionClass::Hsm,
        ProviderHealth::Healthy,
    );
    let s = scope("mock-hsm", "tenant-a");
    let allowed = [s.clone()];
    let selector = ProviderSelection::Instance(instance("mock-hsm"));
    let i = intent();
    let old = drive(registry.route(ProviderRequirements {
        authorized_scopes: &allowed,
        intent: &i,
        selection: &selector,
    }))
    .unwrap_or_else(|e| panic!("{e}"));
    registry.unregister(&s).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(old.ensure_live(), Err(RouteError::StaleRegistration));
    let replacement = Fake::new("mock-hsm", "tenant-a", ProtectionClass::Hsm);
    register(
        &registry,
        &replacement,
        "tenant-a",
        ProtectionClass::Hsm,
        ProviderHealth::Healthy,
    );
    assert_eq!(old.ensure_live(), Err(RouteError::StaleRegistration));
    let new = drive(registry.route(ProviderRequirements {
        authorized_scopes: &allowed,
        intent: &i,
        selection: &selector,
    }))
    .unwrap_or_else(|e| panic!("{e}"));
    assert!(new.ensure_live().is_ok());
    assert_eq!(p.crypto_calls.load(Ordering::SeqCst), 0);
}
#[test]
fn selected_route_uses_mandatory_policy_and_exact_foss404_dispatch_contract() {
    let registry = ProviderRegistry::new();
    let p = Fake::new("mock-hsm", "tenant-a", ProtectionClass::Hsm);
    register(
        &registry,
        &p,
        "tenant-a",
        ProtectionClass::Hsm,
        ProviderHealth::Healthy,
    );
    let scopes = [scope("mock-hsm", "tenant-a")];
    let selection = ProviderSelection::Instance(instance("mock-hsm"));
    let i = intent();
    let selected = drive(registry.route(ProviderRequirements {
        authorized_scopes: &scopes,
        intent: &i,
        selection: &selection,
    }))
    .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(p.crypto_calls.load(Ordering::SeqCst), 0);
    let result =
        run_selected(&selected, &p, "tenant-a", &allow()).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(result.evidence.provider, instance("mock-hsm"));
    assert_eq!(p.crypto_calls.load(Ordering::SeqCst), 1);
}
#[test]
fn revoked_during_async_mandatory_policy_cannot_reach_crypto_dispatch() {
    let registry = ProviderRegistry::new();
    let p = Fake::new("mock-hsm", "tenant-a", ProtectionClass::Hsm);
    register(
        &registry,
        &p,
        "tenant-a",
        ProtectionClass::Hsm,
        ProviderHealth::Healthy,
    );
    let s = scope("mock-hsm", "tenant-a");
    let scopes = [s.clone()];
    let selection = ProviderSelection::AnyCompatible;
    let i = intent();
    let route = drive(registry.route(ProviderRequirements {
        authorized_scopes: &scopes,
        intent: &i,
        selection: &selection,
    }))
    .unwrap_or_else(|e| panic!("{e}"));
    let gate = Policy {
        pending: Arc::new(AtomicBool::new(true)),
    };
    let host = host(&s, ProtectionClass::Hsm);
    let reference = KeyRef::new(
        instance("mock-hsm"),
        namespace("tenant-a"),
        LogicalKeyId::parse("payments").unwrap_or_else(|e| panic!("{e}")),
        KeySelector::ExactProviderVersion {
            resource: resource("mock:payments:42"),
            version: ProviderVersionId::parse("v7").unwrap_or_else(|e| panic!("{e}")),
        },
    );
    let correlation = CorrelationId::parse("routing-revoked").unwrap_or_else(|e| panic!("{e}"));
    let digest = [1u8; 32];
    let future = route.execute(
        &gate,
        OperationRequest {
            scope: &s,
            reference: &reference,
            host_assurance: &host,
            intent: &i,
            input: OperationInput::Digest {
                algorithm: DigestAlgorithm::Sha256,
                bytes: &digest,
                authenticator: None,
            },
            correlation: &correlation,
        },
    );
    let mut future = Box::pin(future);
    let mut context = Context::from_waker(Waker::noop());
    assert!(matches!(future.as_mut().poll(&mut context), Poll::Pending));
    registry.unregister(&s).unwrap_or_else(|e| panic!("{e}"));
    gate.pending.store(false, Ordering::Release);
    match future.as_mut().poll(&mut context) {
        Poll::Ready(Err(err)) => assert_eq!(err.kind(), ProviderErrorKind::PolicyIndeterminate),
        _ => panic!("revoked routing lease reached dispatch or remained unresolved"),
    }
    assert_eq!(p.crypto_calls.load(Ordering::SeqCst), 0);
}
#[test]
fn routing_debug_and_failure_messages_do_not_emit_registered_provider_names() {
    let registry = ProviderRegistry::new();
    let p = Fake::new("sensitive-provider", "tenant-secret", ProtectionClass::Hsm);
    register(
        &registry,
        &p,
        "tenant-secret",
        ProtectionClass::Hsm,
        ProviderHealth::Healthy,
    );
    let allowed = [scope("sensitive-provider", "tenant-secret")];
    let selector = ProviderSelection::AnyCompatible;
    let i = intent();
    let routed = drive(registry.route(ProviderRequirements {
        authorized_scopes: &allowed,
        intent: &i,
        selection: &selector,
    }))
    .unwrap_or_else(|e| panic!("{e}"));
    for text in [
        format!("{registry:?}"),
        format!("{routed:?}"),
        format!("{}", RouteError::NoCompatibleProvider),
    ] {
        assert!(!text.contains("sensitive-provider"));
        assert!(!text.contains("tenant-secret"));
    }
}
