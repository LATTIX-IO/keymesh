//! KM-05 fake-provider end-to-end contract. No crypto, credentials, or network.
use keymesh::{
    AlgorithmProfile, CapabilityEntry, CorrelationId, CryptoOperation, DigestAlgorithm,
    DispatchTarget, ExportRequirement, Exportability, HostScope, HostValidatedCapabilities,
    KeyProvider, KeyRef, KeySelector, LogicalKeyId, OperationInput, OperationIntent,
    OperationRequest, PayloadDescriptor, PolicyContext, PolicyGate, PolicyVerdict,
    PreparedDispatch, ProtectionClass, ProtectionRequirement, ProviderCapabilities,
    ProviderError, ProviderFuture, ProviderInstanceId, ProviderNamespace, ProviderOutput,
    ProviderReply, ProviderResourceId, ProviderVersionId, ResolvedKey, SupportStatus,
    VersionModel, VersionRequirement, CAPABILITY_SCHEMA_VERSION, execute_checked,
};
use std::future::Future;
use std::sync::Arc;
use std::task::{Context, Poll, Wake, Waker};

struct NoopWake;
impl Wake for NoopWake { fn wake(self: Arc<Self>) {} }
fn drive<F: Future>(future: F) -> F::Output {
    let mut future = Box::pin(future);
    let waker = Waker::from(Arc::new(NoopWake));
    let mut context = Context::from_waker(&waker);
    loop {
        if let Poll::Ready(value) = future.as_mut().poll(&mut context) {
            return value;
        }
        std::thread::yield_now();
    }
}
struct Mock {
    provider: ProviderInstanceId,
    catalog: ProviderCapabilities,
    resolved: ResolvedKey,
}
impl KeyProvider for Mock {
    fn instance(&self) -> &ProviderInstanceId { &self.provider }
    fn capabilities<'a>(&'a self, _scope: &'a HostScope) -> ProviderFuture<'a, ProviderCapabilities> {
        Box::pin(async move { Ok(self.catalog.clone()) })
    }
    fn resolve<'a>(&'a self, _scope: &'a HostScope, _reference: &'a KeyRef)
        -> ProviderFuture<'a, ResolvedKey>
    {
        Box::pin(async move { Ok(self.resolved.clone()) })
    }
    fn sign<'a>(&'a self, prepared: &'a PreparedDispatch<'_>, _input: &'a OperationInput<'_>)
        -> ProviderFuture<'a, ProviderReply>
    {
        let reply = ProviderReply::new(
            prepared.target().clone(),
            ProviderOutput::Signature(vec![0xAA, 0xBB]),
            Some(prepared.correlation().clone()),
        );
        // Deterministic test response; NEVER a real cryptographic signature.
        Box::pin(async move { Ok(reply) })
    }
}
struct HostPolicy;
impl PolicyGate for HostPolicy {
    fn evaluate<'a>(&'a self, _ctx: &'a PolicyContext<'_>)
        -> ProviderFuture<'a, PolicyVerdict>
    {
        Box::pin(async { Ok(PolicyVerdict::Permit) })
    }
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let provider_id = ProviderInstanceId::parse("mock-hsm")?;
    let namespace = ProviderNamespace::parse("tenant-a")?;
    let key = LogicalKeyId::parse("payments")?;
    let resource = ProviderResourceId::parse("mock:payments:42")?;
    let version = ProviderVersionId::parse("v7")?;
    let scope = HostScope::new(provider_id.clone(), namespace.clone());
    let profile = AlgorithmProfile::RsaPss {
        modulus_bits: 3072, digest: DigestAlgorithm::Sha256,
        mgf1_digest: DigestAlgorithm::Sha256, salt_bytes: 32,
    };
    let operation = CryptoOperation::SignDigest { digest: DigestAlgorithm::Sha256 };
    let trusted = HostValidatedCapabilities {
        scope: Some(scope.clone()),
        protection: Some(ProtectionClass::Hsm),
        version_model: Some(VersionModel::ProviderVersion),
        ..Default::default()
    };
    let provider = Mock {
        provider: provider_id.clone(),
        catalog: ProviderCapabilities {
            schema_version: CAPABILITY_SCHEMA_VERSION,
            provider_instance: "mock-hsm".to_owned(),
            namespace: "tenant-a".to_owned(),
            protocol_revision: "example.v1".to_owned(),
            feature_revision: "fixture.r1".to_owned(),
            reported_protection: ProtectionClass::Hsm,
            reported_version_model: VersionModel::ProviderVersion,
            reported_exportability: Exportability::None,
            attestation_claims: Vec::new(),
            entries: vec![CapabilityEntry {
                operation: operation.clone(), profile: profile.clone(),
                support: SupportStatus::Supported, max_input_bytes: Some(32),
            }],
        },
        resolved: ResolvedKey::new(provider_id.clone(), namespace.clone(), key.clone(),
            DispatchTarget::ProviderVersion { resource: resource.clone(), version: version.clone() },
        ),
    };
    let reference = KeyRef::new(provider_id, namespace, key,
        KeySelector::ExactProviderVersion { resource, version },
    );
    let intent = OperationIntent {
        operation, profile,
        payload: PayloadDescriptor::Digest { algorithm: DigestAlgorithm::Sha256, bytes: 32 },
        binding: VersionRequirement::ProviderVersion,
        protection: ProtectionRequirement::Hsm,
        export: ExportRequirement::None,
    };
    let digest = [0x5Au8; 32];
    let correlation = CorrelationId::parse("km05-demo")?;
    let completion = drive(execute_checked(&provider, &HostPolicy, OperationRequest {
        scope: &scope, reference: &reference, host_assurance: &trusted,
        intent: &intent,
        input: OperationInput::Digest {
            algorithm: DigestAlgorithm::Sha256, bytes: &digest, authenticator: None,
        },
        correlation: &correlation,
    }))?;
    println!("Provider result: {:?}; version assurance: {:?}",
        completion.evidence.outcome, completion.evidence.assurance);
    println!("A fake response only: no signature, HSM, KMS call or authorization proof.");
    Ok(())
}
