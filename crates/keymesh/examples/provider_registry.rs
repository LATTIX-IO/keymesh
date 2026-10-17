//! FOSS-407 explicit provider routing example. Fake capability data only.
//! No KMS calls, encryption, signing or host attestation occur.
use keymesh::{
    AlgorithmProfile, CAPABILITY_SCHEMA_VERSION, CapabilityEntry, CryptoOperation, DigestAlgorithm,
    ExportRequirement, Exportability, HostScope, HostValidatedCapabilities, KeyProvider, KeyRef,
    OperationIntent, PayloadDescriptor, ProtectionClass, ProtectionRequirement,
    ProviderCapabilities, ProviderError, ProviderErrorKind, ProviderFuture, ProviderHealth,
    ProviderInstanceId, ProviderNamespace, ProviderRegistry, ProviderRequirements,
    ProviderSelection, ResolvedKey, SupportStatus, VersionModel, VersionRequirement,
};
use std::future::Future;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};

fn run<F: Future>(future: F) -> F::Output {
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
struct Fake {
    instance: ProviderInstanceId,
    catalog: ProviderCapabilities,
}
impl KeyProvider for Fake {
    fn instance(&self) -> &ProviderInstanceId {
        &self.instance
    }
    fn capabilities<'a>(
        &'a self,
        _scope: &'a HostScope,
    ) -> ProviderFuture<'a, ProviderCapabilities> {
        Box::pin(async move { Ok(self.catalog.clone()) })
    }
    fn resolve<'a>(
        &'a self,
        _scope: &'a HostScope,
        _key: &'a KeyRef,
    ) -> ProviderFuture<'a, ResolvedKey> {
        Box::pin(async {
            Err(ProviderError::not_dispatched(
                ProviderErrorKind::UnsupportedOperationOrProfile,
            ))
        })
    }
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let registry = ProviderRegistry::new();
    let namespace = ProviderNamespace::parse("tenant-a")?;
    let mut allowed = Vec::new();
    for (name, protection) in [
        ("a-software", ProtectionClass::Software),
        ("b-hsm", ProtectionClass::Hsm),
    ] {
        let instance = ProviderInstanceId::parse(name)?;
        let scope = HostScope::new(instance.clone(), namespace.clone());
        let assurance = HostValidatedCapabilities {
            scope: Some(scope.clone()),
            protection: Some(protection),
            version_model: Some(VersionModel::ProviderVersion),
            ..Default::default()
        };
        let profile = AlgorithmProfile::RsaPss {
            modulus_bits: 3072,
            digest: DigestAlgorithm::Sha256,
            mgf1_digest: DigestAlgorithm::Sha256,
            salt_bytes: 32,
        };
        let provider: Arc<dyn KeyProvider> = Arc::new(Fake {
            instance,
            catalog: ProviderCapabilities {
                schema_version: CAPABILITY_SCHEMA_VERSION,
                provider_instance: name.into(),
                namespace: "tenant-a".into(),
                protocol_revision: "fixture.v1".into(),
                feature_revision: "fixture.r1".into(),
                reported_protection: protection,
                reported_version_model: VersionModel::ProviderVersion,
                reported_exportability: Exportability::None,
                attestation_claims: Vec::new(),
                entries: vec![CapabilityEntry {
                    operation: CryptoOperation::SignDigest {
                        digest: DigestAlgorithm::Sha256,
                    },
                    profile,
                    support: SupportStatus::Supported,
                    max_input_bytes: Some(32),
                }],
            },
        });
        registry.register(provider, scope.clone(), assurance, ProviderHealth::Healthy)?;
        allowed.push(scope);
    }
    let requested = OperationIntent {
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
    };
    // Only providers in the host-authorized set can be selected, and
    // opt-in AnyCompatible does not weaken the HSM requirement.
    let selection = ProviderSelection::AnyCompatible;
    let routed = run(registry.route(ProviderRequirements {
        authorized_scopes: &allowed,
        intent: &requested,
        selection: &selection,
    }))?;
    assert_eq!(routed.instance().as_str(), "b-hsm");
    println!(
        "Selected provider {} after {} denied candidates; no crypto dispatched",
        routed.instance().as_str(),
        routed.trace().rejected
    );
    println!("Mock custody/health values are NOT cryptographic attestations.");
    Ok(())
}
