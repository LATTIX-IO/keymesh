//! KM-07 explicit credential callback example, using *fake* local data only.
//! It never authenticates to any cloud, HSM or live provider.
use keymesh::{
    AlgorithmProfile, CredentialAuthorization, CredentialError, CredentialFuture,
    CredentialPurpose, CredentialRequest, CredentialSource, CryptoOperation, DigestAlgorithm,
    ExportRequirement, HostScope, OperationIntent, PayloadDescriptor, PolicyVerdict,
    ProtectionRequirement, ProviderInstanceId, ProviderNamespace, ScopedCredential, SecretBytes,
    VersionRequirement, acquire_scoped_credential,
};
use std::future::Future;
use std::task::{Context, Poll, Waker};

struct LocalHostPolicy;
impl CredentialAuthorization for LocalHostPolicy {
    fn authorize<'a>(
        &'a self,
        _request: &'a CredentialRequest<'_>,
    ) -> CredentialFuture<'a, PolicyVerdict> {
        // Demonstration only: never hardcode Permit as production policy.
        Box::pin(async { Ok(PolicyVerdict::Permit) })
    }
}
struct LocalFakeSource {
    provider: ProviderInstanceId,
    tenant: ProviderNamespace,
}
impl CredentialSource for LocalFakeSource {
    fn provider(&self) -> &ProviderInstanceId {
        &self.provider
    }
    fn namespace(&self) -> &ProviderNamespace {
        &self.tenant
    }
    fn acquire<'a>(
        &'a self,
        request: &'a CredentialRequest<'_>,
    ) -> CredentialFuture<'a, ScopedCredential> {
        Box::pin(async move {
            let fake = SecretBytes::from_vec(b"fake-fixture-do-not-use-as-credential".to_vec())
                .map_err(|_| CredentialError::InvalidMaterial)?;
            Ok(ScopedCredential::new(
                request.host_scope.clone(),
                request.operation.clone(),
                request.purpose,
                fake,
            ))
        })
    }
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
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let provider = ProviderInstanceId::parse("local-hsm-fixture")?;
    let namespace = ProviderNamespace::parse("tenant-a")?;
    let scope = HostScope::new(provider.clone(), namespace.clone());
    let source = LocalFakeSource {
        provider: provider.clone(),
        tenant: namespace.clone(),
    };
    let intent = OperationIntent {
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
    let operation = intent.operation.clone();
    let mut credential = run(acquire_scoped_credential(
        &source,
        &LocalHostPolicy,
        CredentialRequest {
            host_scope: &scope,
            expected_provider: &provider,
            expected_namespace: &namespace,
            intent: &intent,
            operation: &operation,
            purpose: CredentialPurpose::ProviderAuthentication,
        },
    ))?;
    assert_eq!(credential.scope(), &scope);
    // Only size and static categories are ever printed. No credential data.
    println!(
        "Fake credential acquired with scoped ownership; {} bytes held",
        credential.len()
    );
    credential.erase();
    println!(
        "Owned test buffer explicitly erased: {}",
        credential.is_empty()
    );
    println!("No KeyProvider operation was dispatched. No live secret is accessed.");
    Ok(())
}
