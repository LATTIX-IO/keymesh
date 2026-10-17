//! Explicit, ephemeral Ed25519 software-provider example.
//!
//! Run only with the opt-in feature:
//!   cargo run --locked -p keymesh --features software-provider --example software_ed25519
//!
//! No secret seed, private key, certificate or credential is printed. This
//! example is NOT a KMS, HSM, FIPS-validated service or persistent key store.

use keymesh::{
    AlgorithmProfile, CorrelationId, CryptoOperation, EdDsaVariant, ExportRequirement, HostScope,
    HostValidatedCapabilities, LogicalKeyId, OperationInput, OperationIntent, OperationRequest,
    PayloadDescriptor, PolicyContext, PolicyGate, PolicyVerdict, ProtectionClass,
    ProtectionRequirement, ProviderError, ProviderFuture, ProviderInstanceId, ProviderNamespace,
    ProviderOutput, SoftwareCreateRequest, SoftwareLifecycleContext, SoftwareLifecycleGate,
    SoftwareProvider, VersionModel, VersionRequirement, execute_checked,
};
use std::future::Future;
use std::task::{Context, Poll, Waker};

struct DemoPolicy;
impl SoftwareLifecycleGate for DemoPolicy {
    fn authorize<'a>(
        &'a self,
        _ctx: &'a SoftwareLifecycleContext<'_>,
    ) -> ProviderFuture<'a, PolicyVerdict> {
        // Fixture-only host policy: a real host must independently evaluate
        // authenticated tenant/provider identity and requested operation.
        Box::pin(async { Ok(PolicyVerdict::Permit) })
    }
}
impl PolicyGate for DemoPolicy {
    fn evaluate<'a>(&'a self, _ctx: &'a PolicyContext<'_>) -> ProviderFuture<'a, PolicyVerdict> {
        Box::pin(async { Ok(PolicyVerdict::Permit) })
    }
}
fn run<F: Future>(future: F) -> F::Output {
    let waker = Waker::noop();
    let mut context = Context::from_waker(waker);
    let mut future = Box::pin(future);
    loop {
        if let Poll::Ready(result) = future.as_mut().poll(&mut context) {
            return result;
        }
        std::thread::yield_now();
    }
}
fn intent(op: CryptoOperation, msg_bytes: usize) -> OperationIntent {
    OperationIntent {
        operation: op,
        profile: AlgorithmProfile::EdDsa {
            variant: EdDsaVariant::Ed25519,
        },
        payload: PayloadDescriptor::Message {
            bytes: msg_bytes as u64,
        },
        binding: VersionRequirement::ProviderVersion,
        protection: ProtectionRequirement::Any,
        export: ExportRequirement::None,
    }
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let scope = HostScope::new(
        ProviderInstanceId::parse("explicit-local-software")?,
        ProviderNamespace::parse("example-tenant")?,
    );
    let assurance = HostValidatedCapabilities {
        scope: Some(scope.clone()),
        protection: Some(ProtectionClass::Software),
        version_model: Some(VersionModel::ProviderVersion),
        permit_extensions: false,
        permit_private_export: false,
    };
    let provider = SoftwareProvider::new(scope.provider().clone(), scope.namespace().clone());
    let policy = DemoPolicy;
    let name = LogicalKeyId::parse("demo-ed25519")?;
    let generation = SoftwareProvider::create_intent();
    let created = run(provider.create(
        &policy,
        SoftwareCreateRequest {
            scope: &scope,
            host_assurance: &assurance,
            logical_key: &name,
            intent: &generation,
        },
    ))?;
    let message = b"keymesh FOSS-409 pure Ed25519";
    let trace = CorrelationId::parse("demo-signature-01")?;
    let signing = intent(CryptoOperation::SignMessage, message.len());
    let signed = run(execute_checked(
        &provider,
        &policy,
        OperationRequest {
            scope: &scope,
            reference: created.reference(),
            host_assurance: &assurance,
            intent: &signing,
            input: OperationInput::Message {
                bytes: message,
                authenticator: None,
            },
            correlation: &trace,
        },
    ))?;
    let signature = match signed.output {
        ProviderOutput::Signature(s) => s,
        _ => return Err(Box::new(ProviderError::unknown_commit_state())),
    };
    let verify_intent = intent(CryptoOperation::VerifyMessage, message.len());
    let verified = run(execute_checked(
        &provider,
        &policy,
        OperationRequest {
            scope: &scope,
            reference: created.reference(),
            host_assurance: &assurance,
            intent: &verify_intent,
            input: OperationInput::Message {
                bytes: message,
                authenticator: Some(&signature),
            },
            correlation: &trace,
        },
    ))?;
    assert!(matches!(
        verified.output,
        ProviderOutput::Verification(true)
    ));
    println!(
        "Software-only Ed25519 generated; public key length: {} bytes",
        created.public_key().len()
    );
    println!(
        "Pure-message signature length: {} bytes, verification succeeded",
        signature.len()
    );
    println!("Key is ephemeral and exists only in this process; no private material exported.");
    Ok(())
}
