//! KM-09 isolated, opt-in logical-key rotation and history demonstration.
//! No network/HSM, persistent keys, IAM, private-key export or hardcoded seed.
//!
//! cargo run --locked -p keymesh --features software-provider --example software_rotation

use keymesh::{
    AlgorithmProfile, CorrelationId, CryptoOperation, EdDsaVariant, ExportRequirement,
    HostScope, HostValidatedCapabilities, LogicalKeyId, OperationInput, OperationIntent,
    OperationRequest, PayloadDescriptor, PolicyContext, PolicyGate, PolicyVerdict,
    ProtectionClass, ProtectionRequirement, ProviderError, ProviderFuture,
    ProviderInstanceId, ProviderNamespace, ProviderOutput, SoftwareCreateRequest,
    SoftwareLifecycleContext, SoftwareLifecycleGate, SoftwareProvider, SoftwareRotateRequest,
    SoftwareTransitionAction, SoftwareTransitionRequest, VersionModel,
    VersionRequirement, execute_checked,
};
use std::future::Future;
use std::task::{Context, Poll, Waker};

struct DemoOnlyPermit;
impl SoftwareLifecycleGate for DemoOnlyPermit {
    fn authorize<'a>(
        &'a self, _: &'a SoftwareLifecycleContext<'_>,
    ) -> ProviderFuture<'a, PolicyVerdict> {
        // A real host must supply independently authenticated authorization.
        Box::pin(async { Ok(PolicyVerdict::Permit) })
    }
}
impl PolicyGate for DemoOnlyPermit {
    fn evaluate<'a>(
        &'a self, _: &'a PolicyContext<'_>,
    ) -> ProviderFuture<'a, PolicyVerdict> {
        Box::pin(async { Ok(PolicyVerdict::Permit) })
    }
}
fn run<F: Future>(f: F) -> F::Output {
    let mut f = Box::pin(f);
    let mut ctx = Context::from_waker(Waker::noop());
    loop {
        if let Poll::Ready(v) = f.as_mut().poll(&mut ctx) {
            return v;
        }
        std::thread::yield_now();
    }
}
fn intent(op: CryptoOperation, len: usize) -> OperationIntent {
    OperationIntent {
        operation: op,
        profile: AlgorithmProfile::EdDsa { variant: EdDsaVariant::Ed25519 },
        payload: PayloadDescriptor::Message { bytes: len as u64 },
        binding: VersionRequirement::ProviderVersion,
        protection: ProtectionRequirement::Any,
        export: ExportRequirement::None,
    }
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let scope = HostScope::new(
        ProviderInstanceId::parse("km09-software-local")?,
        ProviderNamespace::parse("km09-demo-tenant")?,
    );
    let assurance = HostValidatedCapabilities {
        scope: Some(scope.clone()),
        protection: Some(ProtectionClass::Software),
        version_model: Some(VersionModel::ProviderVersion),
        permit_extensions: false, permit_private_export: false,
    };
    let provider = SoftwareProvider::new(
        scope.provider().clone(), scope.namespace().clone(),
    );
    let gate = DemoOnlyPermit;
    let logical = LogicalKeyId::parse("demo-rotating-key")?;
    let generate = SoftwareProvider::create_intent();
    let first = run(provider.create(&gate, SoftwareCreateRequest {
        scope: &scope, host_assurance: &assurance,
        logical_key: &logical, intent: &generate,
    }))?;
    let message = b"immutable signing evidence";
    let sign = intent(CryptoOperation::SignMessage, message.len());
    let verify = intent(CryptoOperation::VerifyMessage, message.len());
    let audit = CorrelationId::parse("km09-demo")?;
    let signature = match run(execute_checked(
        &provider, &gate,
        OperationRequest {
            scope: &scope, reference: first.reference(),
            host_assurance: &assurance, intent: &sign,
            input: OperationInput::Message {
                bytes: message, authenticator: None,
            },
            correlation: &audit,
        },
    ))?.output {
        ProviderOutput::Signature(bytes) => bytes,
        _ => return Err(Box::new(ProviderError::unknown_commit_state())),
    };
    let before = provider.snapshot(&scope, &assurance, &logical)?;
    let rotated = run(provider.rotate(&gate, SoftwareRotateRequest {
        scope: &scope, host_assurance: &assurance,
        previous: first.reference(), expected_generation: before.generation(),
        intent: &generate, correlation: Some(&audit),
    }))?;
    let historical = run(execute_checked(&provider, &gate, OperationRequest {
        scope: &scope, reference: first.reference(),
        host_assurance: &assurance, intent: &verify,
        input: OperationInput::Message {
            bytes: message, authenticator: Some(&signature),
        },
        correlation: &audit,
    }))?;
    assert!(matches!(historical.output, ProviderOutput::Verification(true)));
    let retired_sign = run(execute_checked(&provider, &gate, OperationRequest {
        scope: &scope, reference: first.reference(),
        host_assurance: &assurance, intent: &sign,
        input: OperationInput::Message { bytes: message, authenticator: None },
        correlation: &audit,
    }));
    assert!(retired_sign.is_err());
    let snapshot = provider.snapshot(&scope, &assurance, &logical)?;
    assert_eq!(snapshot.versions().len(), 2);
    assert_eq!(snapshot.active(), Some(rotated.created().reference()));
    let disabled = run(provider.transition(&gate, SoftwareTransitionRequest {
        scope: &scope, host_assurance: &assurance,
        reference: rotated.created().reference(),
        expected_generation: snapshot.generation(),
        action: SoftwareTransitionAction::Disable, correlation: Some(&audit),
    }))?;
    assert!(provider.snapshot(&scope, &assurance, &logical)?.active().is_none());
    let restored = run(provider.transition(&gate, SoftwareTransitionRequest {
        scope: &scope, host_assurance: &assurance,
        reference: rotated.created().reference(),
        expected_generation: disabled.generation(),
        action: SoftwareTransitionAction::Enable, correlation: Some(&audit),
    }))?;
    println!("Rotation committed at generation {}", rotated.evidence().generation());
    println!("Old Ed25519 signature verified against exact retired version");
    println!("Retired version could not sign; disable/enable transition committed at {}", restored.generation());
    println!("No secret bytes, remote systems or persistent keys were accessed.");
    Ok(())
}
