//! Human-operated, standalone Keymesh software-provider demonstration.
//! Nothing persists; this is an observability lab, NOT a production KMS.
use keymesh::{
    AlgorithmProfile, CorrelationId, CryptoOperation, DecisionPolicyGate, EdDsaVariant,
    ExportRequirement, HostScope, HostValidatedCapabilities, KeyProvider, KeyRef, KeySelector,
    LogicalKeyId, OperationCompletion, OperationInput, OperationIntent, OperationRequest,
    PayloadDescriptor, PolicyAuditSink, PolicyDecision, PolicyDecisionEvidence,
    PolicyRequirements, PolicyVerdict, ProtectionClass, ProtectionRequirement, ProviderError,
    ProviderErrorKind, ProviderFuture, ProviderHealth, ProviderInstanceId, ProviderNamespace,
    ProviderOutput, ProviderRegistry, ProviderRequirements, ProviderSelection, SoftwareCreateRequest,
    SoftwareLifecycleContext, SoftwareLifecycleGate, SoftwareProvider, SoftwarePurgeRequest,
    SoftwareRotateRequest, SoftwareTransitionAction, SoftwareTransitionRequest, VersionModel,
    VersionRequirement, execute_checked_with_decision,
};
use std::future::Future;
use std::io::{self, Write};
use std::sync::Arc;
use std::task::{Context, Poll, Waker};

fn run<F: Future>(future: F) -> F::Output {
    // The in-memory demo returns ready futures. This is not a production
    // executor and must not be used for networked/HSM adapters.
    let mut future = Box::pin(future);
    let mut ctx = Context::from_waker(Waker::noop());
    loop {
        if let Poll::Ready(result) = future.as_mut().poll(&mut ctx) {
            return result;
        }
        std::thread::yield_now();
    }
}
fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(DIGITS[usize::from(b >> 4)] as char);
        s.push(DIGITS[usize::from(b & 15)] as char);
    }
    s
}
fn print_error(action: &str, err: ProviderError) {
    println!(
        "REJECTED {action}: kind={:?}; state={:?}; retry={:?}",
        err.kind(), err.state(), err.retry()
    );
}
fn show_completion(result: &OperationCompletion) {
    let ev = &result.evidence;
    println!(
        "  [05] DISPATCH RECEIPT: operation={:?}; outcome={:?}; assurance={:?}",
        ev.operation, ev.outcome, ev.assurance
    );
    println!(
        "       fixed provider={} tenant={} key={} version={}",
        ev.provider.as_str(),
        ev.namespace.as_str(),
        ev.logical_key.as_str(),
        ev.target
            .provider_version()
            .map(|v| v.as_str())
            .unwrap_or("no-specific-version")
    );
    println!("       correlation={}", ev.correlation.as_str());
    match &result.output {
        ProviderOutput::Signature(bytes) => {
            println!("       real Ed25519 signature (PUBLIC): {} bytes", bytes.len());
            println!("       signature hex={}", hex(bytes));
        }
        ProviderOutput::Verification(valid) => {
            println!("       cryptographic signature verification={valid}");
        }
        ProviderOutput::PublicKey(bytes) => {
            println!("       public key (PUBLIC): {} bytes; hex={}", bytes.len(), hex(bytes));
        }
        _ => println!("       unexpected provider output type"),
    }
}

struct InteractiveLifecycle {
    refuse: bool,
}
impl SoftwareLifecycleGate for InteractiveLifecycle {
    fn authorize<'a>(
        &'a self,
        ctx: &'a SoftwareLifecycleContext<'_>,
    ) -> ProviderFuture<'a, PolicyVerdict> {
        println!(
            "  [LIFECYCLE] requested action={:?}; expected_generation={:?}",
            ctx.action, ctx.expected_generation
        );
        let outcome = if self.refuse {
            PolicyVerdict::Deny
        } else {
            PolicyVerdict::Permit
        };
        println!("  [LIFECYCLE] host-demo decision={outcome:?}");
        Box::pin(async move { Ok(outcome) })
    }
}

struct InteractiveDecision {
    verdict: PolicyVerdict,
    requirements: PolicyRequirements,
}
impl DecisionPolicyGate for InteractiveDecision {
    fn decide<'a>(&'a self, ctx: &'a keymesh::PolicyContext<'_>) -> ProviderFuture<'a, PolicyDecision> {
        println!("  [03] DECISION HOOK: provider={} tenant={} key={}",
            ctx.scope.provider().as_str(),
            ctx.scope.namespace().as_str(),
            ctx.reference.logical_key().as_str()
        );
        println!("       operation={:?}; provider-reported custody={:?}; binding={:?}",
            ctx.intent.operation,
            ctx.catalog.reported_protection,
            ctx.resolved.dispatch_target().assurance()
        );
        println!("       requested constraints={:?}; verdict={:?}", self.requirements, self.verdict);
        let verdict = self.verdict;
        let requirements = self.requirements.clone();
        Box::pin(async move {
            Ok(PolicyDecision {
                verdict,
                requirements,
                policy_revision: Some(CorrelationId::parse("lab-policy-v1")?),
            })
        })
    }
}
struct InteractiveAudit {
    fail: bool,
}
impl PolicyAuditSink for InteractiveAudit {
    fn record(&self, evidence: &PolicyDecisionEvidence<'_>) -> Result<(), ProviderError> {
        println!(
            "  [04] PRE-DISPATCH AUDIT: verdict={:?}; requirements_met={}; revision={}; correlation={}",
            evidence.decision.verdict,
            evidence.requirements_satisfied,
            evidence
                .decision
                .policy_revision
                .as_ref()
                .map(CorrelationId::as_str)
                .unwrap_or("not-provided"),
            evidence.correlation.as_str()
        );
        if self.fail {
            println!("  [04] SIMULATED AUDIT FAILURE: STOP before dispatch");
            return Err(ProviderError::not_dispatched(ProviderErrorKind::Unavailable));
        }
        Ok(())
    }
}

#[derive(Clone)]
struct Signed {
    exact: KeyRef,
    message: Vec<u8>,
    signature: Vec<u8>,
}
struct Lab {
    scope: HostScope,
    assurance: HostValidatedCapabilities,
    logical: LogicalKeyId,
    provider: Arc<SoftwareProvider>,
    registry: ProviderRegistry,
    current: Option<KeyRef>,
    first: Option<KeyRef>,
    signed: Option<Signed>,
    prior_generation: Option<u64>,
}
impl Lab {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let id = ProviderInstanceId::parse("tour-local-ed25519")?;
        let tenant = ProviderNamespace::parse("tour-tenant-a")?;
        let scope = HostScope::new(id.clone(), tenant.clone());
        let assurance = HostValidatedCapabilities {
            scope: Some(scope.clone()),
            protection: Some(ProtectionClass::Software),
            version_model: Some(VersionModel::ProviderVersion),
            permit_extensions: false,
            permit_private_export: false,
        };
        let provider = Arc::new(SoftwareProvider::new(id, tenant));
        let registry = ProviderRegistry::new();
        registry.register(provider.clone(), scope.clone(), assurance.clone(), ProviderHealth::Unknown)?;
        Ok(Self {
            scope,
            assurance,
            logical: LogicalKeyId::parse("payments-signing")?,
            provider,
            registry,
            current: None,
            first: None,
            signed: None,
            prior_generation: None,
        })
    }
    fn intent(operation: CryptoOperation, input_bytes: usize) -> OperationIntent {
        let export = matches!(operation, CryptoOperation::ExportPublic);
        OperationIntent {
            operation,
            profile: AlgorithmProfile::EdDsa {
                variant: EdDsaVariant::Ed25519,
            },
            payload: if export {
                PayloadDescriptor::None
            } else {
                PayloadDescriptor::Message {
                    bytes: input_bytes as u64,
                }
            },
            binding: VersionRequirement::ProviderVersion,
            protection: ProtectionRequirement::Any,
            export: if export {
                ExportRequirement::Public
            } else {
                ExportRequirement::None
            },
        }
    }
    fn trusted_requirements() -> PolicyRequirements {
        PolicyRequirements {
            algorithm: Some(AlgorithmProfile::EdDsa {
                variant: EdDsaVariant::Ed25519,
            }),
            min_version: Some(VersionRequirement::ProviderVersion),
            protection: Some(ProtectionClass::Software),
        }
    }
    fn execute(
        &self,
        key: &KeyRef,
        operation: CryptoOperation,
        message: &[u8],
        signature: Option<&[u8]>,
        verdict: PolicyVerdict,
        requirements: PolicyRequirements,
        audit_fail: bool,
    ) -> Result<OperationCompletion, ProviderError> {
        let intent = Self::intent(operation.clone(), message.len());
        let label = CorrelationId::parse("keymesh-tour-operation")?;
        let decision = InteractiveDecision { verdict, requirements };
        let sink = InteractiveAudit { fail: audit_fail };
        let input = if operation == CryptoOperation::ExportPublic {
            OperationInput::None
        } else {
            OperationInput::Message {
                bytes: message,
                authenticator: signature,
            }
        };
        println!("  [01] HOST SCOPE: provider={} tenant={} (simulated trusted host)",
            self.scope.provider().as_str(),
            self.scope.namespace().as_str()
        );
        println!("  [02] GATEWAY: typed intent={operation:?}; exact reference={key}");
        println!("       validation -> capabilities -> resolution -> version binding -> policy");
        println!("       (If an early guard rejects this request, [03]/[04] will not run.)");
        run(execute_checked_with_decision(
            self.provider.as_ref(),
            &decision,
            Some(&sink),
            OperationRequest {
                scope: &self.scope,
                reference: key,
                host_assurance: &self.assurance,
                intent: &intent,
                input,
                correlation: &label,
            },
        ))
    }
    fn capabilities(&self) {
        println!("CAPABILITIES (provider reports; separate host corroboration required):");
        match run(self.provider.capabilities(&self.scope)) {
            Ok(catalog) => {
                println!("  schema={} protocol={} revision={}", catalog.schema_version, catalog.protocol_revision, catalog.feature_revision);
                println!("  custody={:?}; version model={:?}; export={:?}",
                    catalog.reported_protection, catalog.reported_version_model, catalog.reported_exportability);
                for entry in &catalog.entries {
                    println!("  operation={:?}; algorithm={:?}; support={:?}; max_bytes={:?}",
                        entry.operation, entry.profile, entry.support, entry.max_input_bytes);
                }
            }
            Err(err) => print_error("capability query", err),
        }
    }
    fn route(&self) {
        println!("ROUTE: one enrolled provider, no automatic fallback.");
        let scopes = [self.scope.clone()];
        let selection = ProviderSelection::Instance(self.scope.provider().clone());
        let intent = Self::intent(CryptoOperation::SignMessage, 12);
        match run(self.registry.route_diagnostic(ProviderRequirements {
            authorized_scopes: &scopes,
            intent: &intent,
            selection: &selection,
        })) {
            Ok(provider) => println!(
                "  SELECTED provider={} tenant={}; capability admission succeeded (no signature dispatched)",
                provider.instance().as_str(), provider.namespace().as_str()
            ),
            Err(err) => println!(
                "  NO ROUTE {:?}; examined={} rejected={} not_healthy={}",
                err.kind, err.trace.examined, err.trace.rejected,
                err.trace.count(keymesh::RejectionReason::NotHealthy)
            ),
        }
    }
    fn health(&self, value: &str) {
        let health = match value {
            "healthy" => ProviderHealth::Healthy,
            "unavailable" => ProviderHealth::Unavailable,
            "unknown" => ProviderHealth::Unknown,
            _ => {
                println!("Usage: health healthy|unavailable|unknown");
                return;
            }
        };
        match self.registry.set_health(&self.scope, health) {
            Ok(()) => println!("HOST ROUTING HEALTH set to {health:?} (host assertion only)"),
            Err(err) => println!("Health change failed: {err}"),
        }
    }
    fn create(&mut self, refuse: bool) {
        let intent = SoftwareProvider::create_intent();
        let gate = InteractiveLifecycle { refuse };
        println!("CREATE: Generate -> host lifecycle authorization -> OS random key -> exact version");
        match run(self.provider.create(
            &gate,
            SoftwareCreateRequest {
                scope: &self.scope,
                host_assurance: &self.assurance,
                logical_key: &self.logical,
                intent: &intent,
            },
        )) {
            Ok(key) => {
                self.current = Some(key.reference().clone());
                if self.first.is_none() {
                    self.first = Some(key.reference().clone());
                }
                println!("  CREATED generation={} URI={}", key.generation(), key.reference());
                println!("  PUBLIC KEY (32 bytes, safe to inspect): {}", hex(key.public_key()));
                println!("  Private seed never returned; held in zeroizing, process-local memory.");
            }
            Err(err) => print_error("create", err),
        }
    }
    fn status(&self) {
        println!("SNAPSHOT: process-local logical key '{}'", self.logical.as_str());
        match self.provider.snapshot(&self.scope, &self.assurance, &self.logical) {
            Ok(snapshot) => {
                println!("  generation={} (optimistic compare-and-swap token)", snapshot.generation());
                println!("  active={}", snapshot.active().map(ToString::to_string).unwrap_or_else(|| "none".into()));
                println!("  latest={}", snapshot.latest().map(ToString::to_string).unwrap_or_else(|| "none".into()));
                for version in snapshot.versions() {
                    println!("    status={:?}; issued_generation={}; exact={}",
                        version.status(), version.issued_generation(), version.reference());
                }
            }
            Err(_) => println!("  NO KEY: fresh provider contains no keys. Run create."),
        }
    }
    fn uri(&self) {
        let Some(key) = self.current.as_ref() else {
            println!("Create a key first.");
            return;
        };
        let value = key.to_string();
        let recovered = value.parse::<KeyRef>();
        println!("CANONICAL KEYREF URI={value}");
        match recovered {
            Ok(parsed) => println!("  parse -> exact structural roundtrip: {}", &parsed == key),
            Err(err) => println!("  unexpected parsing error: {err}"),
        }
        let malformed = value.replacen("keymesh://v1/", "keymesh://v2/", 1);
        println!("  changed URI schema is rejected: {}", malformed.parse::<KeyRef>().is_err());
        println!("  A KeyRef names a key; it is NOT an access token.");
    }
    fn sign(&mut self, message: &str, alias: bool) {
        let Some(current) = self.current.clone() else {
            println!("Create a key first."); return;
        };
        let reference = if alias {
            KeyRef::new(
                self.scope.provider().clone(),
                self.scope.namespace().clone(),
                self.logical.clone(),
                KeySelector::Active,
            )
        } else {
            current.clone()
        };
        let text = if message.is_empty() { "approve purchase order #481" } else { message };
        println!("SIGN {}: UTF-8 message '{}'", if alias {"ACTIVE ALIAS"} else {"EXACT VERSION"}, text);
        match self.execute(
            &reference, CryptoOperation::SignMessage,
            text.as_bytes(), None, PolicyVerdict::Permit, Self::trusted_requirements(), false
        ) {
            Ok(result) => {
                show_completion(&result);
                if let ProviderOutput::Signature(sig) = result.output {
                    self.signed = Some(Signed {
                        exact: current,
                        message: text.as_bytes().to_vec(),
                        signature: sig,
                    });
                    println!("  Saved signature + exact reference for subsequent verify/rotate.");
                }
            }
            Err(err) => print_error("sign", err),
        }
    }
    fn verify(&self, tamper: bool) {
        let Some(saved) = self.signed.clone() else {
            println!("Sign a message first."); return;
        };
        let mut text = saved.message.clone();
        if tamper {
            text.push(b'!');
            println!("VERIFY TAMPERED: added a byte; original signature must fail.");
        } else {
            println!("VERIFY ORIGINAL: exact original key and message.");
        }
        match self.execute(
            &saved.exact, CryptoOperation::VerifyMessage,
            &text, Some(&saved.signature), PolicyVerdict::Permit,
            Self::trusted_requirements(), false
        ) {
            Ok(result) => show_completion(&result),
            Err(err) => print_error("verify", err),
        }
    }
    fn export_public(&self) {
        let Some(key) = self.current.as_ref() else {
            println!("Create a key first."); return;
        };
        println!("EXPORT PUBLIC: explicit public-only operation; private export is never offered.");
        match self.execute(
            key, CryptoOperation::ExportPublic, b"", None, PolicyVerdict::Permit,
            Self::trusted_requirements(), false
        ) {
            Ok(result) => show_completion(&result),
            Err(err) => print_error("public export", err),
        }
    }
    fn policies(&self, choice: &str) {
        let Some(key) = self.current.as_ref() else {
            println!("Create a key first."); return;
        };
        let mut requirements = Self::trusted_requirements();
        let verdict = match choice {
            "deny" => PolicyVerdict::Deny,
            "unknown" => PolicyVerdict::Indeterminate,
            _ => PolicyVerdict::Permit,
        };
        if choice == "hsm" {
            requirements.protection = Some(ProtectionClass::Hsm);
        }
        if choice == "material" {
            requirements.min_version = Some(VersionRequirement::MaterialRevision);
        }
        println!("POLICY CASE={choice}: observe [03] decision and [04] audited constraints.");
        match self.execute(
            key, CryptoOperation::SignMessage, b"should not sign", None,
            verdict, requirements, choice == "audit-fail"
        ) {
            Ok(result) => show_completion(&result),
            Err(err) => print_error("policy-controlled operation", err),
        }
        println!("  Check: denied or indeterminate operations have no [05] dispatch receipt.");
    }
    fn cross_tenant(&self) {
        let Some(key) = self.current.as_ref() else {
            println!("Create a key first."); return;
        };
        let bad = KeyRef::new(
            self.scope.provider().clone(),
            ProviderNamespace::parse("wrong-tenant").expect("literal is valid"),
            self.logical.clone(),
            key.selector().clone()
        );
        println!("TENANT SUBSTITUTION: host={} but key reference={}",
            self.scope.namespace().as_str(), bad.namespace().as_str());
        match self.execute(
            &bad, CryptoOperation::SignMessage, b"wrong tenant", None,
            PolicyVerdict::Permit, Self::trusted_requirements(), false
        ) {
            Ok(result) => show_completion(&result),
            Err(err) => print_error("cross-tenant substitution", err),
        }
    }
    fn rotate(&mut self, stale: bool) {
        let Some(current) = self.current.clone() else {
            println!("Create a key first."); return;
        };
        let snapshot = match self.provider.snapshot(&self.scope, &self.assurance, &self.logical) {
            Ok(s) => s,
            Err(err) => { print_error("snapshot", err); return; }
        };
        let observed = if stale {
            match self.prior_generation {
                Some(gen) => gen,
                None => { println!("Run rotate once before stale-rotate."); return; }
            }
        } else {
            snapshot.generation()
        };
        println!("ROTATE: exact prior version; CAS expected={} actual={}; forced stale={}",
            observed, snapshot.generation(), stale);
        let intent = SoftwareProvider::create_intent();
        let corr = CorrelationId::parse("tour-rotation").expect("literal is valid");
        match run(self.provider.rotate(
            &InteractiveLifecycle { refuse: false },
            SoftwareRotateRequest {
                scope: &self.scope,
                host_assurance: &self.assurance,
                previous: &current,
                expected_generation: observed,
                intent: &intent,
                correlation: Some(&corr),
            },
        )) {
            Ok(rotated) => {
                if !stale {
                    self.prior_generation = Some(observed);
                }
                self.current = Some(rotated.created().reference().clone());
                println!("  ROTATED: old={} new={}", current, rotated.created().reference());
                println!("  lifecycle generation={} public_key={}",
                    rotated.evidence().generation(), hex(rotated.created().public_key()));
                println!("  Prior seed zeroized/dropped; old public key remains for verify only.");
            }
            Err(err) => print_error("rotation", err),
        }
    }
    fn retired_sign(&self) {
        let Some(first) = self.first.as_ref() else {
            println!("Create a key first."); return;
        };
        println!("RETIRED SIGNING TEST: request exact original version.");
        match self.execute(
            first, CryptoOperation::SignMessage, b"old signer should be denied", None,
            PolicyVerdict::Permit, Self::trusted_requirements(), false
        ) {
            Ok(result) => show_completion(&result),
            Err(err) => print_error("signing with retired key", err),
        }
    }
    fn transition(&mut self, action: SoftwareTransitionAction) {
        let Some(current) = self.current.as_ref() else {
            println!("Create a key first."); return;
        };
        let snapshot = match self.provider.snapshot(&self.scope, &self.assurance, &self.logical) {
            Ok(s) => s,
            Err(err) => { print_error("snapshot", err); return; }
        };
        println!("TRANSITION {action:?}: exact version with generation CAS={}", snapshot.generation());
        match run(self.provider.transition(
            &InteractiveLifecycle { refuse: false },
            SoftwareTransitionRequest {
                scope: &self.scope,
                host_assurance: &self.assurance,
                reference: current,
                expected_generation: snapshot.generation(),
                action,
                correlation: None,
            },
        )) {
            Ok(evidence) => println!("  COMMITTED from={:?} to={:?}; next generation={}",
                evidence.from(), evidence.to(), evidence.generation()),
            Err(err) => print_error("lifecycle transition", err),
        }
    }
    fn purge_original(&mut self) {
        let Some(original) = self.first.as_ref() else {
            println!("Create and rotate a key first."); return;
        };
        if Some(original) == self.current.as_ref() {
            println!("Rotate before purging original; use this command for historical cleanup.");
            return;
        }
        println!("PURGE: exact original version {}; historical verification then becomes unavailable.", original);
        match run(self.provider.purge_with_evidence(
            &InteractiveLifecycle { refuse: false },
            SoftwarePurgeRequest {
                scope: &self.scope,
                host_assurance: &self.assurance,
                reference: original,
            },
        )) {
            Ok(evidence) => println!("  PURGED generation={}; old resource cannot verify or sign",
                evidence.generation()),
            Err(err) => print_error("purge old version", err),
        }
    }
    fn reset(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        *self = Self::new()?;
        println!("RESET: discarded software provider and all private keys.");
        println!("  No persistent store, disk state, HSM or network was touched.");
        Ok(())
    }
}
fn menu() {
    println!(r#"
MANUAL TOUR (one command at a time, in this same running process)
  help                 Show this menu
  scope                Show trusted-host simulation
  capabilities         Show real software provider capabilities
  route                Route a request through explicit registry (starts unhealthy)
  health healthy       Mark enrolled provider healthy, then rerun route
  health unavailable   Revoke routing (does not cancel executed operations)
  health unknown       Restore fail-closed unknown routing state
  status               Inspect logical key, CAS generation, active/latest, versions
  create-denied        Show lifecycle host Deny without creating a key
  create               Generate real ephemeral Ed25519 key, public key + exact URI
  uri                  Roundtrip canonical KeyRef URI and reject invalid schema
  sign [message]       Sign message using exact current version; show signature
  sign-alias [message] Sign using Active alias, resolved and pinned before dispatch
  verify               Verify stored signature against its EXACT original version
  tamper               Verify altered message against same signature -> false
  export-public        Checked public-key export (no private export)
  policy-deny          Host policy Deny -> NotDispatched
  policy-unknown       Indeterminate policy -> NotDispatched
  require-hsm          Impossible HSM custody constraint -> PolicyDenied
  require-material     Impossible exact material-revision requirement -> PolicyDenied
  audit-fail           Required pre-dispatch audit write fails closed
  cross-tenant         Substitute another tenant in KeyRef -> ScopeMismatch
  rotate               CAS-controlled rotation; old version permanently retired
  stale-rotate         Reuse old snapshot generation -> operation rejected
  retired-sign         Attempt to sign with rotated-out original -> rejected
  disable              Disable current version, temporarily stop all operations
  enable               Re-enable disabled current version if allowed
  purge-old            Purge exact historical version after rotation
  reset                Destroy all process memory state; status then shows no key
  quit                 End the process (all ephemeral keys disappear)

Safeguards: no real IAM; host is a demo fixture; never use test messages as secrets.
No cloud connection, Vault, HSM, PKCS#11, PQC crypto or persistent storage.
"#);
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut lab = Lab::new()?;
    println!("KEYMESH MANUAL TOUR — local standalone Rust consumer");
    println!("Provider is real in-memory Ed25519. No hidden test sequence will run.");
    println!("Each command prints what the public SDK admitted, decided or rejected.");
    menu();
    loop {
        print!("keymesh-tour> ");
        io::stdout().flush()?;
        let mut line = String::new();
        if io::stdin().read_line(&mut line)? == 0 {
            println!("EOF: keys discarded when process exits.");
            break;
        }
        let (command, input) = line.trim().split_once(' ').unwrap_or((line.trim(), ""));
        match command {
            "help" => menu(),
            "scope" => println!(
                "SIMULATED host authority: provider={}, tenant={}, custody=Software, version=ProviderVersion. Not IAM.",
                lab.scope.provider().as_str(), lab.scope.namespace().as_str()
            ),
            "capabilities" => lab.capabilities(),
            "route" => lab.route(),
            "health" => lab.health(input.trim()),
            "status" => lab.status(),
            "create" => lab.create(false),
            "create-denied" => lab.create(true),
            "uri" => lab.uri(),
            "sign" => lab.sign(input, false),
            "sign-alias" => lab.sign(input, true),
            "verify" => lab.verify(false),
            "tamper" => lab.verify(true),
            "export-public" => lab.export_public(),
            "policy-deny" => lab.policies("deny"),
            "policy-unknown" => lab.policies("unknown"),
            "require-hsm" => lab.policies("hsm"),
            "require-material" => lab.policies("material"),
            "audit-fail" => lab.policies("audit-fail"),
            "cross-tenant" => lab.cross_tenant(),
            "rotate" => lab.rotate(false),
            "stale-rotate" => lab.rotate(true),
            "retired-sign" => lab.retired_sign(),
            "disable" => lab.transition(SoftwareTransitionAction::Disable),
            "enable" => lab.transition(SoftwareTransitionAction::Enable),
            "purge-old" => lab.purge_original(),
            "reset" => lab.reset()?,
            "quit" | "exit" => {
                println!("Process ended; all ephemeral signing material is discarded.");
                break;
            }
            "" => (),
            _ => println!("Unknown command '{command}'. Enter help."),
        }
    }
    Ok(())
}
