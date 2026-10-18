# KM-10 — Explicit policy decisions and pre-dispatch audit

Status: FOSS-411 implementation preview. Core `execute_checked` remains mandatory-policy and API-compatible.

## API boundary

- `DecisionPolicyGate::decide` receives the existing metadata-only `PolicyContext`, after capability admission and exact version resolution, before any native operation.
- `PolicyDecision` contains an explicit Permit, Deny or Indeterminate, optional bounded policy revision, and typed exact-algorithm, version-binding and custody requirements.
- Requirements are applied as an additional deny-only constraint, never as authorization in their own right. HSM and TEE are not interchangeable; trusted host custody must match the requested protection class. Physical revision guarantees are never inferred from provider labels.
- The optional `PolicyAuditSink` receives redacted pre-dispatch decision evidence with a trusted-host correlation. Any sink error prevents dispatch. A sink is not an immutable log; durable retention and cryptographic signing are host responsibilities.
- `execute_checked_with_decision` delegates actual dispatch to KM-05 `execute_checked` so existing anti-substitution checks, exact target pinning, and unknown-commit classification remain authoritative.

## Limitations and security requirements

No generic IAM or policy DSL is implemented. Host construction of scope, capability corroboration and evaluator trust is outside Keymesh. An unconfigured audit sink means there is no durable audit promise. The synchronous sink must be bounded and should not perform unbounded remote I/O. A remote operation after submission can have an unknown commit outcome, which pre-dispatch evidence cannot resolve.

## Acceptance gates

Test exact requirement mismatch, HSM-only request on software provider, policy Deny/Indeterminate/error, sink failure, provider dispatch count zero before Permit, tenant/context substitution, alias change after asynchronous evaluator, Debug redaction, feature-off build, stable and Rust 1.85, RustSec/deny/semver and a standalone consumer before moving FOSS-411 to Done. Publication remains disabled.
