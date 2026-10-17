# KM-05 — Runtime-neutral provider contract v1

Status: FOSS-404 provider-interface contract, **unreleased and not a live KMS/HSM integration**.
The implementations of remote providers, credential brokers, policy engines, secret
memory and cryptographic primitives are later increments.

## One checked execution boundary

Host code calls `execute_checked(&dyn KeyProvider, &dyn PolicyGate, OperationRequest)`.
The checked gateway takes the following sequence, with no automatic retry or
provider routing:

1. Verify configured provider instance, independently authenticated HostScope,
   KeyRef provider/namespace, and the scope on HostValidatedCapabilities.
   Reject cross-tenant/provider attempts before any provider query.
2. Validate OperationIntent and classify the real, borrowed input bytes. Raw
   messages, digests, specialized ML-DSA mu, ciphertext, keys and HKDF info are
   **not** interchangeable; verification requires an explicit signature/tag.
   Bytes, secret-bearing provider error messages and request payloads are
   never copied into Keymesh diagnostics.
3. Call side-effect-free provider `capabilities` and `resolve`, verify exact
   algorithm/profile support and host-corroborated version/custody, then
   `preflight_bind` the resource/version/material against the host scope.
   Any mismatch terminates **before** the operation dispatch.
4. Call the mandatory, host-injected async `PolicyGate` with a safe view of
   the scope, reference, resolved key and capability snapshot. A denial,
   missing/unknown verdict, timeout expressed as an error, or evaluation error
   **prevents operation dispatch**. This library does not contain a policy
   evaluator or independently establish host identity.
5. Construct a private-constructor `PreparedDispatch` that retains the exact
   target, operation, and provider feature **and protocol** revisions. A provider adapter MUST
   use that target, not its mutable alias, and MUST recheck actual
   key-material/version selection at the native boundary.
6. Invoke exactly one discrete provider trait method: sign, verify, encrypt,
   decrypt, wrap, unwrap, MAC, KEM, derive or lifecycle. Every method defaults
   to Unsupported with no operation side effect; there is **no implicit
   software fallback**.
7. Compare the provider-reported target with the preflight target and check
   that the response kind matches the exact operation, including exact
   FIPS 203 ML-KEM encapsulation ciphertext size. Return operation-bound
   `OperationEvidence` only after a confirmed result. Invalid post-dispatch
   evidence is classified `UnknownCommitState`, not `NotDispatched`, because a
   side effect may already have occurred.

This is a declarative boundary and fake-provider test harness. Provider
capability claims, the operation receipt and host-provided corroboration are
**not independently verified attestations**. The implementation environment
must authenticate the scope and enforce the native operation semantics.

## Runtime independence and errors

The object-safe `KeyProvider` trait returns
`ProviderFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, ProviderError>> + Send + 'a>>`.
It depends on standard Rust futures, not Tokio, async-std or a provider SDK.
A native blocking PKCS#11/HSM API MUST be offloaded by its adapter to a
host-configured blocking executor. The provided minimal executor is only a
deterministic immediate-future test tool, not an application runtime.

Every error carries a static `ProviderErrorKind` and an `OperationState`:

| State | Meaning | Retry advice |
| --- | --- | --- |
| NotDispatched | Operation known to have not reached native dispatch | Correct preconditions before deliberate retry |
| ConfirmedSuccess | Provider response accepted with exact target and response shape | No automatic repeat |
| ConfirmedFailure | Provider positively confirmed failure without commit | No automatic repeat |
| UnknownCommitState | Submission/acknowledgement or remote state ambiguous | Reconcile before retry |

`ProviderError::unknown_commit_state()` is mandatory for lost replies or
timeouts after possible submission. Dropping/cancelling the caller's future
does not confirm remote cancellation, and may leave an unknown commit state
without a returned result. For mutation/retry safety the host needs a durable
request record, provider idempotency capability or reconciliation read (KM-18).
An adapter MUST NOT manufacture NotDispatched merely because a local future
was cancelled. Static Debug/Display outputs never expose provider SDK
responses, arbitrary backend errors, bearer tokens or payload bytes.

`CorrelationId` is a bounded safe audit label, not proof of user identity.
`ProviderReply` supplies an untrusted provider receipt ID and observed target;
Keymesh checks target equality but not a hardware certificate.
`OperationEvidence` includes provider, namespace, logical key, concrete target,
assurance, operation, correlation ID, optional provider receipt label and
ConfirmedSuccess. Its Debug formatting is redacted; explicit fields are meant
for permissioned audit sinks only.

## Sensitive material and incomplete real-provider semantics

`OperationInput` borrows real payload bytes and checks classification/size
against the typed KM-04 intent. Raw key material is NOT copied or zeroized by
the KM-05 gateway; the checked gateway now hard-rejects KeyMaterial input
(including key wrapping) until KM-07 supplies a secure secret container and
credential boundary. No KM-05 adapter may read private material through
the unchecked byte-slice input carrier. Returned secret material is represented as an opaque
`ProtectedResultRef` with NO retrieval method or raw secret bytes. This is not
a validated secure-memory implementation; do not treat it as one.

New-key `Generate`/`Import` calls are rejected by the checked gateway until
a separate targetless-creation contract exists; no fictitious BoundKey is
fabricated. AES-GCM encrypt/decrypt is rejected until nonce/AAD/tag and
nonce-uniqueness policy have explicit carrier types. Destructive Rotate,
ScheduleDelete and Purge cannot use mutable Active or Latest references.
Vendor-extension dispatch remains unsupported in the checked gateway even
if a provider reports it; explicit sandboxed/authorized extensions require a
future, separately reviewed contract.

The checked gateway also rejects raw key-material input before provider reads.
The provider trait exposes optional methods for operations not yet reachable
from KM-05. They default to Unsupported and cannot be interpreted as an
implemented cryptographic feature. A provider claiming protected-output
handles must implement their lifecycle and access permissions separately
(KM-07/08). No testing of actual cryptographic signatures, hardware claims,
PKCS#11 modules or KMS integration is implied by fake providers.

## Security acceptance

- Scope/provider catalog substitution => zero crypto dispatch.
- Unsupported algorithm, unknown capability, unverified protection/version =>
  zero crypto dispatch.
- Bad digest/profile/payload form or missing proof => zero provider query and
  zero crypto dispatch.
- Stale version and changed native resource => zero crypto dispatch.
- Deny/unknown/failing policy hook => zero crypto dispatch.
- Async cancellation before first poll => zero provider operation; after the
  adapter's dispatch call => **not** proof of remote cancellation.
- Lost acknowledgement => UnknownCommitState with ReconcileBeforeRetry.
- Post-dispatch wrong target or output => UnknownCommitState.
- Fake concurrent requests remain scoped and retain individual evidence.
- No dependency on Tokio, SDK credentials, blocking device access or network.
- Crate remains `publish = false`; no auto-publishing workflows are added.

Run from the repository root:

```sh
cargo fmt --all -- --check
cargo check --workspace --all-targets --all-features --locked
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
cargo run --locked -p keymesh --example provider_contract
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps --locked
```

See [ADR-0002](../adr/0002-operation-and-failure-semantics.md),
[KM-04 capability contract](capabilities-v1.md), and
[test/provider_contract.rs](../../crates/keymesh/tests/provider_contract.rs).
