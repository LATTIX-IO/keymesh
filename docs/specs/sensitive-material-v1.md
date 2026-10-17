# KM-07 — Secret ownership and scoped credential callbacks

Status: FOSS-408 / KM-07, pre-release. **No live provider, vault, or secret store.**
This increment extends KM-05's provider operation boundary and KM-06's
explicit registry with zeroizing **Rust-owned** buffers and an explicit
host credential callback. It does not authorize native key operations.

## Owned secret representation

`SecretBytes` is a move-only, bounded wrapper around an owned `Vec<u8>`.
It requires a nonempty buffer with both length and allocation capacity
no greater than 65,536 bytes. `from_vec` takes ownership and does not copy
accepted data. Rejected vectors are zeroized before returning static
`SecretError` variants. A `Drop` implementation invokes the audited
RustCrypto `zeroize::Zeroize` primitive on the full owned Vec capacity,
including spare capacity, before releasing the allocation.
`erase(&mut self)` triggers the same primitive early and cannot refill
the buffer. `KeyMaterial` is a separate newtype for private key bytes
with identical ownership and bounds.

Neither type implements Clone, Copy, Display, Serialize, Deserialize,
Deref or AsRef. Debug uses a fixed redacted string and never formats
bytes, length or secret-derived metadata. `with_exposed` is intentionally
the only byte-view API: a synchronous closure receives a borrowed slice
for an explicitly audited consumer. A closure is still capable of copying
the bytes elsewhere or logging them. This is **not** a sandbox, and trusted
adapters must not persist, format, panic-dump or transitively copy secrets.
The public API's compile-fail rustdoc examples forbid accidental Clone,
Display, serde serialization and implicit slice conversion.

**Security limitations:** Zeroization is a best-effort property of the
particular Rust-owned allocation. It does not erase input copies created
before ownership transfer, register/stack spills, compiler/FFI copies,
memory maps, operating-system paging/swap, crash dumps, DMA, virtual-machine
snapshots, key material inside an HSM, cloud-provider memory, or data held
by a malicious callback. No OS memory locking or hardware attestation
is provided. `mem::forget`, process termination and manual unmanaged
allocation can defeat destructor-based guarantees. Safe Rust cannot
inspect already-freed memory to prove physical zeroization. Tests
exercise explicit wiping and ownership behavior; they are not forensic
memory-retention proofs.

## Credential callback and authorization boundary

`CredentialSource` has explicit immutable `provider()` and `namespace()`
identity methods and one asynchronous `acquire` method returning a move-only
`ScopedCredential`. The interface uses boxed std futures and deliberately
introduces no Tokio runtime, credential cache, discovery, IAM, cloud API,
KMS SDK or provider secret manager.

`CredentialRequest` names the exact independently host-approved
`HostScope`, configured expected provider instance and namespace,
`CryptoOperation`, validated `OperationIntent` and `CredentialPurpose`.
These host claims are not self-authenticating: the embedding application
MUST authenticate them independently. `CredentialAuthorization` is a
mandatory host callback returning `Permit`, `Deny` or `Indeterminate`.
The checked acquisition routine processes requests as follows:

1. Validate the independently specified scope/provider/tenant and
   operation/intent match, then structurally validate the operation.
2. Match the credential source's configured instance and namespace.
   Any mismatch fails before the policy callback or credential fetch.
3. Await host `CredentialAuthorization`; only explicit `Permit` proceeds.
   Denial, error, missing evaluation or `Indeterminate` denies before
   invoking the credential source. Authorization must be a separate
   independently enforced decision, not a provider's self-reported claim.
4. Revalidate configured source identity after await, then call
   `CredentialSource::acquire` exactly once. No retry, logging of backend
   error contents, fallback provider or credential discovery is allowed.
5. Match returned `ScopedCredential` scope, operation and purpose to
   the request, and reject empty/erased material. Wrong results are
   dropped, causing the owned secret to be zeroized. Error and Debug
   variants contain only fixed classification strings.

A credential callback is **not** an invocation authority for KeyProvider.
The host still must enforce KM-05's mandatory `PolicyGate`, KM-02 exact
concrete key binding, KM-04 capability/version admission and KM-06
registration/health leases before any cryptographic operation. A
credential may be acquired for an approved purpose but must NOT be
silently transferred to another provider, tenant or operation.

## Prohibited shortcut

KM-05 `execute_checked` still rejects `OperationInput::KeyMaterial`
before provider query or dispatch. The same remains true for
`Generate`/`Import` creation, the unresolved AES-GCM nonce/AAD boundary,
and restricted private export. A `KeyMaterial` instance is **not**
automatically cast or downgraded into a raw input slice for KM-05.
`ProtectedResultRef` remains opaque; no secret retrieval API is added.

Future native adapters must implement credential lifetime/refresh,
short-lived host authority, device-specific protection, key version
assurance, operation-specific input types and nonretriable remote
outcome handling. This increment makes none of those claims.

## Test and audit plan

- Owned Vec pointer remains unchanged on accepted move; no Clone.
- Empty/oversized input and excess capacity rejected; static errors.
- Explicit erase results in zero accessible bytes; idempotent.
- Redacted Debug and nonserializable/no-Display compile-fail doctests.
- Provider, tenant, operation or invalid-intent mismatch causes **zero**
  policy and credential-source callbacks.
- Deny, indeterminate and failed mandatory authorization cause **zero**
  source calls; no fallback.
- Wrong credential scope, purpose, operation or empty material rejected
  and dropped without secret bytes in error/Debug chains.
- A future never polled, or canceled during pending authorization, never
  reaches the credential source.
- Parallel requests cannot silently share credentials across scopes.
- Existing KM-05 raw-material denial and KM-06 no-fallback tests remain.

Run from the repository root:

```sh
cargo fmt --all -- --check
cargo check --workspace --all-targets --all-features --locked
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
cargo run --locked -p keymesh --example credential_boundary
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps --locked
```

This contract is not evidence of FIPS, hardware, memory-hardening or
cloud credential-system certification. `publish = false` is unchanged.
