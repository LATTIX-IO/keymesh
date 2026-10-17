# keymesh

Unified key-provider abstraction for software, HSM, PKCS#11, and KMS backends.

Maintained by Lattix Technologies Corp.

Project website: https://lattix.io

## Status

**Unreleased bootstrap.** Typed key identity/version, URI, crypto taxonomy,
checked async provider operations, explicit capability-based provider routing,
and bounded sensitive-material/credential callback contracts are implemented
and tested using fake providers. No real cryptographic backend, live KMS/HSM,
IAM system, independent assurance attestation or production credential store
is included. Public APIs are not release-stable and the `keymesh` crate
remains **non-publishable** until separate release approval.

## Security and key-versioning design (KM-01)

The security baseline is specified in [THREAT_MODEL.md](THREAT_MODEL.md)
and the implementation decisions below:

- [ADR-0001: Key identity and material-version assurance](docs/adr/0001-key-identity-and-version-assurance.md)
- [ADR-0002: Crypto operations and failure semantics](docs/adr/0002-operation-and-failure-semantics.md)
- [Threat-to-test traceability](docs/security/traceability.md)

The [version-assurance fixture corpus](tests/fixtures/key_binding_contract_v1.json)
and its [reference decision tests](tests/test_key_binding_contract.py) describe
expected allow/deny decisions for cross-provider/tenant routing, alias races,
exact vs opaque key-material versions, credentials, and cryptographic operation
classification. These are **reference-model tests**, not deployed Rust/provider
enforcement or an HSM/KMS certification. Implementations in subsequent
increments must replay equivalent fixtures at their real operation boundary.

## KM-02: provider identities and version assurance (implementation preview)

The `keymesh` Rust crate now contains a **pre-dispatch** binding contract. The following example validates a scope-qualified resource identity without performing a cryptographic operation:

```console
cargo run --example preflight
cargo test --workspace --all-features
python3 scripts/generate_km02_contract.py --check
```

Public APIs:

- `ProviderInstanceId`, `ProviderNamespace`, `LogicalKeyId`, `ProviderResourceId`, `ProviderVersionId` (`KeyVersionId`), `MaterialRevisionId`: distinct, bounded identifier types; strict ASCII labels; native locator validation rejects obvious secret-bearing fields and malformed encodings. Canonical KeyRef URI v1 parsing/formatting is available (KM-03). Native resource locators remain provider-specific and subject to separate adapter validation.
- `KeyRef` + `KeySelector`: logical reference distinct from `Active`, `Latest`, stable-resource, exact provider-version, and exact material-revision selectors.
- `DispatchTarget`: only concrete resource/version/material-revision targets; no mutable alias or native session-handle variant.
- `HostScope` and `preflight_bind`: compare host-authorized scope, requested logical key/resource, required assurance and concrete provider resolution; reject unsupported exact-version constraints instead of falling back.
- `ResolvedKey::with_observed_material_revision` explicitly records informational key-material revisions without claiming they are selectable. For example, AWS KMS material-rotation history does not satisfy `RequiredAssurance::MaterialVersion`.

### Scope and trust boundary

`HostScope::new` does **not** authenticate a caller or create IAM credentials. A host application must create it only after validating identity and provider tenancy. `ResolvedKey` is a **provider-supplied proposal**, not an HSM attestation; future adapters must verify actual provider capability, resolve mutable aliases to immutable dispatch handles, and pass the exact validated `DispatchTarget` into cryptographic execution. No provider implementations, IAM, key generation, or network calls exist in this increment.

Rust regression tests cover negative collisions, cross-provider/tenant substitution, material-version downgrades, stale Azure/Vault key versions, bounded inputs, secret-bearing PKCS#11 locators, and a standalone example. `scripts/generate_km02_contract.py` projects **14 identity-specific cases** from the KM-01 JSON fixtures into a generated `.inc` expression consumed directly by the Rust integration test. CI verifies this projection has not drifted; operation, policy, authentication and destructive-mutation cases remain owned by later increments.

Because these preflight checks require an adapter to honor the bound target, passing these tests is not proof that any remote cryptographic operation is secure.
## KM-03: canonical versioned KeyRef URI

KeyRef references can now be safely rendered and parsed as a canonical,
ASCII-only `keymesh://v1/` representation with explicit active, latest,
stable resource, provider-version, and exact material-revision selectors.
Opaque native provider locators are bounded and percent-encoded as single path
components. Untrusted URI strings are **not** credentials or authorization.

See [the normative v1 URI specification](docs/specs/keyref-uri-v1.md),
[golden and malicious vectors](tests/fixtures/keyref_uri_v1.tsv), and the
[parser tests](crates/keymesh/tests/keyref_uri.rs).

```sh
cargo run --example keyref_uri
cargo test --workspace --all-features
# Optional opt-in fuzz harness: cd fuzz && cargo fuzz run keyref_uri
```

The URI parser performs no I/O or cryptography. A parsed reference still
requires host-authorized `HostScope` and actual provider-side binding before
it can be used for an operation.

## KM-04: typed cryptographic operations and capability admission

Keymesh now exposes a declarative **operation/capability contract**, not
a cryptographic implementation. `CryptoOperation` explicitly separates
SignMessage vs SignDigest, key wrap vs encryption, KEM vs general encryption,
HMAC vs signatures, special ML-DSA external-mu signing, lifecycle permissions,
and public vs private export. `AlgorithmProfile` carries exact RSA, ECC, AES,
HMAC/HKDF and NIST PQC parameter sets. `PayloadDescriptor` contains lengths
and input classification only, **never key material or plaintext**.

`ProviderCapabilities::admit` requires an exact reported algorithm+operation
match with supported status, bounded input and independently host-corroborated
version/custody constraints. A provider's self-reported HSM claim or attestation
metadata is not proof of trusted custody. Unknown capability/assurance, mismatched
hash, unapproved private export and unknown extensions fail closed.
`ProviderCapabilities::intersection` is deterministic and conservative.

See the [schema and security contract](docs/specs/capabilities-v1.md) and
[golden JSON fixture](tests/fixtures/capability_schema_v1.json).

```sh
cargo run --locked -p keymesh --example capability_admission
cargo test --workspace --all-features --locked
```

The example performs no key generation, cryptographic operation, KMS request,
secret transmission, or real hardware attestation. Provider adapters and
enforcement remain KM-05/06 and later increments. The crate is still
`publish = false`.

## KM-07: owned secret buffers and explicit credential callbacks

`SecretBytes` and `KeyMaterial` accept ownership of bounded Rust Vec
allocations and use RustCrypto `zeroize` on explicit erase and Drop.
They cannot be implicitly cloned, serialized, formatted with Display or
converted to raw slices; Debug is always redacted. A deliberately invoked
`with_exposed` callback exposes a borrowed view only to trusted code
(which can still deliberately copy bytes).

The host-injected `CredentialAuthorization` and `CredentialSource`
contracts require independent provider/namespace/operation agreement
and explicit policy `Permit` **before** requesting a scoped credential.
Denied/unknown/error decisions invoke zero credential callbacks; wrong
returned scope/purpose or erased material is rejected. The library
does not implement IAM, a credential store, key rotation, live crypto
or OS-backed memory locking.

**KM-05 continues to reject raw `OperationInput::KeyMaterial`**. The new
wrapper does not enable unsafe import/wrap/export or substitute for the
KM-05 mandatory cryptographic policy. KM-06 provider routing still
rejects unverified HSM/custody claims and provider downgrade.

Read [KM-07 sensitive material specification](docs/specs/sensitive-material-v1.md).
Run the no-network consumer fixture:

```sh
cargo run --locked -p keymesh --example credential_boundary
cargo test --workspace --all-features --locked
```

## KM-06: explicit provider registration and capability routing

`ProviderRegistry` stores only explicitly enrolled, host-scoped providers,
never auto-discovers hardware/KMS devices or silently downgrades HSM protection
to software. Consumers select a named provider or **explicitly opt in** to
`AnyCompatible` among independently authorized tenant/provider scopes. Routes
admit exact KM-04 operations with known health, custody, version and bounds;
Unknown fails closed. Lexicographic tie-breaking is deterministic but not a
security recommendation.

A `RoutedProvider` carries a revocable lease. Its `execute` method preserves
KM-05's mandatory policy, exact identity/version binding and unknown commit
semantics. Registrations may be revoked concurrently, but cannot cancel
remote operations already sent. The host must independently validate health,
identity, HSM claims and tenant authority; mocks are not attestations.

Reference: [KM-06 provider registry](docs/specs/provider-registry-v1.md).

```sh
cargo run --locked -p keymesh --example provider_registry
```

## KM-05: runtime-neutral async provider contract

The crate now defines an object-safe `KeyProvider` trait returning boxed standard
Rust futures with required read-only capability/resolve methods and explicit
optional sign/verify/encrypt/decrypt/wrap/unwrap/MAC/KEM/derive/lifecycle
methods. Every optional method defaults to fail-closed Unsupported.
`execute_checked` is the central no-fallback gateway: host provider/tenant
binding, actual input-shape validation, exact KM-04 capability admission,
concrete KM-02 key/version preflight, mandatory host-policy callback, then
**one** operation dispatch.

The result contains concrete operation identity, exact resolved target,
binding assurance, sanitized correlation/receipt IDs, and confirmed success.
Errors distinguish NotDispatched, ConfirmedFailure and UnknownCommitState,
with conservative retry guidance. Provider claims are **not** independent HSM
attestations and cancellation of a local future does not cancel a remote
operation. No real provider backend, runtime, credential broker, key
import/export, or crypto execution is shipped.

Production sensitive material wrappers (KM-07), explicit real-provider
inputs (including AES-GCM nonces/AAD/tag), targetless key generation,
native provider adapters, and mutation reconciliation remain out of scope.
The crate remains `publish = false`.

Reference: [KM-05 design contract](docs/specs/provider-contract-v1.md).
Execute the deterministic fake-provider example:

```sh
cargo run --locked -p keymesh --example provider_contract
cargo test --workspace --all-features --locked
```

## Crates

- keymesh

## Development

Run:

    cargo fmt --all -- --check
    cargo check --workspace --all-targets --all-features --locked
    cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
    cargo test --workspace --all-features --locked
    RUSTDOCFLAGS='-D warnings' cargo doc --workspace --all-features --no-deps --locked

Publication guard checks (Python 3.11+; standard library only):

    python3 scripts/check_release_safety.py
    python3 -m unittest discover -s tests -p 'test_*.py' -v
    cargo metadata --workspace --no-deps --locked --format-version 1

`Rust CI` runs publication-policy checks, positive and negative regression
fixtures, and the Rust/security gates on every pull request to `main` and on
pushes to `main`.

## Publishing: blocked during bootstrap

Every workspace package must declare `publish = false`. In particular,
`crates/keymesh/Cargo.toml` is **not** registered for crates.io publication.
The prior `release-plz` action on pushes to `main` is disabled, registry/release
tokens are no longer referenced by release workflows, and release-plz GitHub
tag/release generation is disabled. An intentional `workflow_dispatch` run of
**Release readiness (non-publishing)** can execute a read-only workspace
metadata, compilation, and test preview. It cannot publish or create tags.

To authorize a future release, submit a **separate release PR** that:

1. Completes the public API, crate documentation, security and conformance tests.
2. Rechecks the exact package name and crates.io ownership, licenses, and dependency advisories.
3. Documents the release version, MSRV, changelog, feature/support matrix, and artifact provenance.
4. Establishes protected, explicitly approved publication credentials and release workflow; no ordinary push to `main` or Dependabot PR should publish.
5. Deliberately replaces/updates the bootstrap publication guard and changes `publish = false` only after reviewer approval and validation, then performs an independently checked packaging and installation test before registry publication.

The static guard detects publication enabled in Cargo manifests, known direct
publication actions, and unsafe workflow configuration. It does not establish
that arbitrary scripts or third-party actions are safe. Protected branches,
reviewed workflow changes, and least-privilege credentials remain necessary.

## License

Licensed under either:

- Apache License, Version 2.0
- MIT License

at your option.
