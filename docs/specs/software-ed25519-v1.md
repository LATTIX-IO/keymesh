# KM-08 — Explicit opt-in, ephemeral Ed25519 software provider

Status: FOSS-409, pre-release. The implementation is **not** an HSM, KMS,
PKCS#11 adapter, hardware enclave, key vault, FIPS-certified module, or
persistent signing service.

## Explicit software-only enrollment

The `software-provider` Cargo feature is disabled by default. Only an
embedding application that opts in can construct `SoftwareProvider`.
One instance is bound to exactly one host-selected `ProviderInstanceId`
and `ProviderNamespace`. An authenticated host must also explicitly enroll
it under KM-06 `ProviderRegistry` with verified `ProtectionClass::Software`
and `VersionModel::ProviderVersion`. No discovery or automatic fallback
to software is provided. KM-04 admission continues to reject HSM/TEE
protection requirements against this software provider.

The capability catalog reports only Ed25519 pure-message `SignMessage`,
`VerifyMessage` and `ExportPublic`, never SignDigest, import, wrap,
export-private, encryption, Ed448 or other algorithms. A message
can be empty (RFC 8032), with a bounded maximum of 1 MiB.

## Cryptography, randomness and secrets

The feature pins maintained RustCrypto `ed25519-dalek` 2.2.0 with
`zeroize` support and `getrandom` 0.2.17 for OS-sourced entropy.
No deterministic seed or static master key is present in production.
RFC 8032 known-answer seeds are confined to the unit test module.
Ed25519 internally hashes the original message; this is **not**
an external-prehash/digest-signing API.

Only the separate `SoftwareProvider::create` boundary may generate a key.
KM-05 `execute_checked` still rejects targetless Generate/Import and
unprotected `OperationInput::KeyMaterial`. The creation request requires
a matching host-scoped provider, software protection/version assurance,
an exact Ed25519 Generate intent, a previously unused logical-key name
and an independent `SoftwareLifecycleGate` Permit **before** OS entropy
is consumed or a secret buffer allocated. Denied/indeterminate/error
policy prevents generation.

OS entropy produces a 32-byte Ed25519 seed and an unguessable resource
and version ID. Private seed ownership is moved to the KM-07
`KeyMaterial` zeroizing type. RustCrypto temporary signing keys are
zeroized on Drop. `CreatedSoftwareKey` returns ONLY the exact
`KeyRef` and public 32-byte key. No private-key export or persistence.
At most 1024 live keys per process/provider; duplicate names fail.

## Existing-key execution and deletion

All SignMessage/VerifyMessage/ExportPublic calls MUST use the original
KM-05 `execute_checked` gateway, which independently validates tenant
and provider identity, exact KM-04 algorithm/capability/payload limits,
KM-02 concrete provider key/version and the mandatory `PolicyGate`.
The adapter verifies the pinned target **again** at the actual native
operation, including protocol/capability revision. It holds a synchronous
read lock during native crypto so a concurrent policy-authorized purge
cannot substitute the key mid-signature. Neither the read lock nor any
registry lock is held across an awaited host-policy callback.

The separate `SoftwareProvider::purge` method requires host lifecycle
policy and an exact prior provider-version reference; it never accepts
Active/Latest/stable-only aliases. KeyMaterial is zeroized when removed
and dropped. Re-creating the same logical name produces a fresh
CSPRNG-derived resource/version identity, so stale references cannot
silently sign using new material.

This is best-effort Rust-owned memory erasure, **not** protection from
swap, crash dumps, copied memory, DMA, compiler spills or privileged
process access. Process restart loses all keys. No network retry or
remote ambiguous commit semantics apply to this synchronous in-process
adapter. The general provider contract retains UnknownCommitState for
future remote KMS/HSM implementations.

## Acceptance tests

- Two RFC 8032 pure Ed25519 public/signature known-answer fixtures,
  message tampering, wrong key, wrong/truncated signature, empty message
  and OS-CSPRNG-generated key sign/verify smoke.
- Correct 32-byte public key export and scoped operation evidence,
  with redacted Debug and no private key serialization.
- HSM and TEE hard requirements rejected with zero crypto execution,
  including AnyCompatible provider registry selection.
- Wrong tenant/provider/logical key/native version, mutable alias,
  unsupported Ed448/digest and oversize messages rejected.
- Mandatory lifecycle and KM-05 policy denial/error/indeterminate
  prevent unauthorized generation/signing.
- Async policy-pending sign followed by purge and name recreation
  never uses the replacement key; concurrent same-name creation is unique.
- Tests and feature-off compilation run on Rust stable AND Rust 1.85;
  strict Clippy/rustfmt/rustdoc, RustSec audit, license/dependency
  policy, semver and publication guards remain mandatory.

```sh
cargo check --locked -p keymesh --all-targets --no-default-features
cargo check --locked -p keymesh --all-targets --features software-provider
cargo test --workspace --all-features --locked
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo run --locked -p keymesh --features software-provider --example software_ed25519
```

Publication remains disabled by `publish=false`. No actual HSM,
remote secret backend, compliance certification or production readiness
claim is made. Rotation, durable key lifecycle, algorithms beyond pure
Ed25519 and extra platform controls belong to subsequent increments.
