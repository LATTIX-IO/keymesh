# Keymesh operation and provider capability contract v1

Status: KM-04 / FOSS-403, pre-release Rust contract.
Owner: Keymesh Rust library. Depends on ADR-0002 and KM-02/03 identity/version controls.
**Not** a cryptographic provider, primitive implementation, attestation verifier,
or Cryptopolicy policy evaluator.

## Security model

Admission takes only `OperationIntent` metadata and a provider-reported
`ProviderCapabilities` catalog, plus trusted-host corroboration supplied as
`HostValidatedCapabilities`. It does not execute cryptography or
authenticate the host. The host MUST independently verify tenant/provider
scope and protection/version claims. KM-05/06 adapters MUST run
`preflight_bind` against the concrete operation target and MUST NOT turn
the `Admission` result into proof of verified custody, actual material
revision, HSM certification, or successful signature.

A provider claim alone can never satisfy a HSM/TEE or selectable-version
requirement. Unknown or unreported support, unreported positive payload
bounds, conflicting entries, and unknown export constraints fail closed.

### Typed operation partitions

| Partition | Operations | Allowed parameterization |
| --- | --- | --- |
| Message signatures | SignMessage, VerifyMessage | RSA-PSS, ECDSA, pure EdDSA, pure/HashML-DSA, SLH-DSA |
| Digest signatures | SignDigest(digest), VerifyDigest(digest) | RSA-PSS and ECDSA only; digest name *and* length must match |
| Specialized signing | SignExternalMu, VerifyExternalMu | Explicit ML-DSA ExternalMu profile with 64-byte mu; never a generic digest |
| Encryption | Encrypt, Decrypt | RSA-OAEP, AES-GCM; require the matching message/ciphertext shape |
| Key wrapping | WrapKey, UnwrapKey | RSA-OAEP or RFC 3394/5649 AES-KW with a separate capability entry |
| MAC | MacMessage, VerifyMacMessage | HMAC; not a digital signature |
| Key encapsulation | Encapsulate, Decapsulate | ML-KEM; never general encryption |
| Key derivation | DeriveKey | HKDF; bounded `info` and output metadata |
| Lifecycle | Generate, Import, Rotate, Enable, Disable, ScheduleDelete, Recover, Purge | Independently authorized operation entries, not generic `Delete` |
| Export | ExportPublic, ExportPrivate | Distinct operations and explicit `ExportRequirement`; private export needs host approval |
| Extension | Namespaced Extension | Exact namespaced envelope with separate host opt-in; never inferred from an unknown family |

Each `CapabilityEntry` contains the **exact** full algorithm profile,
operation (including digest mode), supported/unsupported/unknown status,
and an optional reported upper input bound. A positive payload requires
a reported size limit. There is no conversion from SignDigest to
SignMessage, no wrap-as-encrypt fallback, no software fallback for HSM,
and no dispatch on Unknown.

### Algorithm parameterization

- RSA-PSS declares modulus length, digest, MGF1 digest and salt length.
  Minimum modeled RSA modulus is 2048 bits. The library checks structural
  salt bounds, not cryptographic implementation correctness or FIPS status.
- RSA-OAEP declares modulus, hash and MGF1 hash separately. The library
  applies the RSA-OAEP plaintext bound `k - 2*hLen - 2` and exact ciphertext
  length to the corresponding metadata. Separate wrap permissions remain
  mandatory even if an adapter uses the same RSA-OAEP primitive.
- ECDSA includes curve, digest and signature encoding (DER/P1363).
- Pure Ed25519/Ed448 are message-only. Ed25519ph is intentionally not
  treated as arbitrary `SignDigest(SHA-512)`; a future profile must specify
  its own prehash and domain-separated semantics.
- AES-GCM v1 requires explicit 128/192/256-bit key and 12-byte nonce,
  16-byte tag. AES-KW is separately tagged RFC 3394 or RFC 5649.
- HMAC and HKDF are independent algorithm families.
- ML-KEM parameter sets: ML-KEM-512, ML-KEM-768, ML-KEM-1024
  (NIST FIPS 203). These are **KEM**, not signature/encrypt aliases.
- ML-DSA sets: ML-DSA-44/65/87 (FIPS 204). Pure, HashMessage(digest)
  and ExternalMu are separate input modes. ExternalMu is
  provider-specific and is not semantically interchangeable with
  a supplied digest; adapters must implement profile-specific behavior.
- SLH-DSA: all 12 SHA2/SHAKE × strength × s/f parameter IDs specified
  in FIPS 205; only message signatures are modeled.
- Namespaced AlgorithmProfile::Extension preserves unrecognized
  vendor extension **identifier and parameters** across serde roundtrips
  but requires host opt-in. Unrecognized top-level algorithm/operation
  discriminators fail instead of silently becoming supported.

### Capability schema and trust

Canonical interoperable fixture:
`tests/fixtures/capability_schema_v1.json`.

The serialized provider catalog has a `schema_version`, protocol/feature
revisions, reported key protection, reported version selectability,
reported exportability, optionally *unverified* attestation claim refs,
and exact operation+profile entries. The current Rust API accepts JSON
via serde; the release schema is **versioned** and rejects unknown
top-level fields, incompatible schema numbers and duplicate entries.
Only the explicit `Extension` envelope permits unknown vendor values.

- `SupportStatus` = Supported / Unsupported / Unknown.
- `ProtectionClass` = Unknown / Software / Tee / Hsm.
- `VersionModel` = Unknown / StableResource / ProviderVersion / MaterialRevision.
- `Exportability` = Unknown / None / PublicOnly / Private.
- HostVerified capabilities are **caller-host assertions** and MUST be
  populated only after that host's independently trusted validation. The
  Rust constructor alone cannot verify the host or a vendor attestation.
- `ProviderCapabilities::intersection` conservatively intersects exact
  entries; it never promotes a missing profile, a weaker version model,
  different protection claim, unknown support, or unverified attestation.
  Intersection output contains **no** inherited attestation claims.
  Entries are stable-sorted for deterministic results.

No remote provider integration currently enforces these declarations.
Production enforcement must independently check the requested payload
shape, actual key version, tenant binding, cryptographic profile and
provider-reported capability again at the KM-05 dispatch boundary.
This is a declarative admission surface, not a compliance certificate.

## Scope limits and downstream handoff

- KM-05: provider trait accepts exact `OperationIntent` and capability
  snapshot; adapter must prohibit side effects on rejected admission.
- KM-06: routing must reject unknown/unverified custody and capabilities
  without downgrading to software.
- KM-08: software provider must only advertise exact implemented
  operations and must use maintained cryptographic implementations.
- KM-13: Cryptopolicy adapter maps explicit typed operations and
  protection requirements without trusting provider claims.
- KM-14–17: provider conformance verifies RAW/DIGEST, key wrap,
  PQC availability, custody and version selectability separately.
- KM-18/19: operational fault injection, fuzz and security evidence.
  No live provider, performance, FIPS or cryptographic claims follow
  from these metadata-only unit tests.

## Local acceptance commands

```shell
cargo fmt --all -- --check
cargo check --workspace --all-targets --all-features --locked
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
cargo run --locked -p keymesh --example capability_admission
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps --locked
```

Tests include the golden serde/API fixture, unknown extension roundtrip,
malformed/duplicate provider metadata, HSM claim substitution, negative
digest-vs-message cases, RSA-OAEP bounds, AES-KW/AES-GCM separation,
PQC operation compatibility, explicit export authorization, stable
capability intersection and deterministic mutation regressions.
CI must exercise both Rust stable and declared Rust 1.85 MSRV.

## Reference standards

- [NIST FIPS 203 — ML-KEM](https://csrc.nist.gov/pubs/fips/203/final)
- [NIST FIPS 204 — ML-DSA](https://csrc.nist.gov/pubs/fips/204/final)
- [NIST FIPS 205 — SLH-DSA](https://csrc.nist.gov/pubs/fips/205/final)
- [ADR-0002 — operation and failure semantics](../adr/0002-operation-and-failure-semantics.md)
- [KeyRef URI v1](keyref-uri-v1.md)
