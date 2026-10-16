# Keymesh threat model and security invariants

Status: **normative design baseline (KM-01 / FOSS-400); not implemented enforcement**  
Version: 1.0-draft (2026-10-16)  
Scope: provider-neutral Rust key management, from caller-supplied key requirements through provider selection, key-version resolution, cryptographic operations, lifecycle changes, and reporting.  
Related decisions: [ADR-0001](docs/adr/0001-key-identity-and-version-assurance.md), [ADR-0002](docs/adr/0002-operation-and-failure-semantics.md).

## System boundary

```text
APPLICATION (authenticates caller, supplies trusted tenant/provider scope)
    |  untrusted request, claimed actor/audit context, data
    v
KEYMESH CORE (validate -> select permitted provider -> resolve -> bind -> authorize -> dispatch -> evidence)
    |                    |                    |
    |                    |                    +-- optional external policy evaluator
    |                    +-- host credential supplier; no credential in KeyRef
    v
PROVIDER ADAPTER (software in-process / PKCS#11 native boundary / remote SDK)
    |
    +-- software memory | HSM/token | cloud KMS | Vault Transit
```

Keymesh does **not** authenticate the human/application caller, grant enterprise IAM access, assert tenant identity based on an opaque audit label, certify FIPS compliance, secure untrusted native modules merely by forbidding Rust `unsafe`, or guarantee that remote operations stop when their local future is dropped. Those responsibilities require external trust anchors and explicit evidence.

## Assets and security objectives

| Asset | Required property |
| --- | --- |
| Private, symmetric and derived key material | Confidentiality; controlled import/export; bounded lifetime; redacted logs/errors |
| Provider credentials and PKCS#11 login material | Non-disclosure; explicit host/adapter ownership; no embedding in public references |
| Provider instance and tenant/namespace identity | No substitution or cross-tenant confusion; validated trusted origin |
| Logical key, native resource and concrete version binding | No implicit alias rebinding; no fabricated immutable material revision |
| Algorithm, operation, parameters and key usage constraints | Exact semantic matching; no downgrade or double hashing |
| Crypto result and lifecycle mutation outcome | Correlatable, appropriately qualified evidence; explicit unknown-commit state |
| Provider capability and protection claims | Truthful source attribution; no upgrade of unknown/provider-reported metadata to independently verified assurance |
| Import material and serialized references | Resource-bounded parsing and validation; no injection, traversal or spoofed identifiers |

## Attacker capabilities, trust boundaries and exclusions

- An untrusted or compromised **caller** can submit malformed key selectors, conflicting tenant labels, aliases, excessive payloads, unsupported profiles, import material and forged audit context. The host must bind authoritative tenant/provider access, independently of these labels.
- A partially compromised **configuration plane** can alter provider registration and aliases. Hard requirements must remain fail-closed and calls must dispatch to the resolved stable identity (or refuse execution), not re-evaluate a mutable alias in an unprotected window.
- A compromised **cloud/Vault endpoint, SDK, or credential supplier** can return misleading metadata or errors. Keymesh reports provider-supplied claims and cannot cryptographically validate them absent independent attestation. Do not represent successful network I/O as independently verified trust.
- A malicious **PKCS#11 native library** may read process memory or trigger memory-safety defects outside Rust; production isolation/allowlisting and code-signature validation are deployment responsibilities. `#![forbid(unsafe_code)]` in the Rust wrapper alone does not eliminate native risk.
- A local attacker with control over **process memory, kernel or host identity** is outside the protection guarantees of a software-only reference provider. Zeroization is best effort for Rust-owned buffers; cannot prove removal of SDK, allocator, swap or hardware copies.
- Network attacker and compromised provider may trigger **timeouts, rate limits, replay, duplicate request execution** and unknown commit state; do not assume a cancelled future cancels remote work.

## Normative invariants

- **INV-01 — Scope binding.** Require authoritative provider instance and namespace/tenant scope before resolving or dispatching a key. Claimed `actor_id`/`tenant_id` audit context is untrusted unless the host explicitly binds it to authenticated principal context.
- **INV-02 — Stable dispatch.** An `Active`, `Latest`, name or alias selector may be an *input*, but an operation requiring stable identity must dispatch using a provider-supported non-alias reference and report that concrete resource. An unresolved/rebound alias cannot serve as exact key evidence.
- **INV-03 — Material guarantee accuracy.** Distinguish provider resource identity, provider-issued version identity and an operation-bound **material revision**. Provider metadata or rotation history alone never upgrades an opaque material revision to exact selection capability. Exact-material requests fail closed when not demonstrable.
- **INV-04 — Provider downgrade refusal.** Hard algorithm, residency/protection, provider, region/partition and version constraints cannot be weakened to find an available backend. No HSM-to-software fallback.
- **INV-05 — Capability congruence.** Requested algorithm *profile*, parameters, data kind and operation must agree with the provider's declared support. `SignMessage` and `SignDigest`, and `WrapKey` and `Encrypt`, are distinct; no implicit conversion.
- **INV-06 — Secrets boundary.** No private key bytes, shared secrets, decrypted data keys, PINs, cloud credentials or bearer tokens in `KeyRef`, canonical URI, `Debug`, `Display`, diagnostics, metrics or audit evidence. Redaction failure is a security defect.
- **INV-07 — Credential authority.** Credential acquisition/rotation belongs to host/adapter. Authenticated credentials, not caller-supplied audit attributes, determine authorization. Unavailable/expired credentials do not cause silent credential or provider substitution.
- **INV-08 — Destructive mutation.** Rotation, import, delete, purge and other mutable operations require explicit bounded scope and host approval policies. Losing an acknowledgement after dispatch is `UnknownCommitState`; retry only when idempotency/reconciliation guarantees are established.
- **INV-09 — Cancellation truthfulness.** Cancellation of Rust future/HTTP connection cannot be described as successful provider cancellation unless provider confirms. Preserve started/unknown/completed distinctions.
- **INV-10 — Sensitive material lifetime.** Sensitive typed wrappers should avoid implicit clones or formatting; zeroize owned memory when feasible and document remaining copies and impossibility of guaranteed eradication.
- **INV-11 — Honest protection metadata.** HSM-backed, managed HSM, FIPS and attestation are sourced claims with provenance and confidence. Unknown or self-asserted class cannot satisfy a mandatory verified requirement.
- **INV-12 — Resource bounds.** Public identifiers, URIs, key imports, payloads, error strings, metadata and concurrency must be size-bounded; malformed encodings/duplicate ambiguous fields are rejected.
- **INV-13 — Policy hook fail-closed.** When a host installs mandatory Cryptopolicy/authorization hooks, an absent, failed, indeterminate or timed-out hook denies dispatch, not permit.
- **INV-14 — Evidence accuracy.** Every completed operation should record provider instance, namespace, stable resource, selected provider version if known, requested vs actual profile, and **qualified** material assurance. It must not claim actual key material version, verified tenant authorization, signature of audit proof, or HSM certification without evidence.

## Threat scenarios / downstream security tests

| ID | Threat / misuse case | Mandatory behavior | Implementation verification owner |
| --- | --- | --- | --- |
| TM-01 | Alias A changed from key X to Y between resolve and dispatch | Do not dispatch via mutable alias under stable-identity requirement | KM-02, KM-06, KM-09 |
| TM-02 | Provider or namespace swapped in returned metadata | Fail before dispatch and redact diagnostic | KM-02, KM-06 |
| TM-03 | AWS KMS stable KeyId with rotated underlying material is claimed immutable | Permit only stable-resource guarantee; deny exact-material | KM-02, KM-16 |
| TM-04 | Azure/Vault version reference mismatch or stale/deactivated version | Reject wrong or inactive version; do not switch to latest | KM-02, KM-09, KM-14, KM-17 |
| TM-05 | HSM requirement silently falls back to software | NoCompatibleProvider (no provider dispatch) | KM-06, KM-08 |
| TM-06 | PIN/token/secret appears in URI, error, logs or Debug | Reject or redact; do not persist in reference/audit | KM-03, KM-07, KM-15 |
| TM-07 | Duplicate create/rotate after timeout | UnknownCommitState, explicit reconciliation; no blind retry | KM-05, KM-09, KM-18 |
| TM-08 | Caller forges tenant and actor audit labels | Host authorization remains authoritative; no cross-scope use | KM-02, KM-06, KM-10 |
| TM-09 | Prehashed digest passed as raw message and hashed twice | Explicit input kind and algorithm contract; refuse mismatch | KM-04, KM-05, KM-16, KM-17 |
| TM-10 | `Encrypt` silently accepted as `WrapKey` | Refuse incompatible operation/capability | KM-04, KM-05 |
| TM-11 | Untrusted PKCS#11 library or stale native object handle | Module allowlist/isolation; no durable identity from handle | KM-03, KM-15 |
| TM-12 | Provider returns unknown protection or fabricated HSM claim | No upgrade to verified assurance | KM-04, KM-06, KM-12 |
| TM-13 | Malformed/key URI triggers traversal, credential interpolation or memory exhaustion | Strict bounded parse, no hidden credentials | KM-03, KM-19 |
| TM-14 | Required external policy hook unavailable or denies | Do not dispatch | KM-10, KM-13 |
| TM-15 | Secret material exported without explicitly supported capability and permission | Deny; safe sensitive material ownership | KM-07, KM-08, KM-14–17 |
| TM-16 | Cancellation after remote submit incorrectly reported as no-op | Unknown/not-confirmed semantics and safe reconciliation | KM-05, KM-18 |

`tests/fixtures/key_binding_contract_v1.json` and `tests/test_key_binding_contract.py` are **reference-model** adversarial fixtures for selected cases. They validate the intended decision semantics, not production Rust/provider enforcement. Actual integration, fuzz, fault-injection, live provider and runtime isolation tests are owned by the issues in the final column. Follow [traceability](docs/security/traceability.md).

## Development/release gates

1. No provider operation API may represent `KeyVersionId` as intrinsically immutable material until ADR-0001's different guarantees are modeled.
2. Before any software provider claims a supported algorithm, it must have known-answer vectors, negative tests and secure-memory handling appropriate to that provider.
3. PKCS#11 emulator tests and cloud mocks prove only fixture behavior; live-provider compatibility requires separate opt-in test evidence. Provider-reported security levels do not imply a FIPS validation of Keymesh.
4. Each PR must add executable negative/positive tests for its affected invariants, keep publication disabled until a separate approved release, and update the support/assurance matrix.

## Provider references (retrieved 2026-10-16)

- AWS KMS rotation and opaque material handling: https://docs.aws.amazon.com/kms/latest/developerguide/rotate-keys.html
- AWS KMS rotation detail listing (material IDs do not imply selection): https://docs.aws.amazon.com/kms/latest/developerguide/list-rotations.html
- AWS KMS aliases: https://docs.aws.amazon.com/kms/latest/developerguide/kms-alias.html
- AWS KMS Sign message kind: https://docs.aws.amazon.com/kms/latest/APIReference/API_Sign.html
- Azure Key Vault key rotation: https://learn.microsoft.com/en-us/azure/key-vault/keys/how-to-configure-key-rotation
- Azure Key Vault version-addressed Sign API: https://learn.microsoft.com/en-us/rest/api/keyvault/keys/sign/sign?view=rest-keyvault-keys-2025-07-01
- Vault Transit API (key_version constraints): https://developer.hashicorp.com/vault/api-docs/secret/transit
- PKCS#11 URI syntax/credential fields: https://www.rfc-editor.org/rfc/rfc7512.html
