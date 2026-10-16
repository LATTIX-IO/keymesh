# ADR-0002: Explicit crypto operations, credential boundary and failure outcomes

- **Status:** Accepted for implementation planning (KM-01 / FOSS-400); no runtime/provider implementation yet.
- **Date:** 2026-10-16
- **Applies to:** Future Keymesh Rust public API and all provider adapters.

## Problem

Providers perform different input transformations, cryptographic operations, authentication, retries, and lifecycle transitions. A single vague `sign()`, `encrypt()`, or `delete()` risks silent algorithm substitution, a double hash, authorization bypass, key-version drift, or a duplicate destructive action on retry.

## Decision

### Operation identity and data classification

Every request MUST contain an explicit typed operation and algorithm profile, including parameters and key usage. At minimum distinguish:

- `SignMessage`: raw message input. Provider hashing/prehashing behavior is declared for the particular algorithm and adapter.
- `SignDigest`: digest input with an explicitly named digest algorithm and length. No implicit second hash. For algorithms with specialized prehash behavior (including Ed25519ph or ML-DSA external mu variants), use *separate, correctly specified profiles*; don't generalize one vendor's `DIGEST` or `EXTERNAL_MU` semantics.
- `VerifyMessage` versus `VerifyDigest` as appropriate, including whether authorization was checked by provider or verification was local.
- `Encrypt`, `Decrypt`, `WrapKey`, `UnwrapKey`: distinct permissions/capabilities; a provider's use of the same underlying primitive does not make requests interchangeable. Bulk data encryption is an application/envelope layer, not a reason to misuse KMS payload-limited operations.
- `Encapsulate`, `Decapsulate`, `DeriveKey`: only if the provider declares exact supported algorithm/parameter sets; shared secrets use sensitive-memory handling.
- `Generate`, `Import`, `Rotate`, `Enable`, `Disable`, `ScheduleDelete`, `Recover`, `Purge`: explicitly scoped lifecycle operations; unsupported or irreversible semantics remain visible. No ambiguous `delete()`.

**Provider examples:** AWS KMS `Sign` differentiates `RAW` and `DIGEST` (and specific profiles can use `EXTERNAL_MU`); Microsoft Azure Key Vault `sign` signs a digest and uses a versioned key URI. No adapter may blindly copy input classification from one provider to another.

### Credential and authorization boundary

- The caller host authenticates users and supplies an *authoritative* tenant/namespace mapping. Free-form `OperationContext.actor_id` and `.tenant_id` are audit annotations, not identity proof.
- Credentials are obtained through explicitly configured host/adapter credential providers, never parsed out of `KeyRef`, CLI flags intended for logs, generic metadata, or PKCS#11 URI `pin-value`/`pin-source`.
- A configured mandatory policy hook that denies, errors, times out, or returns unknown prevents dispatch. Policy must see a safe resolved key/capability snapshot rather than private key bytes or authentication secrets.
- Provider-side authorization failures stay failures; no fall-through to another credential or weaker provider without explicit host approval and an appropriate new request.

### Lifecycle idempotency and cancellation

Model operation outcomes as:

```text
NotDispatched               # safe to retry the intended operation once conditions are fixed
ConfirmedSuccess            # provider confirmed completion
ConfirmedFailure            # provider confirmed failure without ambiguous commit
UnknownCommitState          # request may have executed remotely, including after local timeout
```

- Transport cancellation or dropped future is **not** remote cancellation confirmation.
- Idempotent read-only operations may be retried with bounded backoff/deadline when provider semantics allow. For generate, import, rotate and delete, retries require provider-supported idempotency tokens or a safe reconciliation read. Without evidence, return `UnknownCommitState` and require a new deliberate action after reconciliation.
- The adapter records whether the operation reached dispatch, the idempotency/reconciliation strategy and safe provider request ID, but does not invent a `NotDispatched` result after an unknown remote acknowledgement.
- Destruction/purge must not be submitted via alias or mutable active-version selector when exact scope is required; all irreversible operations need explicitly configured approval/safety policy.
- For provider operations that change alias/active version, cache invalidation must be version-aware and work under races, not merely TTL-based.

### Security fail-closed outcomes

| Condition | Outcome |
| --- | --- |
| Capability missing/unknown or operation does not match typed request | `UnsupportedOperationOrProfile`; no dispatch |
| Provider instance/tenant/namespace mismatch | `ScopeMismatch`; no dispatch |
| Required material or provider version not selectable | `UnsupportedVersionAssurance`; no dispatch |
| Alias changes after resolution | `IdentityChanged` or `CannotGuaranteeBinding`; no dispatch |
| External policy hook required but failed | `PolicyIndeterminateOrDenied`; no dispatch |
| Auth credentials unavailable/rejected | `Unauthenticated`/`AuthorizationDenied`; no provider fallback |
| Mutation timed out after possible submission | `UnknownCommitState`; do not assume rollback or safe retry |

Structured error variants above are design labels for KM-04/KM-05 to finalize. Exact Rust spelling is not part of KM-01. Errors and telemetry must not include PINs, access tokens, private key material, plaintext, or secret-bearing unfiltered provider replies.

## Alternatives rejected

- A generic `sign(bytes)` that guesses prehashing from input length: **rejected** (double hashing and confused signing profiles).
- Treat key wrap as normal encrypt/decrypt to simplify provider API: **rejected** (authorization and mechanism differences).
- Retry all cloud errors by default: **rejected** (duplicate remote mutations and unknown commit state).
- Treat cancelling the caller future as cancellation of HSM/cloud operation: **rejected** (not guaranteed by providers).
- Trust caller-supplied audit context for tenant isolation: **rejected** (host auth boundary violation).

## Verification obligations

- KM-04/KM-05: typed compile/negative tests, digest-length/profile check, explicit `RAW`/`DIGEST` semantics and operation mismatch.
- KM-06/KM-10/KM-13: no-dispatch assertions on policy denial, unknown assurance and provider downgrade.
- KM-18: fault-injection for transport timeout before/after send, ambiguous commit, duplicate rotate/delete, lost response and reconciliation.
- KM-03/KM-07: credentials/secret string rejection/redaction with adversarial formats.
- KM-14 to KM-17: provider-specific contract and opt-in live conformance evidence; no fake live claims.

## References

- AWS KMS [`Sign` API](https://docs.aws.amazon.com/kms/latest/APIReference/API_Sign.html)
- Azure Key Vault [`sign` API](https://learn.microsoft.com/en-us/rest/api/keyvault/keys/sign/sign?view=rest-keyvault-keys-2025-07-01)
- Vault Transit [API reference](https://developer.hashicorp.com/vault/api-docs/secret/transit)
- RFC 7512 [PKCS#11 URI Scheme](https://www.rfc-editor.org/rfc/rfc7512.html)
