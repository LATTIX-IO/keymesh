# ADR-0001: Provider identity, key versions, and material-assurance truthfulness

- **Status:** Accepted for implementation planning (KM-01 / FOSS-400), pending Rust API implementation in KM-02/KM-05.
- **Date:** 2026-10-16
- **Decision owners:** Keymesh core / provider-adapter maintainers
- **Compatibility impact:** Normative for future public KeyRef/ProviderCapabilities; no preexisting API to migrate.

## Problem

`LogicalKeyId`, cloud KMS Key IDs, provider version URIs, PKCS#11 object selectors, and internal cryptographic material rotations do **not** represent interchangeable identities. The original design requirement to identify every operation's *immutable key version* is only truthful where the provider can actually bind the operation to that version. AWS KMS rotating symmetric key material retains its KMS KeyId/ARN even though it can expose a list of material revisions; clients cannot universally request a particular underlying material revision for cryptographic operations. Azure Key Vault creates versioned key URIs; Vault Transit accepts explicit key versions for particular operations. These facts require separate types/assurance semantics.

## Decision

### 1. Identity dimensions

A typed reference will distinguish these concepts (names illustrative; KM-02 settles the exact Rust spelling):

| Identity | Meaning | Trust requirement |
| --- | --- | --- |
| `ProviderInstanceId` | Explicit Keymesh adapter instance; never inferred from key name | Bound to host registration |
| `ProviderNamespace` | Authoritative tenant/account/partition/vault/region scope | Validated against trusted host configuration and provider credentials |
| `LogicalKeyId` | Application-controlled stable key/group name, may have active version | **Not** itself a physical key version |
| `ProviderResourceId` | Durable provider-native resource identity, e.g. AWS KMS Key ARN | Must not be mutable alias or ephemeral object handle |
| `ProviderVersionId` | Provider-addressable version under resource, e.g. Azure key version or Vault Transit key_version | Verified as target of the specific operation, where supported |
| `MaterialRevisionId` | Provider-observed cryptographic material revision ID | Metadata alone may not allow operation selection/pinning |

All identity comparisons are at least `(provider_instance, authoritative_namespace, provider_resource_id)`. Cross-provider and cross-namespace collisions are never merged. Provider locator values are opaque and never contain credentials. `KeyVersionId` in the final public API must not imply cryptographically immutable material if the provider only provides resource identity.

### 2. Assurance categories (not interchangeable)

- **`MaterialVersionBound`**: the provider supports a caller-addressable material revision for the specified operation, explicitly binds execution to it, and returns adequate operation identity evidence. This is a strong *contractual/provider-reported guarantee*, not independent attestation of actual HSM material.
- **`ProviderVersionBound`**: the provider accepts a concrete, immutable-for-identity provider key version and executes using that version. It must not imply that Keymesh has independently verified physical backing material. Upgrade to `MaterialVersionBound` only with a documented provider-specific guarantee that selection pins material for that operation.
- **`StableResourceBound`**: execution is pinned to a stable provider resource ID, but backing cryptographic material may be provider-managed and rotate beneath that resource ID. A stable ARN is not a material-version identifier.
- **`AliasOrNameOnly`**: a mutable alias/logical-name mapping remains at provider dispatch. Not sufficient for callers that require stable identity. Attempt to resolve through the adapter to a stable resource; otherwise deny.
- **`Unknown`**: insufficient evidence or unsupported operation/version semantics. Not upgraded by caller assertions, guessed versions, timestamps, metadata history, or a provider-reported HSM label.

These classes are guarantees **for an operation and configured provider profile**, not universal provider brand attributes. Required assurance matching is *monotonic*, with `MaterialVersionBound` meeting version requirements (when the requested material revision is exact and matched), `ProviderVersionBound` meeting concrete resource-version requirements, `StableResourceBound` meeting only stable-resource requirements, and `Unknown`/`AliasOrNameOnly` never meeting stable or exact requirements.

### 3. Selection contract

The public selector needs the semantic equivalents of:

```text
ExactMaterialRevision(provider material revision) # only if adapter supports selection
ExactProviderVersion(provider version)
StableResource(provider resource ID)
ActiveLogical(logical key)                 # must resolve to concrete resource/version
LatestLogical(logical key)                 # explicit nondeterministic input, not evidence
```

A strong selector **must not** silently degrade to `Latest`, `Active` or stable-resource-only binding. A weak selector may be resolved and then bound to stronger identity when supported. Preflight resolution and actual dispatch must bind the *same resolved resource/version*, not re-submit a mutable alias. If the provider cannot pin the requested guarantee, return structured `UnsupportedVersionAssurance` / `IdentityChanged` before dispatch.

The provider adapter must document whether atomic/verified alias resolution is possible; a read-then-dispatch race that still sends an alias is unacceptable when a stable identity is required. Rechecking after the fact does not undo an unintended cryptographic operation.

### 4. Operation evidence contract

For every completed cryptographic operation, record (safe/redacted fields only):

```text
provider_instance
validated_namespace
logical_key_id (optional display/reference)
stable_provider_resource_id
provider_version_id (when actually used)
material_revision_id (only if provider actually reports it)
material_revision_selection_supported (bool)
version_assurance (one of the categories above)
requested_selector, requested_assurance, resolved_binding
operation + typed algorithm profile
provider_request_id (only if safe), caller_correlation_id (untrusted)
outcome: confirmed_success | confirmed_failure | unknown_commit
```

An observation of `ListKeyRotations` output, an alias name, a provider-reported protection label, or a latest-key metadata read cannot by itself supply the binding evidence for an already-executed request.

### 5. Provider-specific baseline

| Provider/configuration | Default modeling consequence |
| --- | --- |
| Explicit in-memory software key version | `MaterialVersionBound` when the same immutable entry is used for dispatch and evidence (after KM-08/KM-09 implements that contract). |
| Azure Key Vault / Managed HSM | Key version URIs are addressable for supported operations; model at least `ProviderVersionBound`. Only claim stronger material guarantee per documented operation/profile, not by platform name alone. |
| Vault Transit | Named key supports `key_version` for supported encrypt/sign operations, subject to minimum versions and key state; version-dependent operations must pin and record the requested version. |
| AWS KMS key ARN with provider-managed symmetric rotation | `StableResourceBound` for operations using the resolved KeyId/ARN. Rotation material IDs may be observed via `ListKeyRotations`, but not assumed caller-selectable. Deny `ExactMaterialRevision` even if a matching material ID is visible in metadata but not usable to constrain dispatch. |
| AWS KMS alias | Resolve to KeyId/ARN; do not dispatch alias for requests requiring stable binding. Alias policies may differ when KeyId is substituted; surface authorization incompatibility rather than using alias anyway. |
| PKCS#11 | Native handles are ephemeral; persistent identity requires token/module/slot/object attributes and an adapter validation strategy. RFC 7512 can express public resource selection, but `pin-value`/`pin-source` must be excluded from loggable public KeyRef. Material immutability/versioning is NOT inferred from identical object IDs alone. |

**Important 2026 AWS nuance:** AWS may enumerate material identifiers, rotation dates and states, but the existence of an identifier does not demonstrate that a cryptographic request can pin a particular material revision. Keep **observability** separate from **selectability**.

### 6. Trust and rejection rules

1. Tenant/audit labels alone are not authorization or cryptographic isolation. Keymesh must compare provider scope with host-validated tenancy and reject mismatched identities.
2. An ambiguous, insufficient or provider-declared unknown assurance fails any corresponding hard requirement (`Deny`, not automatic fallback).
3. Observed `provider-reported` protection cannot be silently promoted to an independently validated HSM/FIPS attestation.
4. Cache keys include provider instance, namespace and concrete provider resource/version; alias-resolution cache invalidation must preserve the stable dispatch invariant.
5. Operation response evidence records the **actual** bound level; no fictional version/revision created for convenience.
6. On a provider change, namespace mismatch, missing confirmation or loss of version support, the operation refuses execution rather than using the newest available material.

## Alternatives rejected

- Treat every `KeyVersionId` as immutable key material irrespective of provider: **rejected** because AWS KMS resource and key material rotation semantics differ.
- Make a material revision from rotation timestamps or observed material ID: **rejected** because observing a revision is not pinning its use.
- Perform cryptography on alias, then confirm identity after completion: **rejected** because security-critical work may have occurred on the wrong key.
- Degrade a required HSM/exact-version operation to a software or resource-only provider: **rejected** as silent policy downgrade.
- Treat a provider's FIPS/protection claim as Keymesh certification: **rejected** absent independent validation.

## Verification plan / traceability

- Before KM-02: run the reference fixture harness `python3 -m unittest discover -s tests -p 'test_*.py' -v` for expected cross-tenant, wrong-provider, exact-versus-opaque material, alias and version mismatch decisions. **This tests the contract model, not the Rust enforcement path.**
- KM-02 / KM-03: implement Rust types + canonical parser with negative/collision/fuzz tests matching these fixtures.
- KM-05 / KM-06: execute fake provider operations and prove no dispatch on a failed guarantee, hard provider requirement, alias race or wrong scope.
- KM-09/KM-14/KM-16/KM-17: provider-specific rotation/version conformance, including actual operation correlation and live-provider evidence profiles.

## References (checked 2026-10-16)

- AWS KMS [Rotate AWS KMS keys](https://docs.aws.amazon.com/kms/latest/developerguide/rotate-keys.html)
- AWS KMS [List rotations and key materials](https://docs.aws.amazon.com/kms/latest/developerguide/list-rotations.html)
- AWS KMS [Aliases in AWS KMS](https://docs.aws.amazon.com/kms/latest/developerguide/kms-alias.html)
- Azure [Key rotation in Key Vault](https://learn.microsoft.com/en-us/azure/key-vault/keys/how-to-configure-key-rotation)
- Azure [Version-addressed sign API](https://learn.microsoft.com/en-us/rest/api/keyvault/keys/sign/sign?view=rest-keyvault-keys-2025-07-01)
- Vault [Transit API](https://developer.hashicorp.com/vault/api-docs/secret/transit)
- IETF [RFC 7512: PKCS#11 URI Scheme](https://www.rfc-editor.org/rfc/rfc7512.html)
