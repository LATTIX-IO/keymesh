# KM-01 threat-to-test traceability and implementation handoff

Status: **normative planning**, not proof of deployed enforcement. The contract fixtures are a small executable *reference model* until the Rust implementation follows.

| Threats | Invariant | KM-01 reference fixture | Next Rust implementation tests |
| --- | --- | --- | --- |
| TM-01 alias rebinding | INV-02 | alias-swapped, alias-only, active-resolved | KM-02, KM-06, KM-09: dispatch spy sees no alias |
| TM-02 provider/namespace swapping | INV-01, INV-14 | wrong-provider, wrong-namespace, wrong-resource, wrong-logical-key | KM-02, KM-06: scope and ID mismatch without dispatch |
| TM-03 opaque AWS material revision | INV-03 | aws-stable, aws-no-exact, aws-material-metadata-only | KM-02, KM-16: live/mock capability and unselectable material |
| TM-04 Azure/Vault stale explicit version | INV-03 | azure-version, vault-version, wrong-version | KM-09, KM-14, KM-17: version pins and reject stale state |
| TM-05 provider downgrade | INV-04, INV-11 | hsm-missing, hsm-unverified | KM-06, KM-08: no fallback to software |
| TM-06 secret locators | INV-06, INV-07 | uri-secret | KM-03, KM-07: URI fuzzing, redaction tests |
| TM-07, TM-16 unknown commit/cancellation | INV-08, INV-09 | design decision ADR-0002 only | KM-05, KM-18: injection, request sent/lost acknowledgement |
| TM-08 untrusted audit labels/identity | INV-01, INV-07 | untrusted-host-scope, unauthorized | KM-02, KM-10: host scope binding |
| TM-09 prehash confusion | INV-05 | sign-input-mismatch | KM-04, KM-05, KM-16: RAW/DIGEST vector tests |
| TM-10 wrap vs encrypt | INV-05 | wrap-as-encrypt | KM-04, KM-05: explicit operation mismatch |
| TM-11 native handles | INV-02, INV-10 | native-handle-dispatch | KM-15: emulator, stale handles, native boundary |
| TM-12 fabricated protection | INV-11 | hsm-unverified | KM-04, KM-06: provenance-sensitive assurance matching |
| TM-13 malformed URI and resource exhaustion | INV-12 | uri-secret is limited example | KM-03, KM-19: corpus/property/fuzz/size bounds |
| TM-14 policy hook outage | INV-13 | policy-timeout | KM-10, KM-13: zero provider calls |
| TM-15 unauthorized export | INV-06, INV-07 | design decision ADR-0002 only | KM-07, KM-08, KM-14–17: export deny and secret wipe |

## KM-01 acceptance evidence

Run from repository root (Python 3.11+):

```shell
python3 -m unittest discover -s tests -p 'test_*.py' -v
```

- Every fixture includes an expected `allow`/`deny`, a TM threat identifier, and an explanation.
- The test oracle refuses to match weaker assurance, an unbound alias, unknown provenance, mismatched tenant/provider/key, unsupported operation form, or a secret-bearing public locator.
- Mutation tests explicitly downgrade assurance and substitute provider/namespace/resource identity to ensure the reference oracle rejects them.
- These tests do **not** exercise actual Rust cryptography/provider code, and no provider or material attestations are being represented as verified. Actual code coverage will be added at the specific implementation issues linked above.

## Open engineering decisions (KM-02/KM-05)

1. Final public Rust naming for assurance enums and exact-selector result variants.
2. Provider capability discovery and pinning API at the async boundary, including unavoidable TOCTOU hazards and version races.
3. Bound on identifier and URI size; exact normalization and canonical format rules (KM-03).
4. Whether explicit `MaterialVersionBound` is offered for provider versioned cryptography through a validated contract, or reserved for software/HSM providers with stronger revision guarantees.
5. Struct/version compatibility format and semantic error codes for `UnknownCommitState`/`UnsupportedVersionAssurance`.


## KM-06 fake provider-registry traceability (FOSS-407)

The Rust routing harness covers INV-01 (scope), INV-02/03 (concrete
version), INV-04/11 (no HSM/software downgrade), INV-08/09 (do not
reinterpret provider operation outcomes), and INV-13 (policy remains
mandatory). Tests reject cross-tenant allowed sets and duplicate registrations;
deny Unknown health/support; require exact FOSS-403 capability admission;
show deterministic multi-provider tie-break; and revoke a route while an
async capability read or policy decision is pending, with **zero crypto
dispatch**. These tests use no actual HSM, KMS, secrets or network clients.
Live adapter and remote revocation semantics remain out of scope.

## KM-05 fake-provider gateway test coverage (PR #12)

The following Rust cases exercise the checked no-dispatch gateway with an
in-memory spy. They are **not** evidence that a remote SDK or HSM enforces it.
Provider and policy reads are allowed before policy decisions; the enforced
zero-dispatch property refers specifically to cryptographic/lifecycle calls.

| Threat/invariant | New fake-provider tests | Enforced property / remaining work |
| --- | --- | --- |
| TM-01 / INV-02 alias / rebound key | stale_exact_version_or_rebound_resource_is_not_dispatched | No changed concrete version/resource reaches the operation method; backend TOCTOU still KM-06/09 |
| TM-02 / INV-01 tenant/provider substitution | mismatched_tenant_or_provider_is_rejected_before_any_provider_query; catalog_provider_or_namespace_swap_is_not_dispatched | Authenticated host scope and catalog scope must match |
| TM-03 / INV-03 opaque/unselectable version | unknown_capability_or_version_is_not_dispatched | No observed material revision upgraded to selectable key material |
| TM-05 / INV-11 fabricated HSM custody | verified_hsm_protection_is_not_replaced_by_provider_claim | Host validation and provider report must agree; neither is hardware attestation |
| TM-07/TM-16 / INV-08/09 unknown remote commit | unknown_commit_requires_reconciliation_even_for_timeout_or_lost_ack; dropping_pending_future_after_dispatch_does_not_confirm_cancellation | No auto retry and no claim of remote rollback; lost acknowledgement produces UnknownCommitState |
| TM-08 / INV-01 host audit labels | serialized_errors_outputs_and_correlation_are_redacted | Redacted errors and output Debug; correlation labels remain non-authoritative |
| TM-09 / INV-05 prehash/digest classification | payload_mismatch_and_digest_length_fail_before_query_or_dispatch | Actual bytes and declared digest must match; KM-04 provides precise algorithm semantics |
| TM-10 / INV-05 wrap/encrypt conflation | KM-04 algorithm_semantics regression; KM-05 discrete trait methods | Unsupported defaults; no operation translation or fallback |
| TM-12 / INV-11 unknown capabilities | unknown_capability_or_version_is_not_dispatched | Unknown/unsupported cannot authorize operation |
| TM-14 / INV-13 policy hook outage | denied_indeterminate_or_failed_mandatory_policy_never_dispatches | Denial, indeterminate, and policy error cause zero crypto operation calls |
| Provider output substitution | substituted_target_or_wrong_response_kind_after_dispatch_is_unknown_commit | Bad result evidence after possible side effect is ambiguous, not NotDispatched |
| Runtime neutrality / cancellation | future_dropped_before_first_poll_cannot_dispatch; simultaneous_requests_keep_scope_and_evidence_isolated | No Tokio dependence; simulated post-dispatch cancellation is not a remote confirmation |

To execute this harness (no SDKs, no network):

```sh
cargo test --locked -p keymesh --test provider_contract
cargo run --locked -p keymesh --example provider_contract
```

The test oracle has no cryptographic provider under test and cannot establish
real provider capability, HSM custody, FIPS compliance, safe native retries,
or key-material binding at the physical device. Those remain KM-06 onward.


## KM-07 bounded secret and credential callback evidence (FOSS-408)

This increment tests TM-06/INV-06,07 (secret-bearing metadata,
accidental diagnostic exposure), TM-08/INV-01 (provider/tenant/operation
scope), TM-13/INV-12 (secret allocation size/capacity bounds) and
TM-15/INV-06,07 (unapproved export and raw secret dispatch).

Rust `secret::tests` and `tests/credential_boundary.rs` cover move-only
ownership, explicit wiping and Drop using RustCrypto `zeroize`,
oversized/empty/excess-capacity rejection, static/redacted errors,
compile-fail Clone/Display/AsRef/serde attempts, exact
host/provider/tenant/operation checks, no credential-source callback after
policy Deny/Indeterminate/Error, rejected mismatched callback responses,
pending-future cancellation before source invocation and isolated
parallel fake requests. Existing KM-05 tests continue to prove that
`OperationInput::KeyMaterial` is rejected before provider dispatch.

All tests use synthetic placeholder credentials. They do not prove
physical erasure of allocator/OS/device memory, credential authenticity,
IAM authorization, HSM compliance or real cryptographic enforcement.
Future native adapters must close those gaps independently.


## KM-08 real Ed25519 software provider (FOSS-409)

The opt-in software provider adds a real Ed25519 primitive, without
pretending to establish hardware custody. RFC 8032 KATs (public key
and signature) plus negative tampering/wrong-key/signature tests
cover TM-09/INV-05 message-vs-digest confusion and signature fidelity.

Host-authorized targetless creation, exact version/custody checks,
KM-04 admission and KM-05 mandatory `PolicyGate` are exercised before
any keyed sign/verify/export operation. Tests cover TM-01/TM-02/TM-05
(alias/version/tenant substitutions and HSM-to-software downgrade),
TM-14/INV-13 mandatory policy outage, and TM-15/INV-06 private export
denial. Concurrent purge/name reuse while signing policy is pending
cannot switch material; duplicate creation races admit one key.
OS-CSPRNG generated private material remains under KM-07 zeroization;
no key bytes enter logs, audit objects, serialization or PR fixtures.
Provider registry must be explicitly enrolled; feature-off builds
remain available. This work is not FIPS/HSM/KMS certification.
