# Keymesh feature and conformance matrix

Status: FOSS-410 / KM-09 pre-release API baseline. This matrix reports
**implemented code contracts**, not a certified security product.

| Capability | Contract in Rust | Live provider implementation | Independent conformance |
| --- | --- | --- | --- |
| Typed provider / tenant / logical key / version selectors | KM-02, yes | No | KM-02 Rust fixtures only |
| Canonical KeyRef URI, secret-locator rejection | KM-03, yes | No | URI golden and adversarial vectors |
| RSA/ECC/AES/HMAC/HKDF + ML-KEM/ML-DSA/SLH-DSA taxonomy | KM-04, yes | No | Pure metadata regression tests |
| Typed operation/capability admission | KM-04, yes | No | Negative profiles and support intersection |
| Runtime-neutral asynchronous provider contract | KM-05, yes | Fake only | Object-safe std-future consumer |
| Checked provider, namespace and version binding before crypto | KM-05 gateway | Fake only | Spoofed provider, tenant, resource, version |
| Mandatory policy hook that fails closed on deny/error/unknown | KM-05 injection boundary | Fake only | No provider-op dispatch assertions |
| Provider operation success evidence | KM-05 metadata contract | Fake only | Exact target/output/category validation |
| Unknown commit, cancellation and conservative retry classification | KM-05 contract | Fake only | Before/after dispatch future cancellation |
| Side-effect-free provider capability/resolve reads | KM-05 required trait contract | Fake only | Adapter author obligation |
| Explicit provider registry / deterministic capability routing | KM-06, yes | Fake only | Scoped health/assurance, no fallback, removal races |
| Native health probe, circuit breakers or physical revocation | Not implemented | No | KM-18 and provider adapters |
| Bounded move-only secret/key material and explicit zeroize-on-drop | KM-07 Rust-owned bytes | No live adapter | Bounds, erase, redaction and compile-fail doctests |
| Host-approved provider/tenant/operation-scoped credential callbacks | KM-07 contract | Fake only | Denial/invalid-scope/mismatched-return regressions |
| Production credential broker, OS locked memory and native key import | Not implemented | No | Subsequent adapter/security increments |
| Feature-gated Ed25519 pure-message software sign/verify and public key | KM-08, yes | Ephemeral local-only | RFC 8032 KATs, scoped lifecycle and gateway tests |
| Immutable local software versions, CAS rotation, exact history, disable/enable/delete | KM-09, yes | Ephemeral local-only | Historical signatures, pending-policy rotation and alias race regressions |
| Durable lifecycle journal, multi-process state or clock-driven deletion | Not implemented | No | Future lifecycle hardening |
| RSA/ECDSA, Ed448, prehash and non-software providers | Not implemented | No | Later capability increments |
| PKCS#11 hardware modules or cloud KMS integration | Not implemented | No | KM-14–17 planned |
| Provider attestation and certified protection verification | Not implemented | No | Live validation needed |
| Mutating operation reconciliation / idempotency | Not implemented | No | KM-18 planned |
| Hardware-backed FIPS claims, latency/SLO benchmarks | Not validated | No | No claims |
| Publishing to crates.io | Explicitly disabled | N/A | publish = false guard |

KM-05 deliberately refuses AES-GCM encryption/decryption until typed nonce/AAD
contracts exist and refuses Generate/Import because no targetless key-creation
binding or secure input ownership exists. Optional methods default to
Unsupported rather than transparently retrying, mapping to software, or
claiming capability from a provider's self-reported HSM label.

A provider adapter MUST independently authenticate its configured caller,
verify real backend version/material selection and custody, and classify
remote commit state accurately. The Rust host-assurance constructor and
unverified provider capability catalog do not themselves attest any of these.

Related: [KM-07 secret boundary](sensitive-material-v1.md), [KM-05 provider contract](provider-contract-v1.md),
[KM-04 capability schema](capabilities-v1.md), [Threat traceability](../security/traceability.md).
