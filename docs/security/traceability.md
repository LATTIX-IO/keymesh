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
