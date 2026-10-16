# Keymesh KeyRef URI v1 — canonical wire contract

Status: **FOSS-402 / KM-03 pre-release contract**  
Version: **1**  
Scope: public textual key references only, not authorization or cryptography.

## Grammar

The URI authority is always the literal `v1` token (not a cloud host, username or provider).

```text
keymesh://v1/<provider>/<namespace>/<logical-key>/active
keymesh://v1/<provider>/<namespace>/<logical-key>/latest
keymesh://v1/<provider>/<namespace>/<logical-key>/resource/<resource>
keymesh://v1/<provider>/<namespace>/<logical-key>/version/<resource>/<provider-version>
keymesh://v1/<provider>/<namespace>/<logical-key>/material/<resource>/<provider-version>/<material-revision>
```

Provider, namespace, logical key, provider version, and material revision use
the existing distinct Rust identifier types. Each is ASCII `[A-Za-z0-9._-]`,
1–128 bytes, and neither `.` nor `..`. Case is significant and preserved.
Only lowercase `keymesh://v1/` is supported.

Resource is one percent-encoded path segment containing a validated opaque
`ProviderResourceId`, at most 1024 decoded bytes. The only unescaped
characters are RFC 3986 unreserved ASCII `[A-Za-z0-9._~-]`. Other bytes are
encoded as `%HH` (uppercase hex), including `:` → `%3A`, `/` → `%2F` and
`%` → `%25`. Redundant escapes and lowercase hex are noncanonical.
The complete URI is bounded at 4096 bytes.

Native locator checks forbid cloud presigned signatures (AWS X-Amz-Signature,
Azure SAS sig, and other secret-bearing fields) and reject nested percent
encoding before an adapter receives the reference. After the native locator's
single decode, control bytes, non-ASCII bytes and backslashes are rejected.
The sole narrow exception is percent-encoded binary octets within a terminal
PKCS#11 `id=` attribute, as required by RFC 7512; earlier PKCS#11 fields
cannot contain encoded controls. A credential must never be placed in any
provider-native resource, including one with misleading escaping.

**Unicode policy:** v1 intentionally accepts only ASCII identities and
decoded resource values. No Unicode normalization or case folding occurs.
Unicode/UTF-8 percent encodings are rejected, not silently converted into
a visually confusable tenant or provider identity. Any future Unicode
grammar requires a new version.

## Examples

```text
keymesh://v1/software-local/tenant-a/customer-data/active
keymesh://v1/software-local/tenant-a/customer-data/resource/software%3Acustomer-data%3A42
keymesh://v1/azure-prod/tenant-a/customer-data/version/https%3A%2F%2Fvault.vault.azure.net%2Fkeys%2Fpayments%2Fkey-v7/key-v7
keymesh://v1/hsm-prod/tenant-a/payments/resource/pkcs11%3Atoken%3DHSM1%3Bobject%3Dmy-key%3Btype%3Dprivate%3Bid%3D%2501
```

A PKCS#11 URI is provider-native opaque data **inside** the Keymesh resource
component, never a second spelling of the `keymesh://` scheme. Per RFC 7512,
`token=` identifies a token label; `pin-value=` and `pin-source=` are
credential-bearing and forbidden in public references. The outer URI contains
no credentials, userinfo, URL query, fragment, login fields, or native session
handle. Provider adapters must independently validate durable token/module
identity and permission to use it.

## Normative invariants

1. `KeyRef::from_str` accepts only canonical forms, and `KeyRef::to_string`
   emits one unique representation. Duplicate/extra selector segments,
   empty fields, ambiguous authority, raw URI delimiters, and invalid
   percent encoding are rejected. Native encoded `/` is data in one
   resource component, never a new tenant or selector segment.
2. Dot segments in identity fields and native provider resource paths
   are invalid, including their nested encoded forms. Scope fields may
   not use percent encoding to change provider or tenant identity.
3. Parsing does **not** authenticate or authorize a caller. The host must
   provide an independent authenticated `HostScope` to `preflight_bind`.
4. `active`/`latest` require provider-specific resolution before dispatch;
   neither is evidence of a concrete material revision. `version` requests
   a provider-addressable version. `material` requires a provider-supported
   caller-selectable material revision. No automatic downgrade.
5. Errors do not print the untrusted URI or source locator. The validator
   rejects known secret-bearing fields but cannot prove arbitrary user
   strings contain no secrets; secret material must never be supplied here.
6. The parser performs no provider lookup, I/O, credential management,
   signing, encryption, or release publication.

## Developer verification

```rust
use keymesh::KeyRef;
let uri = "keymesh://v1/software-local/tenant-a/signing/active";
let reference: KeyRef = uri.parse()?;
assert_eq!(reference.to_string(), uri);
# Ok::<(), keymesh::KeyRefUriError>(())
```

Use `cargo run --example keyref_uri` and the
[golden vectors](../../tests/fixtures/keyref_uri_v1.tsv).

The default Rust CI runs the golden fixtures, deterministic property
regressions, scope/material-downgrade negatives and the existing KM-02
tests. An isolated `fuzz/` crate provides the optional libFuzzer target:
`cd fuzz && cargo fuzz run keyref_uri` after installing `cargo-fuzz`.
No timed fuzzing claim is made without recorded evidence.

This contract extends [ADR-0001](../adr/0001-key-identity-and-version-assurance.md),
[ADR-0002](../adr/0002-operation-and-failure-semantics.md), and
the [threat model](../../THREAT_MODEL.md).
