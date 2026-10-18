# Keymesh first public alpha — controlled release checklist

**Status:** Readiness work, not approval to publish.

Proposed public version: `v0.1.0-alpha.1`. Current unreleased workspace version
`0.1.0` is not a published semantic compatibility contract. Any version
change and `publish = false` removal require a *separate* explicit maintainer
release PR, approved by an authorized release owner.

## Verified prerequisites

- [x] KM-09 version-safe ephemeral Ed25519 key rotation, irreversible
  retirement and historical verification merged with post-merge CI.
- [x] KM-10 typed decision policy and optional fail-closed pre-dispatch
  audit-gate merged with post-merge CI.
- [x] KM-11 isolated packaged-crate Rust consumer, stable/MSRV CI and
  software-provider-off negative test merged with post-merge CI.
- [x] Publication guard (`publish = false`) and manual-only read-permission
  release readiness workflow remain in effect.

## Outstanding before any irreversible registry release

- [ ] Verify `keymesh` crates.io name availability and reserve/confirm
  ownership by the intended Lattix publishing identity (no registry access
  or ownership verification has been performed).
- [ ] Final human audit of public API, safety docs, license notices and
  supported Rust targets, including independent cryptographic review.
- [ ] Produce and retain a standards-conformant SBOM (CycloneDX/SPDX) and
  review pinned dependencies, advisories and licenses for the exact release
  contents. `cargo metadata` alone is not an SBOM.
- [ ] Record the exact reviewed commit, package SHA-256, immutable signed tag
  and CI execution evidence, plus a verifiable provenance statement.
- [ ] Obtain explicit maintainer approval for package version,
  registry publisher identity, release credentials and protected workflow.
- [ ] In the **separate approved release PR**, enable `publish` only for
  authorized registry publication, with least-privilege scoped credentials;
  dry-run and verify exact package contents and provenance.
- [ ] After publication, verify registry version, docs.rs build, install
  from a clean external Rust project, artifact digest and release notes.
- [ ] Keep `v1.0` production conformance and all live HSM/KMS claims out of
  the initial alpha release.

## Evidence generation (safe, no publish)

```sh
bash scripts/release_candidate_preflight.sh
```

This script runs publication guard and negative tests, formatting, Rust
checks/Clippy/tests/rustdoc, packaged consumer acceptance, and outputs
candidate package and lockfile SHA-256 digests. It does not publish, tag,
upload, sign, attest, create an SBOM, or validate crates.io ownership.
The manually triggered GitHub workflow has `contents: read` only.
