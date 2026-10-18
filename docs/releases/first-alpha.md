# Keymesh first public alpha — controlled release checklist

**Status:** Readiness work, not approval to publish.

**Registry baseline:** `keymesh` **0.1.0** was published to crates.io on
2026-10-07 as a namespace placeholder referencing `LATTIX-IO/keymesh`. That
published placeholder is not the current functional SDK. Repository links do
not authenticate current registry ownership.

**Proposed first functional prerelease:** `0.2.0-alpha.1`, pending explicit
maintainer and registry-owner approval. The formerly proposed `0.1.0-alpha.1`
precedes the already published `0.1.0` in SemVer precedence and must not be
used. The workspace remains at `0.1.0` with `publish = false`; changing either
requires a separate approved release PR.

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

- [x] Registry namespace and bootstrap version `0.1.0` publicly observed.
- [ ] Verify authenticated crates.io owner list and confirm the designated
  Lattix release principal can publish a later version.
- [ ] Final human audit of public API, safety docs, license notices and
  supported Rust targets, including independent cryptographic review.
- [ ] Generate and retain a validated CycloneDX SBOM and review licenses,
  advisories and exact dependencies for the **approved final version**. CI
  now generates a CycloneDX 1.5 candidate and checks required fields;
  independent schema validation and a human license review remain.
- [ ] Record the final reviewed commit, package SHA-256, immutable signed tag,
  CI execution and cryptographically verifiable provenance. Provisional
  build/SBOM attestations from protected `main` are not final release evidence
  after a version change.
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
checks/Clippy/tests/rustdoc, packaged consumer acceptance and prints archive
and lockfile SHA-256 digests. It cannot publish, tag, sign or attest.

A separate `release-evidence.yml` workflow runs unprivileged packaging and
CycloneDX 1.5 SBOM generation on PRs and protected `main`, with 30-day GitHub
artifact retention. Its scoped OIDC/Sigstore signing job runs **only on main**;
untrusted pull-request code never receives write or signing permissions.
The existing manual release preview remains read-only.

Verify the resulting signed candidate archive using:

```sh
gh attestation verify keymesh-<candidate>.crate --repo LATTIX-IO/keymesh
```

These attestations cannot authorize publication and must be regenerated
against the final approved release version. Neither workflow authenticates
crates.io ownership or issues a release tag.
