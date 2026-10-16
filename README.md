# keymesh

Unified key-provider abstraction for software, HSM, PKCS#11, and KMS backends.

Maintained by Lattix Technologies Corp.

Project website: https://lattix.io

## Status

**Unreleased bootstrap.** No provider-neutral key-management API or provider adapter
is implemented yet. Public APIs will remain unstable until a deliberately approved
release. The `keymesh` crate is explicitly **not publishable** at this stage.

## Security and key-versioning design (KM-01)

The security baseline is specified in [THREAT_MODEL.md](THREAT_MODEL.md)
and the implementation decisions below:

- [ADR-0001: Key identity and material-version assurance](docs/adr/0001-key-identity-and-version-assurance.md)
- [ADR-0002: Crypto operations and failure semantics](docs/adr/0002-operation-and-failure-semantics.md)
- [Threat-to-test traceability](docs/security/traceability.md)

The [version-assurance fixture corpus](tests/fixtures/key_binding_contract_v1.json)
and its [reference decision tests](tests/test_key_binding_contract.py) describe
expected allow/deny decisions for cross-provider/tenant routing, alias races,
exact vs opaque key-material versions, credentials, and cryptographic operation
classification. These are **reference-model tests**, not deployed Rust/provider
enforcement or an HSM/KMS certification. Implementations in subsequent
increments must replay equivalent fixtures at their real operation boundary.

## Crates

- keymesh

## Development

Run:

    cargo fmt --all -- --check
    cargo check --workspace --all-targets --all-features --locked
    cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
    cargo test --workspace --all-features --locked
    RUSTDOCFLAGS='-D warnings' cargo doc --workspace --all-features --no-deps --locked

Publication guard checks (Python 3.11+; standard library only):

    python3 scripts/check_release_safety.py
    python3 -m unittest discover -s tests -p 'test_*.py' -v
    cargo metadata --workspace --no-deps --locked --format-version 1

`Rust CI` runs publication-policy checks, positive and negative regression
fixtures, and the Rust/security gates on every pull request to `main` and on
pushes to `main`.

## Publishing: blocked during bootstrap

Every workspace package must declare `publish = false`. In particular,
`crates/keymesh/Cargo.toml` is **not** registered for crates.io publication.
The prior `release-plz` action on pushes to `main` is disabled, registry/release
tokens are no longer referenced by release workflows, and release-plz GitHub
tag/release generation is disabled. An intentional `workflow_dispatch` run of
**Release readiness (non-publishing)** can execute a read-only workspace
metadata, compilation, and test preview. It cannot publish or create tags.

To authorize a future release, submit a **separate release PR** that:

1. Completes the public API, crate documentation, security and conformance tests.
2. Rechecks the exact package name and crates.io ownership, licenses, and dependency advisories.
3. Documents the release version, MSRV, changelog, feature/support matrix, and artifact provenance.
4. Establishes protected, explicitly approved publication credentials and release workflow; no ordinary push to `main` or Dependabot PR should publish.
5. Deliberately replaces/updates the bootstrap publication guard and changes `publish = false` only after reviewer approval and validation, then performs an independently checked packaging and installation test before registry publication.

The static guard detects publication enabled in Cargo manifests, known direct
publication actions, and unsafe workflow configuration. It does not establish
that arbitrary scripts or third-party actions are safe. Protected branches,
reviewed workflow changes, and least-privilege credentials remain necessary.

## License

Licensed under either:

- Apache License, Version 2.0
- MIT License

at your option.
