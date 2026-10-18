# keymesh

Provider-neutral typed key-provider interface for Rust, maintained by Lattix
Technologies Corp. Repository: https://github.com/LATTIX-IO/keymesh.

## Release status

The crates.io version **0.1.0** published on 2026-10-07 was a namespace
placeholder, not this functional implementation. This repository's SDK is
**not yet published**; the tentative functional prerelease is
**0.2.0-alpha.1**, pending authenticated registry-owner approval. Its
manifest retains `publish = false` until an expressly approved release PR.

## Supported behavior (software-only alpha scope)

- Typed key/provider/tenant identities, URI references and exact-version
  binding/capability admission through the checked asynchronous dispatcher.
- Explicitly enrolled `software-provider` feature (off by default) enables
  local process-memory Ed25519 generation, signing, verification and
  public-key export, with independent host-supplied policy authorization.
- Immutable version rotation, irreversible retirement with zeroized signing
  seed, historical exact-reference verification, CAS lifecycle transitions,
  typed policy decisions and optional fail-closed pre-dispatch audit callbacks.
- Independent packaged-crate consumer tested on Rust stable and Rust 1.85.

## Important limitations

No durable keys, production HSM/KMS/PKCS#11 implementation, live IAM, verified
hardware custody, FIPS validation, persistent audit log or provider fallback.
Keys are lost when the provider is dropped or the process terminates.
A host-generated `HostScope` is not proof of authenticated tenant identity.
Example allow/deny policy gates are for integration tests, not production IAM.

Run `bash scripts/test_packaged_consumer.sh` from the repository root to
validate the locally packaged crate. The protected workflow also creates
candidate CycloneDX SBOM and Sigstore/GitHub attestations without publishing.

For the full security model and release requirements, see:
https://github.com/LATTIX-IO/keymesh/blob/main/THREAT_MODEL.md
and https://github.com/LATTIX-IO/keymesh/blob/main/docs/releases/first-alpha.md.

## License

Dual-licensed under Apache-2.0 or MIT at your option. See `LICENSE-APACHE`
and `LICENSE-MIT`, included in the crate archive.
