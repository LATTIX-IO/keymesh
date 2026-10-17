# keymesh

`keymesh` is the planned provider-neutral key-management Rust library maintained
by Lattix Technologies Corp.

Repository: https://github.com/LATTIX-IO/keymesh

## Status

**Unreleased bootstrap.** A runtime-neutral provider interface, explicit
provider registry, and bounded secret/credential callback contracts exist, but
no production provider adapter, hardware-backed cryptography or live credential
service is included. The `software-provider` feature enables only ephemeral,
software-only Ed25519 signing/verification without HSM fallback. The crate explicitly declares `publish = false`; nothing in this package
should be interpreted as a published, security-assessed key-management library.

See the [repository README](../../README.md) for the release-safety guard,
non-publishing manual preview, development commands, and future release approval
requirements.

## License

Licensed under either Apache-2.0 or MIT, at your option.

KM-09 extends the optional software provider with immutable Ed25519
versions, CAS-controlled rotation, Enable/Disable/ScheduleDelete and
host-policy-authorized exact-version purge, plus historical verification.
All in-memory keys are lost at process restart. See the
[KM-09 lifecycle contract](../../docs/specs/software-lifecycle-v1.md).
