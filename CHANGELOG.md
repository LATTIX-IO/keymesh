# Changelog

All notable changes to this project will be documented in this file.

The project follows Semantic Versioning once its public API reaches a stable contract. Pre-1.0 releases may evolve more rapidly, with breaking changes documented here.

## [Unreleased]

### Added

### Changed

### Fixed

### Security

## Pre-release alpha scope (candidate; not yet published)

- Typed provider, tenant and key identity with version-safe URI encoding.
- Explicit provider registry, capability negotiation and fail-closed dispatch.
- OS-CSPRNG Ed25519 software keys behind opt-in feature, including immutable rotation,
  irreversible private-key retirement and exact historical signature verification.
- Optional typed host policy decision and pre-dispatch redacted audit sink.
- Standalone packaged-crate consumer proving public API, policy denial and
  feature-off behavior on supported Rust versions.

### Explicit limitations

No persistent or HSM-backed keys, live Vault/cloud adapter, hardware custody
attestation, FIPS validation, durable audit store or automated release publishing.
Private keys are process-local and lost on restart.
