# KM-09 — Logical key lifecycle, immutable versions and rotation

Status: **FOSS-410 pre-release**. Only the optional, process-local
`software-provider` Ed25519 adapter is implemented. No durable KMS/HSM,
persistent audit store, network replication, clock-triggered deletion,
certificate, hardware-backed custody or crates.io publication is implied.

## Security and concurrency invariants

1. A logical key is bound to exactly one independently authenticated
   `HostScope` (provider instance and tenant namespace). A Rust struct is
   **not** identity proof: the embedding host performs IAM first.
2. Each generated Ed25519 version has a CSPRNG-derived immutable
   `ProviderResourceId` and `ProviderVersionId`; material and public key
   never change for that identity. The newest version has its own metadata
   `latest`, which is **not** a synonym for an enabled `active` version.
3. At most one version per logical key is `Active`. A rotation permanently
   retires the prior version from signing, drops (zeroizes) that version's
   private signing seed, creates an independently seeded successor, and
   commits an atomic active-pointer change under the write lock.
4. Every lifecycle mutation is authorized by `SoftwareLifecycleGate` before
   randomness or state changes and compares the caller's observed
   `generation` again **after** asynchronous policy and while holding the
   write lock. A stale generation, missing version, wrong tenant/provider
   or mismatched exact target fails `NotDispatched`. The global generation
   counter increases on every committed mutation, including purge, and is
   never reset on logical name reuse in the same process.
5. KM-05 `execute_checked` remains the exclusive checked gateway for
   sign, verify and public key export. Only the separate software
   `create`/`rotate`/`transition`/`purge_with_evidence` APIs mutate
   lifecycle state; KM-05's `Generate`, `Import` and raw
   `OperationInput::KeyMaterial` remain unsupported.
6. `Active`/`Latest` are **read-only selectors** resolved to a concrete
   `DispatchTarget::ProviderVersion` before KM-05 policy. A
   `PreparedDispatch` carries that exact target AND the original selector
   so the native adapter can detect a changed active/latest pointer.
   The adapter never silently follows a new alias after a policy await.
   Native signing additionally requires that the pinned version is
   still the sole `Active` version. A retired version may verify a
   previously made signature only through its exact pinned reference
   and a separate successful KM-05 policy evaluation.
7. Disabled or pending-deletion versions cannot sign, verify or export
   their public keys. Neither a signed object nor a prior policy Permit
   silently re-enables a version. Policy denial, error and indeterminate
   states make zero cryptographic or lifecycle changes.
8. No provider fallback is introduced. `software-provider` is off by
   default, requires explicit host registry enrollment, and is never a
   substitute for HSM/TEE assurances.

## Finite-state model

| From | Action | To | Preconditions |
| --- | --- | --- | --- |
| Absent | Generate | Active | No existing logical name; lifecycle Permit |
| Active | Rotate | Retired + new Active | Exact current reference; matching CAS generation; cap available; Permit |
| Active | Disable | Disabled | Exact target, matching generation, Permit; active cleared |
| Retired | Disable | Disabled | Exact target, matching generation, Permit |
| Disabled | Enable | Active | Version was never retired; no other active version; matching generation, Permit |
| Retired | ScheduleDelete | PendingDeletion | Matching generation, Permit |
| Disabled | ScheduleDelete | PendingDeletion | Matching generation, Permit |
| Any existing state | Purge exact | Absent (that version) | Exact native version, independently authorized Permit; never an alias |

All other transitions return a statically classified error with
`OperationState::NotDispatched`. `ScheduleDelete` does NOT run a clock,
schedule asynchronous work, or automatically erase keys. Only a separately
approved `purge_with_evidence`/`purge` call drops the selected
`KeyMaterial`. The KM-08 exact active-version purge behavior remains
available for compatibility, but hosts should disable first.

A retired version cannot sign. Its public verification key and signed
historical evidence remain accessible only when the host permits the
exact-key verification request. Rotation immediately drops (zeroizes) the
retired version's Rust-owned secret material and retains public verification
metadata. Disable preserves permanent-retirement provenance, so a rotated-out
version cannot be re-enabled via Retired -> Disabled -> Active even after the
successor is disabled. Enable from Disabled requires that the version was
**never retired** and no other active version exists. PendingDeletion cannot
be re-enabled in this increment.

## Process-local storage and limits

Each `LogicalRecord` stores a version-indexed map of immutable targets,
each with a status and creation order. `SoftwareState` maintains an
in-process monotonic `u64` generation, total retained-version count and
logical records behind an `RwLock`. One provider instance supports up to
`MAX_SOFTWARE_KEYS = 1024` retained versions across all logical names,
and `MAX_SOFTWARE_VERSIONS_PER_KEY = 32` per logical key.

The global counter fails closed on overflow. Creation, rotation and
purge mutate memory under a **single** write lock, never spanning an
await. Native signature and verification hold a read lock to prevent
concurrent purge/disable/rotation from changing their pinned target.
A process restart loses all key versions, their generation counter,
and audit receipts unless the host persists the non-secret receipts
separately; neither durability nor distributed CAS is guaranteed.
Random resource/version values mitigate stale-key name reuse, but
do not provide a hardware attestation or durable anti-rollback proof.

## Public API and receipts

- `SoftwareProvider::snapshot(scope,host,key)`: bounded metadata,
  active/latest concrete references, immutable version references,
  lifecycle states and current generation. The host must independently
  authorize access to metadata; constructing HostScope is not IAM.
- `SoftwareProvider::rotate(policy, SoftwareRotateRequest)`:
  exact previous active reference, expected generation, Ed25519 Create
  intent, host scope and optional safe correlation label. Returns
  `SoftwareRotation` containing the new public key and concrete
  `CreatedSoftwareKey` plus `SoftwareLifecycleEvidence`.
- `SoftwareProvider::transition(policy, SoftwareTransitionRequest)`:
  typed Disable, Enable or ScheduleDelete and current generation;
  returns evidence describing the exact prior/current version, old/new
  states, committed generation and optional correlation.
- `SoftwareProvider::purge_with_evidence` uses the existing
  `SoftwarePurgeRequest` (explicit version and host scope) and returns
  the removal receipt. The KM-08 `purge` API remains available and
  delegates to this checked path. Both reject `Active` or `Latest` aliases
  as mutation targets.
- `SoftwareLifecycleEvidence` is not a signed audit log. It contains
  non-secret scope, logical identity, exact version references, state
  transition and monotonic generation, plus optional host correlation.
  Its `Debug` representation is always redacted. A trusted host must
  persist/sign it if external audit immutability or authenticity is
  required. No cryptographic key material is included.

## Threat tests and acceptance

The Rust tests exercise:
- Real OS-CSPRNG-created Ed25519 signature before rotation, exact
  historical signature verification after rotation, and old-version
  signing denial.
- Correct Active/Latest alias pinning, actual adapter recheck after
  awaited KM-05 policy, stale alias denial, changed state and exact
  version no-retarget behavior.
- Concurrent CAS rotations of the same observed generation, one
  success/no double active; pending policy followed by disable causes
  subsequent rotation to fail. No mutation on stale revisions.
- Active/Retired/Disabled/PendingDeletion state transitions, irreversible
  signing retirement after disable/enable sequences, no double active,
  exact-version purge and key-name
  reuse without old material resurrection.
- Credential-free exact tenant/provider/operation binding and
  independent policy Deny/Indeterminate/Error fail-closed behavior.
- Bounded 32-version historical retention, correct freeing of a slot
  only after exact purge, redacted snapshot/evidence formatting,
  monotonic generations, and lost-key behavior on process restart.
- Existing RFC 8032 vectors, KM-08 provider routing tests, KM-07
  secret ownership, KM-05 policy enforcement, and all prior regression
  suites remain mandatory.

```sh
cargo fmt --all -- --check
cargo check --workspace --all-targets --all-features --locked
cargo check --locked -p keymesh --all-targets --no-default-features
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
cargo run --locked -p keymesh --features software-provider --example software_rotation
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps --locked
```

Run the same feature-enabled suite and consumer with Rust 1.85. The
existing supply-chain checks (RustSec, dependency policy, semver),
bootstrap `publish = false` and review gates still apply.

No key-management system should treat KM-09 as a certified HSM/TEE,
durable system of record, distributed transaction log, trusted clock,
or independent source of policy and attestation. Cross-provider
rotation and migration are out of scope.
