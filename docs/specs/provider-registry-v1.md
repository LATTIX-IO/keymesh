# KM-06 — Explicit provider registry and fail-closed capability routing

Status: FOSS-407 contract, pre-release and **not a live crypto/HSM integration**.
Depends on KM-05 / FOSS-404's checked provider interface, merged in PR #12.
This increment is an explicit host-controlled provider catalogue, not discovery,
identity management, a secrets broker, adapter health probe, automatic fallback,
policy evaluator or a cryptographic primitive implementation.

## Registration and host authority

`ProviderRegistry::register` requires an owned, explicitly supplied
`Arc<dyn KeyProvider>`, a previously host-authorized `HostScope` with a concrete
`ProviderInstanceId` and tenant namespace, corroborating
`HostValidatedCapabilities` for that exact scope, and an initial host-asserted
`ProviderHealth` (Unknown, Healthy or Unavailable). Registration rejects
duplicate instance IDs, mismatched instance/host assurance/tenant identity,
and registry overflow (128 providers maximum). A single provider-instance
registration is scoped to **one** host-authorized tenant. Configure independent
logical instances for any additional authorized tenant; the registry does
not automatically share an instance across tenancy boundaries.

HostScope is an explicit assertion by embedding application code, **not**
authenticated proof by constructing a Rust value. The host must independently
authenticate the user, tenant and configured provider; validate physical
custody/version semantics; and only then populate the registration. Reported
HSM/TEE attributes and a host-supplied Healthy flag do not establish a device
certificate. A provider's capabilities/resolve hooks must be side-effect-free.

`set_health` updates only a scoped registered instance; Unknown and Unavailable
fail closed for new routes. Registration does **not** imply healthy or
compliant. `unregister` revokes the local lease and removes future selection
eligibility. Removing an instance does not roll back real operations already
sent to the provider.

## Explicit selection modes

`ProviderRequirements` contains:
- a bounded, explicitly host-authorized list of `HostScope` entries for the
  **same** tenant namespace; mixing tenants or supplying no scopes is invalid;
- exact `OperationIntent` including operation, algorithm variant and parameters,
  version/protection/export assurance, and payload descriptor;
- `ProviderSelection::Instance(id)` for a specific instance with **no fallback**,
  or an **explicitly opted in** `AnyCompatible` mode.

For opt-in matching, candidate enumeration uses a `BTreeMap`, producing stable
lexicographic tie-breaking by validated ProviderInstanceId. This order is
not a declaration of safety, cryptographic strength, cost or provider quality.
Candidates are only considered if their scope appears in the independently
authorized set, the provider identity is unchanged, the host health is Healthy,
the catalogue is readable, and exact KM-04
`ProviderCapabilities::admit` succeeds for the requested profile,
operation, version selectability, protection and bounded payload. Unknown
support, unverified HSM/TEE, opaque material version, insufficient payload
budget and incompatible algorithms are never relaxed to permit routing.

A missing/disabled explicit provider is an error; it does **not** cause a
software/HSM or alternate-cloud fallback. An opt-in AnyCompatible request
may examine multiple already-approved candidates **before any crypto
dispatch**, but cannot retry a failed operation on another candidate after
dispatch. Routing performs no signing, key generation, encryption or
lifecycle mutation. There is no automatic network discovery or live adapter
bootstrap.

`RouteTrace` reports only counts by static rejection reason (scoped mismatch,
deregistered, unhealthy, read error, capability mismatch, assurance mismatch).
The optional `route_diagnostic` API returns `RoutingFailure` with the same
bounded trace on failure; `route` keeps its simpler static error enum.
Candidate enumeration and diagnostic counts include **only** host-approved
provider+tenant scopes; the existence of other tenants/providers is not
disclosed through routing statistics. Ordinary Debug on routed selections
and registry instances redacts provider, namespace and private paths. The application must treat the explicit
`RoutedProvider::instance` accessor as audit metadata requiring suitable
access controls.

## Concurrent removal and checked dispatch

Routing captures a short, bounded snapshot of explicit registration references
under a std RwLock. **No lock is held across an async provider read.** Each
registration has a revocable atomic active flag (new registrations have
distinct allocation identities, preventing stale handles from reviving after
unregister/re-register). Routing checks the lease before and after capability
reads, and immediately before returning a selection.

A `RoutedProvider` is not permanent authority. `ensure_live` fails if
the instance is deregistered or marked unhealthy. Its `execute` convenience
path validates the exact routed operation, host scope, host assurance and
requested reference, then invokes KM-05 `execute_checked` with the existing
mandatory host `PolicyGate`. A guard rechecks registration health and
revocation **before and after awaiting the policy hook**. A revocation while
that hook is pending turns into fail-closed policy-indeterminate, with no
cryptographic/lifecycle operation dispatched.

The narrow check-to-dispatch concurrency window cannot guarantee rollback
if a native call was already started. Removing a provider is **not**
cryptographic revocation at the device and does not cancel outstanding
transactions. Adapters must recheck exact key/version and feature semantics
at their own dispatch boundary and preserve KM-05 UnknownCommitState
reconciliation. A lease does not grant IAM authorization, bypass mandatory
policy, or replace the KM-02 exact target binding.

## Acceptance coverage

`crates/keymesh/tests/provider_registry.rs` exercises:
- explicit selection and no-crypto side effects during routing;
- deterministic tie-breaking regardless of insertion order;
- Unknown/unavailable health and no explicit-provider fallback;
- no HSM-to-software/TEE downgrade or unverified HSM assertion;
- exact operation/parameter-version admission, Unknown support denial;
- duplicate provider, tenant mismatch and unauthorized allowed-scope lists;
- removal while capability read is pending (stale route rejected);
- old lease remains revoked after same-name re-registration;
- execute through KM-05 mandatory policy and exact binding;
- revoke during awaited policy (zero provider dispatch);
- redacted Debug, error messages and static rejection counts.

`cargo run --locked -p keymesh --example provider_registry` demonstrates
opt-in HSM routing over a software and an HSM *fake* with no secrets,
network clients or cryptography.

## Exit gates

```sh
cargo fmt --all -- --check
cargo check --workspace --all-targets --all-features --locked
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
cargo run --locked -p keymesh --example provider_registry
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps --locked
```

Stable Rust, Rust 1.85 MSRV, RustSec, dependency deny, semver and publication
guard must remain green on the **exact PR head** before merge. No provider or
key-management compliance claim follows from fake tests. Crate publication
continues to be disabled.

See [KM-04 capability matching](capabilities-v1.md),
[KM-05 runtime contract](provider-contract-v1.md), and
[threat-to-test traceability](../security/traceability.md).
