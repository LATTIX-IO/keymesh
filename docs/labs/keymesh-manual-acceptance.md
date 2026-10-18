# Keymesh hands-on release-candidate acceptance lab

This is a **human-operated, standalone Rust consumer**, not a test runner.
The CLI prints each observed stage of Keymesh's public API boundary. You choose
every operation at its interactive prompt. The software Ed25519 signing is
real cryptography; provider routing, authorization and audit are hosted demo
fixtures. This lab does not grant release or registry authorization.

## 0. Prepare PowerShell and the source

Open PowerShell on the Windows machine with the repository clone:

~~~powershell
cd E:\lattix\keymesh
git fetch origin
git status --short
rustc --version
cargo --version
git switch feat/foss-431-interactive-tour
# If necessary: git switch --track origin/feat/foss-431-interactive-tour
Get-Content .\labs\keymesh-tour\Cargo.toml
Get-Content .\crates\keymesh\Cargo.toml | Select-String "publish = false"
~~~

You need Rust 1.85 or newer and Git. The standalone test project under
labs/keymesh-tour consumes ../../crates/keymesh through a path dependency with
the software-provider feature explicitly enabled. It does not consume the
public crates.io 0.1.0 namespace placeholder. Package publishing remains off.
Cargo may download standard dependencies when compiling.

## 1. Launch the interactive process

~~~powershell
cargo run --manifest-path .\labs\keymesh-tour\Cargo.toml
~~~

Wait for the keymesh-tour> prompt. **Do not run each subsequent step as a new
cargo command**: the provider and all private keys exist solely in this one
running Rust process. Read the printed help screen before starting.

All commands below are typed **inside** the interactive keymesh-tour> prompt.
They are NOT PowerShell commands. The five visible stage markers mean:

- [01] Host simulation of authenticated provider/tenant scope.
- [02] Checked gateway request with typed operation and concrete key binding.
- [03] Host-defined decision callback (metadata only), reached after admission.
- [04] Audit callback; failure prevents dispatch.
- [05] Successful checked-operation completion receipt with output.

If a validation fails before the policy callback, [03]/[04]/[05] are absent.
These are host-side observability prints, not cryptographic hardware attestations.

## 2. Check scope and real provider capability advertisement

~~~text
scope
capabilities
~~~

Expected: provider tour-local-ed25519, tenant tour-tenant-a, declared Software
protection and ProviderVersion assurance. The reported operation catalog lists
SignMessage, VerifyMessage and ExportPublic for Ed25519 (not AES, RSA or PQC).
An advertised capability is not a host attestation or an IAM identity.

## 3. Watch provider routing fail closed

~~~text
route
health healthy
route
health unavailable
route
health healthy
route
~~~

Expected: initially NO ROUTE because Unknown health is not usable. Healthy
selects only the enrolled provider; Unavailable refuses, with no invisible
fallback. This is a read-only routing decision and does not create a key.
Health is a demo host declaration, not endpoint monitoring.

## 4. Confirm the store starts empty and requires lifecycle approval

~~~text
status
create-denied
status
~~~

Expected: NO KEY; a Generate lifecycle request is rejected with PolicyDenied
and NotDispatched; still NO KEY. Signing policy and key-lifecycle policy are
separate gates.

## 5. Generate real Ed25519 signing material and examine its URI

~~~text
create
status
uri
~~~

Expected: Generate is explicitly permitted, OS randomness generates an
ephemeral key, and the CLI prints a 32-byte PUBLIC key, an exact
keymesh://v1/.../version/... reference and a monotonic generation (usually 1).
Snapshot shows one Active version, with the same exact reference.
The URI parser roundtrip succeeds, while a v2 URI is rejected. No private seed
or raw key material is displayed. A KeyRef is not an authorization token.

Record the first exact version URI and public key. They change across runs.

## 6. Sign and verify with an actual Ed25519 operation

~~~text
sign approve payment 481 for 125 USD
verify
tamper
export-public
~~~

Expected from sign: the decision hook sees typed Ed25519 SignMessage and the
resolved version-binding assurance; the audit sink records the decision before
dispatch; [05] shows ConfirmedSuccess, exact provider version, and an actual
64-byte hex signature (PUBLIC). Keep the printed signature as test evidence.

Expected from verify: Verification(true) for exact saved version and text.
Expected from tamper: Verification(false) after altering the text while
retaining the original signature. This is a successfully executed verification
whose cryptographic answer is false, NOT an API dispatch failure.
Expected from export-public: 32 public bytes matching the generated key.
Private export is not supported.

## 7. Demonstrate alias resolution to a concrete version

~~~text
sign-alias review project approval
verify
status
~~~

Expected: SignMessage request has an Active alias, but the [05] receipt names
an EXACT concrete provider version. The lab retains the exact signing key in
its saved signature record. This illustrates pinned resolution: a later
rotation must not silently redirect historical verification.

## 8. Prove host policy and assurance constraints fail closed

~~~text
policy-deny
policy-unknown
require-hsm
require-material
audit-fail
cross-tenant
~~~

Expected:
- policy-deny -> PolicyDenied, NotDispatched.
- policy-unknown -> PolicyIndeterminate, NotDispatched.
- require-hsm -> PolicyDenied, requirements_met=false: host supports only Software.
- require-material -> PolicyDenied, requirements_met=false: ProviderVersion is
  weaker than MaterialRevision binding.
- audit-fail -> PolicyIndeterminate, NotDispatched; there is no [05] receipt.
- cross-tenant -> ScopeMismatch, NotDispatched, usually before [03]/[04].

Deny and Indeterminate do not silently become Permit. Keymesh does not
pretend the local provider has HSM or exact material-revision guarantees.
The demo host is not performing real identity authentication.

## 9. Rotate and compare the immutable versions and generations

~~~text
status
rotate
status
~~~

Expected: an exact currently Active version plus an observed CAS generation
authorizes creation of a DIFFERENT public key and exact version URI. The prior
version becomes Retired; the new version becomes Active. The old private seed
is dropped/zeroized while the old PUBLIC verification key remains. The
snapshot generation increments. Write down both URI versions and generation.

## 10. Verify history, irreversible retirement and stale CAS defense

~~~text
verify
retired-sign
stale-rotate
status
~~~

Expected: a pre-rotation signature still verifies true using its original exact
retired key. Reusing the original version to SIGN is denied. A second rotation
with the old, previously consumed generation is rejected with
UnsupportedVersionAssurance/NotDispatched; status does not advance.
No Retired -> Disabled -> Active path may restore signing authority.

## 11. Exercise disable, re-enable and historical purge

~~~text
disable
status
sign should fail while disabled
enable
status
purge-old
status
verify
~~~

Expected: disable sets active=none for the current version and stops signing;
enable (when no other version is active) restores THIS non-retired key, increasing
generation both times. purge-old permanently removes the original retired
version, so verifying the saved historical signature now produces an exact-key
lookup failure, NOT Verification(false). This is a deliberate lifecycle policy:
once the old public key is gone from the provider, its historical verification
cannot be serviced there.

## 12. Check the remaining key, then prove memory-only lifetime

~~~text
sign current signing key is still usable
verify
reset
status
quit
~~~

Expected: new active version still signs and verifies. reset drops the entire
software provider and constructs a new empty instance; status reports NO KEY.
Exiting discards any remaining private material. Relaunch and run status again
to demonstrate the absence of persistent key storage.

## 13. Inspect the non-cryptographic contracts (back in PowerShell)

Run each separately after quitting the interactive program:

~~~powershell
cd E:\lattix\keymesh
cargo run --locked -p keymesh --example keyref_uri
cargo run --locked -p keymesh --example capability_admission
cargo run --locked -p keymesh --example provider_registry
cargo run --locked -p keymesh --example provider_contract
cargo run --locked -p keymesh --example credential_boundary
cargo run --locked -p keymesh --features software-provider --example software_ed25519
cargo run --locked -p keymesh --features software-provider --example software_rotation
~~~

The URI, capability, registry, provider-contract and credential demonstrations
use fake/mock boundaries. The final two use actual ephemeral Ed25519 crypto.
None performs real Vault Transit, PKCS#11, HSM, Azure/AWS KMS or post-quantum
operations. Keymesh models some of those algorithms but has no live adapters.

## 14. Save manual release-review evidence

You may record a PowerShell transcript (use ONLY public/test messages):

~~~powershell
Start-Transcript -Path .\keymesh-tour-manual-review.txt
cargo run --manifest-path .\labs\keymesh-tour\Cargo.toml
# Execute sections 2–12 inside the Rust prompt, then type quit.
Stop-Transcript
~~~

The transcript contains your message plaintext, key URIs, public keys and
public signatures. It is a debugging record, not immutable trusted audit.

| Manual check | Expected result | Verdict |
|---|---|---|
| Empty store, create-denied | No key; PolicyDenied | Pass / Fail |
| Ed25519 creation | New 32-byte public key, exact URI | Pass / Fail |
| URI canonical roundtrip | True; altered version rejected | Pass / Fail |
| Provider routing | Unknown/Unavailable denied, Healthy selected | Pass / Fail |
| Real signature and verification | 64-byte signature; true | Pass / Fail |
| Tampered message | Verification(false) | Pass / Fail |
| Exact policy controls | Deny/unknown/hardware/material/audit all fail closed | Pass / Fail |
| Cross-tenant reference | ScopeMismatch / NotDispatched | Pass / Fail |
| Rotation | New key, old Retired, generation advanced | Pass / Fail |
| Retired signing attempt | Denied; old signature still verifies | Pass / Fail |
| Stale CAS | Rejected, no state mutation | Pass / Fail |
| Disable/re-enable | Current non-retired version toggles | Pass / Fail |
| Historical purge | Old exact reference no longer verifies | Pass / Fail |
| Process reset/restart | No keys retained | Pass / Fail |

## Release authorization is a separate decision

Passing this tour validates currently implemented **software-only functional
behavior**; it does not certify production IAM, persistent storage,
hardware-backed key management, FIPS, PQC, multitenant deployment, an
attestation service or a live registry release. The crate currently has
publish = false. The published 0.1.0 was a namespace placeholder, not this SDK.

The proposed first functional prerelease remains 0.2.0-alpha.1, subject to
authenticated crates.io owner verification, independent crypto/API/security
review, signed final-version provenance, approved publishing credentials,
signed release tag, genuine registry publication, and a clean external
consumer build against that PUBLISHED package. Do not conflate this local
path-dependency lab with post-publication acceptance.
