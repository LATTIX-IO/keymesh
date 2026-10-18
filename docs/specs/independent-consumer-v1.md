# KM-11 — Independent consumer and package acceptance

The `scripts/test_packaged_consumer.sh` workflow executes `cargo package`
for the unpublished Keymesh crate, extracts that actual archive outside the
source tree, builds an independent Cargo project against its extracted manifest,
and runs the public-API example. The temporary consumer is not a workspace
member; it imports no internal modules and uses the opt-in software-provider
feature explicitly. It also builds a separate feature-off consumer designed to
fail specifically when importing `SoftwareProvider`.

The clean-room fixture proves the package contains all required Rust library
sources, exercises actual Ed25519 signing, verifies across an immutable rotation,
checks a retired version cannot sign, checks lifecycle state changes, and rejects
a host policy Deny with `NotDispatched`.

**Release boundary:** This is local packaging and install acceptance only.
Registry ownership, reproducible SBOM, provenance and manual publication are
reserved for FOSS-431. The seeded example policy is a demo only; no production
authorization or hardware-backed cryptographic custody is asserted.

Run `bash scripts/test_packaged_consumer.sh` on Rust stable and 1.85, plus the
existing format/check/Clippy/test/rustdoc/RustSec/deny/SemVer suite.
