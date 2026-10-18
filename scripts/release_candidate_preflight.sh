#!/usr/bin/env bash
# Read-only, non-publishing release preview. Does NOT use registry credentials.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
python3 scripts/check_release_safety.py
python3 -m unittest discover -s tests -p 'test_*.py' -v
cargo fmt --all -- --check
cargo check --workspace --all-targets --all-features --locked
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps --locked
bash scripts/test_packaged_consumer.sh
VERSION="$(sed -n '/^\[workspace.package\]/,/^\[/s/^version = "\([^"]*\)"/\1/p' Cargo.toml | head -n 1)"
ARCHIVE="target/package/keymesh-$VERSION.crate"
test -f "$ARCHIVE"
sha256sum "$ARCHIVE"
sha256sum Cargo.lock
echo "Release readiness preview only: no publication, tag, signing or attestations."
