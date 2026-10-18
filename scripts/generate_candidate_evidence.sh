#!/usr/bin/env bash
# Non-publishing exact-source candidate archive, SPDX-licensed dependencies,
# CycloneDX 1.5 SBOM and SHA-256 manifests. Requires cargo-cyclonedx 0.5.9.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
python3 scripts/check_release_safety.py
if ! command -v cargo-cyclonedx >/dev/null 2>&1; then
  echo "Missing required cargo-cyclonedx 0.5.9" >&2
  exit 1
fi
case "$(cargo cyclonedx --version)" in
  *0.5.9*) ;;
  *) echo "Unapproved cargo-cyclonedx version" >&2; exit 1 ;;
esac
VERSION="$(sed -n '/^\[workspace.package\]/,/^\[/s/^version = "\([^"]*\)"/\1/p' Cargo.toml | head -n 1)"
test -n "$VERSION"
mkdir -p target/release-evidence
cargo package -p keymesh --locked --allow-dirty --no-verify
ARCHIVE="target/package/keymesh-$VERSION.crate"
test -s "$ARCHIVE"
# Enumerate the entire compressed archive first. Grep -q directly from tar
# would close its output early and produce a false failure under pipefail.
tar -tzf "$ARCHIVE" > target/release-evidence/PACKAGE_CONTENTS.txt
for required in README.md LICENSE-APACHE LICENSE-MIT; do
  if ! grep -Fxq "keymesh-$VERSION/$required" target/release-evidence/PACKAGE_CONTENTS.txt; then
    echo "Packaged crate lacks $required" >&2
    exit 1
  fi
done
cp "$ARCHIVE" "target/release-evidence/keymesh-$VERSION.crate"
# Build from resolved exact Cargo metadata and the locked dependency graph.
# SOURCE_DATE_EPOCH stabilizes timestamps. A deterministic UUIDv5 serial is
# added after generation for the pinned GitHub attestation action.
SOURCE_DATE_EPOCH="$(git show -s --format=%ct HEAD)" \
  cargo cyclonedx --manifest-path crates/keymesh/Cargo.toml \
  --format json --all-features --target all --spec-version 1.5 --license-strict
mapfile -t BOMS < <(find crates/keymesh -maxdepth 1 -type f -name '*.cdx.json' -print)
if [ "${#BOMS[@]}" -ne 1 ]; then
  echo "Expected exactly one generated CycloneDX JSON BOM" >&2
  exit 1
fi
mv "${BOMS[0]}" "target/release-evidence/keymesh-$VERSION.cdx.json"
SOURCE_SHA="$(git rev-parse --verify HEAD)"
python3 scripts/verify_candidate_evidence.py --normalize \
  "target/release-evidence/keymesh-$VERSION.cdx.json" "$VERSION" "$SOURCE_SHA"
(
  cd target/release-evidence
  sha256sum "keymesh-$VERSION.crate" "keymesh-$VERSION.cdx.json" > SHA256SUMS
  sha256sum -c SHA256SUMS
)
git rev-parse HEAD > target/release-evidence/SOURCE_COMMIT.txt
sha256sum Cargo.lock > target/release-evidence/Cargo.lock.sha256
echo "Candidate evidence created. No registry publish, release tag or signing performed."
