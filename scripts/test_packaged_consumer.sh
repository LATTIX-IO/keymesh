#!/usr/bin/env bash
# KM-11: execute the shipped crate from an isolated external Cargo consumer.
# No registry publication, persistent keys or credentials are used.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
VERSION="$(sed -n '/^\[workspace.package\]/,/^\[/s/^version = "\([^"]*\)"/\1/p' "$ROOT/Cargo.toml" | head -n 1)"
test -n "$VERSION"
cargo package --manifest-path "$ROOT/Cargo.toml" -p keymesh --locked --allow-dirty --no-verify
PACKAGE="$ROOT/target/package/keymesh-$VERSION.crate"
test -f "$PACKAGE"
tar -xzf "$PACKAGE" -C "$WORK"
PKG="$WORK/keymesh-$VERSION"
test -f "$PKG/Cargo.toml"
test -f "$PKG/src/lib.rs"
mkdir -p "$WORK/consumer/src"
cp "$ROOT/tests/consumer/main.rs" "$WORK/consumer/src/main.rs"
cat > "$WORK/consumer/Cargo.toml" <<EOF
[package]
name = "keymesh-independent-consumer"
version = "0.0.0"
edition = "2024"
publish = false

[dependencies]
keymesh = { path = "$PKG", features = ["software-provider"] }
EOF
(
  cd "$WORK/consumer"
  cargo generate-lockfile
  cargo run --locked
  cargo test --locked
)
# Default builds must NOT unexpectedly export the opt-in private-key provider.
mkdir -p "$WORK/disabled/src"
cat > "$WORK/disabled/Cargo.toml" <<EOF
[package]
name = "keymesh-feature-off-rejection"
version = "0.0.0"
edition = "2024"
publish = false

[dependencies]
keymesh = { path = "$PKG" }
EOF
cat > "$WORK/disabled/src/main.rs" <<'EOF'
use keymesh::SoftwareProvider;
fn main() { let _ = core::mem::size_of::<SoftwareProvider>(); }
EOF
if cargo check --manifest-path "$WORK/disabled/Cargo.toml" > "$WORK/feature-off.log" 2>&1; then
  echo "ERROR: software-provider symbol is unexpectedly available without opt-in" >&2
  exit 1
fi
if ! grep -q 'unresolved import.*SoftwareProvider' "$WORK/feature-off.log"; then
  echo "ERROR: default-disabled check failed for an unexpected reason" >&2
  cat "$WORK/feature-off.log" >&2
  exit 1
fi
echo "KM-11: independently packaged consumer and opt-in negative check succeeded"
