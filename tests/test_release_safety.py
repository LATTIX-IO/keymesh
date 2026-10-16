"""Positive and adversarial bootstrap release policy tests."""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from check_release_safety import ReleaseSafetyError, check_repository  # noqa: E402

MANIFEST = '[package]\nname = "keymesh"\nversion = "0.1.0"\npublish = false\n'
RELEASE = """name: Release readiness (non-publishing)
on:
  workflow_dispatch:
permissions:
  contents: read
jobs:
  preview:
    runs-on: ubuntu-latest
    steps:
      - run: python3 scripts/check_release_safety.py
"""
CI = """name: Rust CI
on:
  pull_request:
    branches: [main]
permissions:
  contents: read
jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - run: python3 scripts/check_release_safety.py
      - run: python3 -m unittest discover -s tests
"""
CONFIG = '[workspace]\ngit_release_enable = false\ngit_tag_enable = false\n'


class PublicationGuardTests(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.write("Cargo.toml", '[workspace]\nmembers = ["crates/keymesh"]\n')
        self.write("crates/keymesh/Cargo.toml", MANIFEST)
        self.write(".github/workflows/ci.yml", CI)
        self.write(".github/workflows/release-plz.yml", RELEASE)
        self.write("release-plz.toml", CONFIG)

    def write(self, path: str, content: str) -> None:
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")

    def rejected(self) -> None:
        with self.assertRaises(ReleaseSafetyError):
            check_repository(self.root)

    def test_valid_manual_preview_passes(self) -> None:
        self.assertEqual(check_repository(self.root), 1)

    def test_publish_registry_allowlist_rejected(self) -> None:
        self.write("crates/keymesh/Cargo.toml", MANIFEST.replace("false", '["crates-io"]'))
        self.rejected()

    def test_publish_true_rejected(self) -> None:
        self.write("crates/keymesh/Cargo.toml", MANIFEST.replace("false", "true"))
        self.rejected()

    def test_missing_publish_rejected(self) -> None:
        self.write("crates/keymesh/Cargo.toml", MANIFEST.replace("publish = false\n", ""))
        self.rejected()

    def test_new_package_without_guard_rejected(self) -> None:
        self.write("crates/other/Cargo.toml", '[package]\nname="other"\nversion="0.1.0"\n')
        self.rejected()

    def test_push_trigger_rejected(self) -> None:
        self.write(".github/workflows/release-plz.yml", RELEASE.replace(
            "  workflow_dispatch:", "  push:\n    branches: [main]\n  workflow_dispatch:"))
        self.rejected()

    def test_inline_trigger_rejected(self) -> None:
        self.write(".github/workflows/release-plz.yml", RELEASE.replace(
            "on:\n  workflow_dispatch:", "on: [push, workflow_dispatch]"))
        self.rejected()

    def test_registry_token_rejected(self) -> None:
        self.write(".github/workflows/release-plz.yml",
                   RELEASE + '      - run: echo "${{ secrets.CARGO_REGISTRY_TOKEN }}"\n')
        self.rejected()

    def test_release_action_rejected(self) -> None:
        self.write(".github/workflows/release-plz.yml",
                   RELEASE + "      - uses: release-plz/action@unsafe\n")
        self.rejected()

    def test_other_workflow_publisher_rejected(self) -> None:
        self.write(".github/workflows/other.yml",
                   "name: Publish\non: [push]\njobs:\n  p:\n    steps:\n      - run: cargo publish\n")
        self.rejected()

    def test_write_permission_rejected(self) -> None:
        self.write(".github/workflows/release-plz.yml",
                   RELEASE.replace("contents: read", "contents: write"))
        self.rejected()

    def test_job_level_write_all_rejected(self) -> None:
        self.write(".github/workflows/release-plz.yml", RELEASE.replace(
            "  preview:\n", "  preview:\n    permissions: write-all\n"))
        self.rejected()

    def test_other_permission_write_rejected(self) -> None:
        self.write(".github/workflows/release-plz.yml", RELEASE.replace(
            "  contents: read\n", "  contents: read\n  actions: write\n"))
        self.rejected()

    def test_inline_permission_write_rejected(self) -> None:
        self.write(".github/workflows/release-plz.yml", RELEASE.replace(
            "  preview:\n", "  preview:\n    permissions: {deployments: write}\n"))
        self.rejected()

    def test_release_guard_echo_not_executed_rejected(self) -> None:
        self.write(".github/workflows/release-plz.yml", RELEASE.replace(
            "run: python3 scripts/check_release_safety.py",
            'run: echo "python3 scripts/check_release_safety.py"'))
        self.rejected()

    def test_ci_guard_echo_not_executed_rejected(self) -> None:
        self.write(".github/workflows/ci.yml", CI.replace(
            "run: python3 scripts/check_release_safety.py",
            'run: echo "python3 scripts/check_release_safety.py"'))
        self.rejected()

    def test_ci_guard_yaml_comment_not_executed_rejected(self) -> None:
        self.write(".github/workflows/ci.yml", CI.replace(
            "- run: python3 scripts/check_release_safety.py",
            "# run: python3 scripts/check_release_safety.py"))
        self.rejected()

    def test_ci_unittest_echo_not_executed_rejected(self) -> None:
        self.write(".github/workflows/ci.yml", CI.replace(
            "run: python3 -m unittest discover -s tests",
            'run: echo "python3 -m unittest discover -s tests"'))
        self.rejected()

    def test_automatic_tagging_rejected(self) -> None:
        self.write("release-plz.toml", CONFIG.replace("git_tag_enable = false", "git_tag_enable = true"))
        self.rejected()

    def test_missing_ci_guard_rejected(self) -> None:
        self.write(".github/workflows/ci.yml", CI.replace(
            "python3 scripts/check_release_safety.py", "echo bypassed"))
        self.rejected()


if __name__ == "__main__":
    unittest.main()
