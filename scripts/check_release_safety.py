#!/usr/bin/env python3
"""Read-only bootstrap publication safety gate (Python 3.11+, stdlib only)."""
from __future__ import annotations

import re
import sys
import tomllib
from pathlib import Path


class ReleaseSafetyError(Exception):
    """A repository configuration violates non-publication requirements."""


def check_manifest(path: Path) -> bool:
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    if "package" not in data:
        return False
    if data["package"].get("publish") is not False:
        raise ReleaseSafetyError(f"{path}: expected explicit publish = false")
    return True


def check_release_workflow(text: str) -> None:
    lines = text.splitlines()
    on_lines = [i for i, line in enumerate(lines) if line.rstrip() == "on:"]
    if len(on_lines) != 1:
        raise ReleaseSafetyError("Release workflow requires a single block-form on: trigger")
    triggers: list[str] = []
    for line in lines[on_lines[0] + 1:]:
        if line.strip() and not line.startswith((" ", "\t", "#")):
            break
        if line.strip() and not line.lstrip().startswith("#"):
            triggers.append(line)
    if triggers != ["  workflow_dispatch:"]:
        raise ReleaseSafetyError("Release readiness workflow must be manual-only")
    if not re.search(r"(?m)^permissions:\s*$", text) or not re.search(
        r"(?m)^  contents:\s*read\s*$", text
    ):
        raise ReleaseSafetyError("Release workflow requires contents: read permission")
    if re.search(r"(?im)^\s*(?:contents|pull-requests|packages|id-token):\s*write\b", text):
        raise ReleaseSafetyError("Release preview may not request write permissions")
    if "python3 scripts/check_release_safety.py" not in text:
        raise ReleaseSafetyError("Release workflow must invoke the publication guard")


def check_repository(root: Path) -> int:
    root = root.resolve()
    if not (root / "Cargo.toml").is_file():
        raise ReleaseSafetyError("Missing root Cargo.toml")
    manifests = sorted(
        path for path in root.rglob("Cargo.toml")
        if not any(part in {"target", ".git", ".venv"} for part in path.relative_to(root).parts)
    )
    count = sum(check_manifest(path) for path in manifests)
    if count == 0:
        raise ReleaseSafetyError("No Cargo package is protected")
    workflow_dir = root / ".github" / "workflows"
    release_path = workflow_dir / "release-plz.yml"
    ci_path = workflow_dir / "ci.yml"
    if not release_path.is_file() or not ci_path.is_file():
        raise ReleaseSafetyError("Required CI and release readiness workflows missing")
    workflows = sorted([*workflow_dir.glob("*.yml"), *workflow_dir.glob("*.yaml")])
    blocked = (
        (r"\bcargo\s+(?:publish|login)\b", "registry publish/login"),
        (r"release-plz/action@", "automatic release action"),
        (r"(?m)^\s*command:\s*release\s*(?:#.*)?$", "release command"),
        (r"\bCARGO_REGISTRY_TOKEN\b", "registry token"),
        (r"\bRELEASE_PLZ_TOKEN\b", "release token"),
    )
    for path in workflows:
        content = path.read_text(encoding="utf-8")
        for pattern, label in blocked:
            if re.search(pattern, content, re.IGNORECASE):
                raise ReleaseSafetyError(f"{path}: forbidden {label}")
    check_release_workflow(release_path.read_text(encoding="utf-8"))
    ci = ci_path.read_text(encoding="utf-8")
    if ("python3 scripts/check_release_safety.py" not in ci
            or "python3 -m unittest discover -s tests" not in ci):
        raise ReleaseSafetyError("PR CI must run guard and adversarial tests")
    config_path = root / "release-plz.toml"
    if config_path.is_file():
        config = tomllib.loads(config_path.read_text(encoding="utf-8")).get("workspace", {})
        if config.get("git_release_enable") is not False or config.get("git_tag_enable") is not False:
            raise ReleaseSafetyError("Release and tag generation must be disabled")
    return count


def main() -> int:
    try:
        count = check_repository(Path(__file__).resolve().parent.parent)
    except (ReleaseSafetyError, OSError, UnicodeError, tomllib.TOMLDecodeError) as exc:
        print(f"Publication safety FAILED: {exc}", file=sys.stderr)
        return 1
    print(f"Publication safety PASS: {count} explicitly nonpublishable package(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
