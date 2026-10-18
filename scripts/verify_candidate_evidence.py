#!/usr/bin/env python3
"""Fail-closed structural checks for the generated CycloneDX candidate SBOM.

The trusted generator emits the SBOM. This does not replace independent
JSON-schema validation or final dependency/license approval.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path


def validate(path: Path, version: str) -> int:
    bom = json.loads(path.read_text(encoding="utf-8"))
    if bom.get("bomFormat") != "CycloneDX" or bom.get("specVersion") != "1.5":
        raise ValueError("Expected CycloneDX 1.5")
    component = bom.get("metadata", {}).get("component", {})
    if (component.get("name"), component.get("version")) != ("keymesh", version):
        raise ValueError("Top-level component/version mismatch")
    deps = bom.get("components", [])
    if not isinstance(deps, list) or not deps:
        raise ValueError("Missing dependency components")
    for dependency in deps:
        if not all(dependency.get(key) for key in ("name", "version", "bom-ref")):
            raise ValueError("Unidentified dependency component")
    required = {"serde", "zeroize", "ed25519-dalek", "getrandom"}
    observed = {dependency["name"] for dependency in deps}
    if missing := required - observed:
        raise ValueError(f"Expected all-feature dependencies not found: {sorted(missing)}")
    return len(deps)


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: verify_candidate_evidence.py SBOM VERSION", file=sys.stderr)
        return 2
    try:
        count = validate(Path(sys.argv[1]), sys.argv[2])
    except (OSError, ValueError, TypeError, KeyError) as error:
        print(f"Candidate SBOM invalid: {error}", file=sys.stderr)
        return 1
    print(f"CycloneDX 1.5 candidate structure accepted: {count} dependencies")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
