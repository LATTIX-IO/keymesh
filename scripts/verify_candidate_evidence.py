#!/usr/bin/env python3
"""Fail-closed structural checks for the generated CycloneDX candidate SBOM.

The trusted generator emits the SBOM. This does not replace independent
JSON-schema validation or final dependency/license approval.
"""
from __future__ import annotations

import json
import re
import sys
import uuid
from pathlib import Path


def expected_serial(version: str, source_sha: str) -> str:
    if not re.fullmatch(r'[0-9a-f]{40}', source_sha):
        raise ValueError('Expected a full lowercase commit SHA')
    if not version or len(version) > 64:
        raise ValueError('Invalid package version')
    name = f'https://github.com/LATTIX-IO/keymesh/commit/{source_sha}#keymesh:{version}'
    return 'urn:uuid:' + str(uuid.uuid5(uuid.NAMESPACE_URL, name))


def ensure_serial(path: Path, version: str, source_sha: str) -> str:
    """Add deterministic CycloneDX UUIDv5 serial for GitHub attestation."""
    bom = json.loads(path.read_text(encoding='utf-8'))
    if bom.get('bomFormat') != 'CycloneDX' or bom.get('specVersion') != '1.5':
        raise ValueError('Expected generated CycloneDX 1.5 BOM')
    component = bom.get('metadata', {}).get('component', {})
    if (component.get('name'), component.get('version')) != ('keymesh', version):
        raise ValueError('Generated BOM identity mismatch')
    serial = expected_serial(version, source_sha)
    if 'serialNumber' in bom and bom['serialNumber'] != serial:
        raise ValueError('Mismatched generated BOM serialNumber')
    bom['serialNumber'] = serial
    path.write_text(json.dumps(bom, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    return serial



def validate(path: Path, version: str) -> int:
    bom = json.loads(path.read_text(encoding="utf-8"))
    if bom.get("bomFormat") != "CycloneDX" or bom.get("specVersion") != "1.5":
        raise ValueError("Expected CycloneDX 1.5")
    serial = bom.get("serialNumber")
    if not isinstance(serial, str) or not serial.startswith("urn:uuid:"):
        raise ValueError("CycloneDX serialNumber UUID URN is required")
    try:
        parsed = uuid.UUID(serial[len("urn:uuid:"):])
    except ValueError as error:
        raise ValueError("Invalid CycloneDX serialNumber") from error
    if parsed.version != 5 or str(parsed) != serial[len("urn:uuid:"):]:
        raise ValueError("Expected canonical UUIDv5 serialNumber")
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
    normalize = len(sys.argv) == 5 and sys.argv[1] == "--normalize"
    if not normalize and len(sys.argv) != 3:
        print("usage: verify_candidate_evidence.py [--normalize] SBOM VERSION [SHA]", file=sys.stderr)
        return 2
    try:
        if normalize:
            serial = ensure_serial(Path(sys.argv[2]), sys.argv[3], sys.argv[4])
            print(f"Assigned deterministic serialNumber: {serial}")
        sbom, version = (sys.argv[2], sys.argv[3]) if normalize else (sys.argv[1], sys.argv[2])
        count = validate(Path(sbom), version)
    except (OSError, ValueError, TypeError, KeyError) as error:
        print(f"Candidate SBOM invalid: {error}", file=sys.stderr)
        return 1
    print(f"CycloneDX 1.5 candidate structure accepted: {count} dependencies")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
