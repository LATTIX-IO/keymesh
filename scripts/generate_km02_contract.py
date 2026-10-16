#!/usr/bin/env python3
"""Generate Rust KM-02 preflight tests from the versioned KM-01 JSON contract.

This is an intentionally scoped projection of the identity/version fixture cases.
KM-03..KM-18 must implement the other (policy/crypto/auth/provider) cases.
No dependencies beyond Python 3.11's standard library.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests/fixtures/key_binding_contract_v1.json"
OUTPUT = ROOT / "crates/keymesh/tests/generated_km02_contract.inc"

IDS = (
    "software-stable",
    "azure-exact-version",
    "vault-exact-version",
    "aws-stable-resource",
    "aws-no-exact-material",
    "aws-material-metadata-only",
    "software-exact-material",
    "alias-active-resolved",
    "wrong-provider",
    "wrong-namespace",
    "wrong-resource",
    "wrong-logical-key",
    "stale-azure-version",
    "software-stale-material",
)


def lit(value: object) -> str:
    if value is None:
        return "None"
    if not isinstance(value, str):
        raise TypeError(f"Expected string or null: {value!r}")
    if not value.isascii():
        raise ValueError("Non-ASCII snapshot needs explicit Rust escaping")
    return f"Some({json.dumps(value)})"


def generate() -> str:
    fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
    if fixture["schema"] != "keymesh.key-binding-contract/v1":
        raise ValueError("Unsupported fixture schema")
    by_id = {case["id"]: case for case in fixture["cases"]}
    if len(by_id) != len(fixture["cases"]):
        raise ValueError("Duplicate fixture IDs")
    if missing := set(IDS) - set(by_id):
        raise ValueError(f"Missing identity contract cases: {sorted(missing)}")

    fields = (
        "req_provider", "req_namespace", "req_logical", "req_resource",
        "req_binding", "req_version", "req_material", "selector",
        "bound_provider", "bound_namespace", "bound_logical", "bound_resource",
        "dispatch_kind", "dispatch_version", "dispatch_material", "observed_material",
        "expected",
    )
    lines = [
        "// Generated from tests/fixtures/key_binding_contract_v1.json.",
        "// This .inc expression is included by contract_replay.rs and ignored by rustfmt.",
        "[",
    ]

    for id_ in IDS:
        case = by_id[id_]
        req = {**fixture["defaults"]["request"], **case.get("request", {})}
        bound = {**fixture["defaults"]["bound"], **case.get("bound", {})}
        if req["required_binding"] not in {"stable_resource", "provider_version", "material_version"}:
            raise ValueError(f"Unrecognized binding in {id_}")
        dispatch = bound["dispatch_kind"]
        if dispatch == "material_version" and not bound.get("material_revision_selectable"):
            # Metadata-only material revision does not grant a selectable target.
            dispatch = "stable_resource"
        if dispatch not in {"stable_resource", "provider_version", "material_version"}:
            raise ValueError(f"Unsupported dispatch kind in snapshot: {id_}, {dispatch}")
        selector = "active" if id_ == "alias-active-resolved" else (
            "material" if req.get("required_material_revision") else (
                "version" if req.get("required_version") else "resource"
            )
        )
        entries = {
            "req_provider": req["provider_instance"],
            "req_namespace": req["namespace"],
            "req_logical": req["logical_key"],
            "req_resource": req["resource_id"],
            "req_binding": req["required_binding"],
            "req_version": req.get("required_version"),
            "req_material": req.get("required_material_revision"),
            "selector": selector,
            "bound_provider": bound["provider_instance"],
            "bound_namespace": bound["namespace"],
            "bound_logical": bound["logical_key"],
            "bound_resource": bound["resource_id"],
            "dispatch_kind": dispatch,
            "dispatch_version": bound.get("version"),
            "dispatch_material": bound.get("material_revision") if dispatch == "material_version" else None,
            "observed_material": bound.get("material_revision") if dispatch == "stable_resource" else None,
            "expected": case["expected"] == "allow",
        }
        lines.append("        Fixture {")
        lines.append(f"            id: {json.dumps(id_)},")
        for field in fields:
            if field == "expected":
                value = "true" if entries[field] else "false"
            else:
                value = lit(entries[field])
            lines.append(f"            {field}: {value},")
        lines.append("        },")

    lines += ["]", ""]
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="Fail unless committed Rust fixture matches JSON")
    args = parser.parse_args()
    expected = generate()
    if args.check:
        if not OUTPUT.is_file() or OUTPUT.read_text(encoding="utf-8") != expected:
            print("KM-02 generated Rust fixture is stale; regenerate and commit", file=sys.stderr)
            return 1
        print(f"KM-02 contract projection PASS ({len(IDS)} scenarios)")
        return 0
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(expected, encoding="utf-8")
    print(f"generated {OUTPUT} ({len(IDS)} scenarios)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())