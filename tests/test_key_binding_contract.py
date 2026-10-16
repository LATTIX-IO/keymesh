"""Normative key-binding reference model (NOT production provider enforcement).

These tests guard the design contract until the matching Rust tests in KM-02,
KM-04, KM-05, KM-06 and provider implementations replace the reference model.
"""
from __future__ import annotations

import json
import unittest
from pathlib import Path

FIXTURE = Path(__file__).parent / "fixtures" / "key_binding_contract_v1.json"
ROOT = Path(__file__).resolve().parents[1]

BINDING_STRENGTH = {
    "unknown": 0,
    "alias_only": 0,
    "stable_resource": 1,
    "provider_version": 2,
    "material_version": 3,
}
VALID_DISPATCH = {"stable_resource", "provider_version", "material_version"}
SENSITIVE_MARKERS = ("pin-value=", "pin-source=", "token=", "password=", "secret=", "access_key=")


def contract_decision(request: dict, bound: dict) -> str:
    """Minimal design oracle to test the future API's fail-closed obligations."""
    if not request.get("host_scope_verified"):
        return "deny"
    if not bound.get("authorization_verified"):
        return "deny"
    if any(bound.get(k) != request.get(k) for k in (
        "provider_instance", "namespace", "logical_key", "resource_id"
    )):
        return "deny"
    if bound.get("dispatch_kind") not in VALID_DISPATCH:
        return "deny"
    resource = bound.get("provider_locator", "")
    if not isinstance(resource, str) or any(s in resource.lower() for s in SENSITIVE_MARKERS):
        return "deny"
    required_binding = request.get("required_binding")
    actual_binding = bound.get("assurance")
    if required_binding not in BINDING_STRENGTH or actual_binding not in BINDING_STRENGTH:
        return "deny"
    if BINDING_STRENGTH[actual_binding] < BINDING_STRENGTH[required_binding]:
        return "deny"
    if actual_binding in {"alias_only", "unknown"}:
        return "deny"
    if required_binding == "provider_version" or required_binding == "material_version":
        if not request.get("required_version") or bound.get("version") != request["required_version"]:
            return "deny"
        if bound.get("dispatch_kind") not in {"provider_version", "material_version"}:
            return "deny"
    if required_binding == "material_version":
        if not (bound.get("material_revision_selectable") and bound.get("material_revision") == request.get("required_material_revision")):
            return "deny"
        if bound.get("dispatch_kind") != "material_version":
            return "deny"
    if request.get("require_attested_hsm") and not (
        bound.get("protection") in {"hsm", "dedicated_hsm"} and bound.get("protection_verified")
    ):
        return "deny"
    if any(bound.get(k) != request.get(k) for k in ("operation", "profile", "payload_kind")):
        return "deny"
    if request.get("mandatory_policy") and bound.get("policy_decision") != "allow":
        return "deny"
    if request.get("mutation") and not bound.get("mutation_approved"):
        return "deny"
    return "allow"


class ContractFixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.data = json.loads(FIXTURE.read_text(encoding="utf-8"))

    def test_fixture_schema_and_traceability(self) -> None:
        self.assertEqual(self.data["schema"], "keymesh.key-binding-contract/v1")
        ids = [c["id"] for c in self.data["cases"]]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertGreaterEqual(len(ids), 16)
        threat_ids = [c["threat_id"] for c in self.data["cases"]]
        model = (ROOT / "THREAT_MODEL.md").read_text(encoding="utf-8")
        for threat in threat_ids:
            self.assertIn(threat, model)
        for case in self.data["cases"]:
            self.assertIn(case["expected"], {"allow", "deny"})
            self.assertTrue(case.get("reason"))

    def test_expected_contract_decisions(self) -> None:
        baseline_request = self.data["defaults"]["request"]
        baseline_bound = self.data["defaults"]["bound"]
        for case in self.data["cases"]:
            with self.subTest(case=case["id"]):
                request = {**baseline_request, **case.get("request", {})}
                bound = {**baseline_bound, **case.get("bound", {})}
                self.assertEqual(contract_decision(request, bound), case["expected"])

    def test_mutation_property_wrong_provider_or_namespace_denies(self) -> None:
        request = self.data["defaults"]["request"]
        base = self.data["defaults"]["bound"]
        self.assertEqual(contract_decision(request, base), "allow")
        for field in ("provider_instance", "namespace", "logical_key", "resource_id"):
            for wrong_value in ("", "tenant-b", "foreign-provider", "../other"):
                with self.subTest(field=field, wrong_value=wrong_value):
                    self.assertEqual(contract_decision(request, {**base, field: wrong_value}), "deny")

    def test_mutation_property_never_upgrade_unknown_or_alias(self) -> None:
        request = self.data["defaults"]["request"]
        base = self.data["defaults"]["bound"]
        for category in ("unknown", "alias_only"):
            for dispatch in ("alias", "stable_resource", "provider_version", "material_version"):
                with self.subTest(category=category, dispatch=dispatch):
                    self.assertEqual(contract_decision(request, {**base, "assurance": category, "dispatch_kind": dispatch}), "deny")

    def test_mutation_property_secrets_in_locator_denied(self) -> None:
        request = self.data["defaults"]["request"]
        base = self.data["defaults"]["bound"]
        for marker in SENSITIVE_MARKERS:
            with self.subTest(marker=marker):
                self.assertEqual(contract_decision(request, {**base, "provider_locator": "pkcs11:object=x?" + marker + "EXAMPLE"}), "deny")

    def test_strong_requirement_cannot_be_downgraded(self) -> None:
        request = {**self.data["defaults"]["request"],
                   "required_binding": "material_version", "required_version": "v4",
                   "required_material_revision": "rev4"}
        base = self.data["defaults"]["bound"]
        for category in ("unknown", "alias_only", "stable_resource", "provider_version"):
            with self.subTest(category=category):
                self.assertEqual(contract_decision(request, {**base, "assurance": category,
                    "version": "v4", "material_revision": "rev4", "material_revision_selectable": True}), "deny")
        self.assertEqual(contract_decision(request, {**base, "assurance": "material_version",
            "dispatch_kind": "material_version", "version": "v4", "material_revision": "rev4",
            "material_revision_selectable": True}), "allow")


if __name__ == "__main__":
    unittest.main()
