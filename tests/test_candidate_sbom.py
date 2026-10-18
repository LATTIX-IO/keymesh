"""KM-20: SBOM validator must reject missing or substituted evidence."""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from verify_candidate_evidence import ensure_serial, expected_serial, validate  # noqa: E402

REQUIRED = ("serde", "zeroize", "ed25519-dalek", "getrandom")
SOURCE_SHA = "a" * 40
SERIAL = expected_serial("0.1.0", SOURCE_SHA)


def sample(name="keymesh", version="0.1.0", spec="1.5", missing=()):
    return {
        "bomFormat": "CycloneDX",
        "specVersion": spec,
        "serialNumber": SERIAL,
        "metadata": {"component": {"name": name, "version": version}},
        "components": [
            {"name": dep, "version": "1.0.0", "bom-ref": "pkg:cargo/" + dep}
            for dep in REQUIRED if dep not in missing
        ],
    }


class CandidateSbomTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name) / "candidate.cdx.json"

    def check(self, data, expected="0.1.0"):
        self.path.write_text(json.dumps(data), encoding="utf-8")
        return validate(self.path, expected)

    def test_complete_bom_is_accepted(self):
        self.assertEqual(self.check(sample()), 4)

    def test_old_format_is_rejected(self):
        with self.assertRaises(ValueError):
            self.check(sample(spec="1.3"))

    def test_other_crate_or_version_cannot_pass(self):
        for data in (sample(name="unrelated"), sample(version="9.9.9")):
            with self.subTest(data=data):
                with self.assertRaises(ValueError):
                    self.check(data)

    def test_missing_optional_provider_is_not_an_all_features_bom(self):
        with self.assertRaises(ValueError):
            self.check(sample(missing={"ed25519-dalek"}))

    def test_malformed_components_fail(self):
        broken = sample()
        broken["components"][0].pop("bom-ref")
        with self.assertRaises(ValueError):
            self.check(broken)


    def test_missing_cyclonedx_serial_is_rejected(self):
        bom = sample()
        del bom["serialNumber"]
        with self.assertRaisesRegex(ValueError, "serialNumber"):
            self.check(bom)

    def test_invalid_cyclonedx_serial_is_rejected(self):
        for serial in ("not-a-uuid", "urn:uuid:not-valid",
                       "urn:uuid:00000000-0000-0000-0000-000000000000"):
            with self.subTest(serial=serial):
                bom = sample()
                bom["serialNumber"] = serial
                with self.assertRaises(ValueError):
                    self.check(bom)

    def test_normalize_deterministic_and_idempotent(self):
        bom = sample()
        del bom["serialNumber"]
        self.path.write_text(json.dumps(bom), encoding="utf-8")
        self.assertEqual(ensure_serial(self.path, "0.1.0", SOURCE_SHA), SERIAL)
        self.assertEqual(validate(self.path, "0.1.0"), 4)
        first = self.path.read_bytes()
        self.assertEqual(ensure_serial(self.path, "0.1.0", SOURCE_SHA), SERIAL)
        self.assertEqual(self.path.read_bytes(), first)

    def test_normalize_rejects_untrusted_existing_serial(self):
        bom = sample()
        bom["serialNumber"] = "urn:uuid:123e4567-e89b-42d3-a456-426614174000"
        self.path.write_text(json.dumps(bom), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "Mismatched"):
            ensure_serial(self.path, "0.1.0", SOURCE_SHA)
        with self.assertRaisesRegex(ValueError, "SHA"):
            ensure_serial(self.path, "0.1.0", "invalid")


if __name__ == "__main__":
    unittest.main()
