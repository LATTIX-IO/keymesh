"""KM-20: SBOM validator must reject missing or substituted evidence."""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from verify_candidate_evidence import validate  # noqa: E402

REQUIRED = ("serde", "zeroize", "ed25519-dalek", "getrandom")


def sample(name="keymesh", version="0.1.0", spec="1.5", missing=()):
    return {
        "bomFormat": "CycloneDX",
        "specVersion": spec,
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


if __name__ == "__main__":
    unittest.main()
