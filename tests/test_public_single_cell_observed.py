# SPDX-License-Identifier: Apache-2.0
"""Check copied run-record consistency; not a substitute for rerunning GEO data."""
import base64
import hashlib
import importlib.util
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("observed_example", ROOT / "examples/public-single-cell/run_example.py")
EXAMPLE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(EXAMPLE)
RECORD = ROOT / "examples/public-single-cell/observed-run.json"


class ObservedRecordTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.record = json.loads(RECORD.read_text(encoding="utf-8"))

    def test_copied_summary_matches_the_observed_digest(self):
        self.assertEqual(hashlib.sha256(EXAMPLE.canonical(self.record["summary"])).hexdigest(),
                         self.record["verification"]["summary_sha256"])

    def test_copied_receipt_matches_the_observed_digest(self):
        self.assertEqual(hashlib.sha256(EXAMPLE.canonical(self.record["receipt"])).hexdigest(),
                         self.record["verification"]["receipt_sha256"])

    def test_existing_verifier_accepts_exact_copied_receipt(self):
        verifier = EXAMPLE.load_verifier()
        schema = verifier.load_schema(str(ROOT / "schema/governed-receipt.schema.json"))
        ok, messages = verifier.verify_records([self.record["receipt"]], schema)
        self.assertTrue(ok, messages)
        statement = json.loads(base64.b64decode(self.record["receipt"]["payload"], validate=True))
        self.assertEqual(statement["subject"], [{"name": "summary.json", "digest": {
            "sha256": self.record["verification"]["summary_sha256"]}}])
        self.assertEqual(statement["predicate"]["analysis_sha256"], EXAMPLE.file_sha(Path(EXAMPLE.__file__)))

    def test_narrow_interpretation_is_preserved(self):
        value = self.record["verification"]
        self.assertFalse(value["signature_verified"])
        self.assertFalse(value["trusted_authorship_verified"])
        self.assertFalse(value["biological_claim_validated"])
        self.assertEqual(value["scoring_methods_benchmarked"], [])
        self.assertEqual(self.record["summary"]["parameters"], EXAMPLE.PARAMETERS)


if __name__ == "__main__":
    unittest.main()
