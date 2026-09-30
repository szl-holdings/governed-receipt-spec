"""Separate current conformance from immutable historical reproduction evidence."""

import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts import qualify_current_verifier as current
from scripts import stage_historical_example as historical

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "conformance/current-verifier-qualification.json"


class CurrentQualificationTests(unittest.TestCase):
    def test_retained_qualification_replays_with_exact_current_inputs(self):
        retained = json.loads(MANIFEST.read_text(encoding="utf-8"))
        current.check_retained(retained, current.qualify())
        self.assertEqual(retained["execution"]["historical_data_analysis_rerun"], "NOT_RUN")
        self.assertEqual(retained["execution"]["private_key_generation"], "NOT_RUN")

    def test_source_drift_missing_cases_and_positive_claim_changes_fail(self):
        observed = current.qualify()
        for mutation in ("source", "missing", "signature", "boolean"):
            with self.subTest(mutation=mutation):
                retained = copy.deepcopy(observed)
                if mutation == "source":
                    retained["source_sha256"]["verify.py"] = "0" * 64
                elif mutation == "missing":
                    retained["results"].pop()
                elif mutation == "signature":
                    retained["results"][0]["signature_states"] = ["PASS"]
                else:
                    retained["results"][0]["verifier_ok"] = 1
                with self.assertRaises(ValueError):
                    current.check_retained(retained, observed)

    def test_failed_verification_cannot_emit_a_positive_qualification(self):
        with patch.object(current.verify, "verify_records", return_value=(True, ["    sig:    PASS"])), \
                self.assertRaises(ValueError):
            current.qualify()


class HistoricalStagingTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.source = self.root / "source"
        self.source.mkdir()
        verifier = b"# inert historical verifier fixture\n"
        analysis = ('VERIFIER_BLOB = "' + historical.git_blob(verifier) + '"\n').encode()
        self.objects = dict(zip(historical.PAYLOAD, (verifier, b"{}\n", analysis)))
        profile = {"historical_reproduction_commit": "a" * 40,
                   "historical_analysis_git_blob": historical.git_blob(analysis)}
        for name in historical.TOOLING:
            path = self.source / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"immutable fixture bytes\n")
        (self.source / (historical.EXAMPLE + "reproduction-profile.json")).write_text(json.dumps(profile))
        (self.source / (historical.EXAMPLE + "run_example.py")).write_bytes(analysis)

    def stage(self):
        with patch.object(historical.subprocess, "check_output",
                          side_effect=lambda argv, **kwargs: self.objects[argv[-1].split(":", 1)[1]]):
            return historical.stage(self.root / "stage", self.source)

    def test_historical_bytes_are_staged_separately_without_mutating_current_source(self):
        current_path = self.source / "verify.py"
        current_path.write_bytes(b"# current verifier remains separate\n")
        report = self.stage()
        self.assertEqual(current_path.read_bytes(), b"# current verifier remains separate\n")
        for name, data in self.objects.items():
            self.assertEqual((self.root / "stage" / name).read_bytes(), data)
        self.assertIn("historical reproduction only", report["scope"])
        with self.assertRaises(ValueError):
            self.stage()

    def test_wrong_historical_verifier_or_changed_analysis_blocks_staging(self):
        self.objects["verify.py"] += b"changed"
        with self.assertRaisesRegex(ValueError, "historical verifier"):
            self.stage()
        self.assertFalse((self.root / "stage").exists())

    def test_changed_current_historical_analysis_blocks_staging(self):
        (self.source / (historical.EXAMPLE + "run_example.py")).write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError, "current historical analysis"):
            self.stage()
        self.assertFalse((self.root / "stage").exists())
