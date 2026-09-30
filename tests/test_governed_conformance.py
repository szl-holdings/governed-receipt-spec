"""Portable GovernedAction adapter contracts must reject partial/ambiguous evidence."""

import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from scripts import replay_governed_conformance as replay


ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "conformance/governed-action-v1.json"


class TestGovernedConformance(unittest.TestCase):
    def setUp(self):
        self.raw = CORPUS.read_bytes()
        self.corpus = replay.load_corpus(self.raw)

    def adapter_results(self):
        return {
            "format": "GovernedActionAdapterResults/v1",
            "corpus_sha256": hashlib.sha256(self.raw).hexdigest(),
            "results": [dict(**replay.identity(case), **case["expected"]) for case in self.corpus["cases"]],
        }

    def test_reference_replays_every_case_with_a_fixed_clock(self):
        report = replay.evaluate(self.raw)
        self.assertEqual(report["state"], "PASS")
        self.assertEqual(report["mismatches"], [])
        self.assertEqual(report["verification_time"], "2026-09-19T00:00:00Z")
        self.assertEqual(report["corpus_sha256"], hashlib.sha256(self.raw).hexdigest())
        self.assertEqual(report, replay.evaluate(self.raw))
        self.assertEqual(len(report["results"]), len(self.corpus["cases"]))
        self.assertGreaterEqual(len(report["results"]), 20)
        states = {row["state"] for row in report["results"]}
        stages = {row["stage"] for row in report["results"]}
        self.assertEqual(states, {"PASS", "INCOMPLETE", "FAIL"})
        self.assertEqual(stages, {"parse", "validate"})

    def test_matching_adapter_results_can_be_reordered(self):
        results = self.adapter_results()
        results["results"].reverse()
        report = replay.evaluate(self.raw, json.dumps(results).encode())
        self.assertEqual(report["state"], "PASS")
        self.assertEqual(report["mode"], "compare-reported-adapter-results")
        self.assertEqual(report["results"], self.adapter_results()["results"])

    def test_no_adapter_result_can_be_missing_duplicated_or_unknown(self):
        for mutation in ("missing", "duplicate", "unknown", "empty"):
            with self.subTest(mutation=mutation):
                results = self.adapter_results()
                if mutation == "missing":
                    results["results"].pop()
                elif mutation == "duplicate":
                    results["results"].append(copy.deepcopy(results["results"][0]))
                elif mutation == "unknown":
                    results["results"][0]["id"] = "unknown"
                else:
                    results["results"] = []
                with self.assertRaises(replay.ContractError):
                    replay.evaluate(self.raw, json.dumps(results).encode())

    def test_adapter_binding_is_exact_corpus_bytes_not_semantic_json(self):
        adapter = json.dumps(self.adapter_results()).encode()
        with self.assertRaises(replay.ContractError):
            replay.evaluate(self.raw + b"\n", adapter)
        bad = self.adapter_results()
        bad["corpus_sha256"] = "a" * 64
        with self.assertRaises(replay.ContractError):
            replay.evaluate(self.raw, json.dumps(bad).encode())

    def test_adapter_states_stages_and_shapes_are_strict(self):
        for field, value in (
            ("state", True), ("state", "SUCCESS"), ("state", "UNSIGNED"),
            ("stage", "exception"), ("stage", []), ("extra", "ignored"),
            ("id", None), ("mode", "auto"), ("input_sha256", "a" * 64),
        ):
            with self.subTest(field=field, value=value):
                bad = self.adapter_results()
                bad["results"][0][field] = value
                with self.assertRaises(replay.ContractError):
                    replay.evaluate(self.raw, json.dumps(bad).encode())
        bad = self.adapter_results()
        bad["results"][0].update(stage="parse", state="PASS")
        with self.assertRaises(replay.ContractError):
            replay.evaluate(self.raw, json.dumps(bad).encode())

    def test_adapter_disagreement_cannot_be_reported_as_suite_pass(self):
        bad = self.adapter_results()
        case = next(row for row in bad["results"] if row["state"] == "FAIL" and row["stage"] == "validate")
        case["state"] = "PASS"
        report = replay.evaluate(self.raw, json.dumps(bad).encode())
        self.assertEqual(report["state"], "FAIL")
        self.assertEqual(len(report["mismatches"]), 1)
        self.assertEqual(report["mismatches"][0]["id"], case["id"])

    def test_corpus_shapes_and_clock_are_strict(self):
        mutations = (
            ("format", "other"), ("synthetic", False), ("cases", []),
            ("cases", {}), ("verification_time", "2026-09-19T00:00:00"),
            ("verification_time", "2026-02-30T00:00:00Z"), ("extra", "ignored"),
        )
        for field, value in mutations:
            with self.subTest(field=field, value=value):
                bad = copy.deepcopy(self.corpus)
                bad[field] = value
                with self.assertRaises(replay.ContractError):
                    replay.load_corpus(json.dumps(bad).encode())
        bad = copy.deepcopy(self.corpus)
        bad["cases"].append(copy.deepcopy(bad["cases"][0]))
        with self.assertRaises(replay.ContractError):
            replay.load_corpus(json.dumps(bad).encode())
        for field, value in (("mode", "auto"), ("input_json", {}), ("id", ""), ("extra", 0)):
            bad = copy.deepcopy(self.corpus)
            bad["cases"][0][field] = value
            with self.assertRaises(replay.ContractError):
                replay.load_corpus(json.dumps(bad).encode())

    def test_ambiguous_or_invalid_contract_json_fails_closed(self):
        for raw in (b'{"format":"a","format":"b"}', b'{"x":NaN}', b'\xff', b'[]', b'null'):
            with self.subTest(raw=raw):
                with self.assertRaises(replay.ContractError):
                    replay.load_corpus(raw)
                with self.assertRaises(replay.ContractError):
                    replay.evaluate(self.raw, raw)

    def test_validator_exception_is_a_mismatch_not_an_expected_fail(self):
        with patch.object(replay.governed, "validate_predicate", side_effect=TypeError("secret-payload")):
            report = replay.evaluate(self.raw)
        self.assertEqual(report["state"], "FAIL")
        self.assertTrue(any(row["actual"]["stage"] == "exception" for row in report["mismatches"]))
        self.assertNotIn("secret-payload", json.dumps(report))

    def test_parser_exception_cannot_satisfy_a_parser_rejection(self):
        failures = [self.corpus] + [RuntimeError("secret-parser-payload") for _ in self.corpus["cases"]]
        with patch.object(replay.governed, "parse_json_document", side_effect=failures):
            report = replay.evaluate(self.raw)
        self.assertEqual(report["state"], "FAIL")
        self.assertEqual(len(report["mismatches"]), len(self.corpus["cases"]))
        self.assertTrue(all(row["stage"] == "exception" for row in report["results"]))
        self.assertNotIn("secret-parser-payload", json.dumps(report))

    def test_cli_is_offline_and_returns_distinct_contract_failure(self):
        script = ROOT / "scripts/replay_governed_conformance.py"
        run = subprocess.run([sys.executable, "-B", str(script)], cwd=ROOT.parent,
                             capture_output=True, text=True, timeout=10)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(json.loads(run.stdout)["state"], "PASS")
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "bad.json"
            path.write_text('{"format":"wrong"}', encoding="utf-8")
            run = subprocess.run([sys.executable, "-B", str(script), "--adapter-results", str(path)],
                                 capture_output=True, text=True, timeout=10)
            self.assertEqual(run.returncode, 2)
            self.assertEqual(json.loads(run.stdout)["error"], "INVALID_CONFORMANCE_CONTRACT")
            self.assertNotIn("Traceback", run.stderr)
            bad = self.adapter_results()
            bad["results"][0]["state"] = "FAIL"
            path.write_text(json.dumps(bad), encoding="utf-8")
            run = subprocess.run([sys.executable, "-B", str(script), "--adapter-results", str(path)],
                                 capture_output=True, text=True, timeout=10)
            self.assertEqual(run.returncode, 1)
            self.assertEqual(json.loads(run.stdout)["state"], "FAIL")


if __name__ == "__main__":
    unittest.main()
