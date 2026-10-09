# SPDX-License-Identifier: Apache-2.0
"""Hand-checked matrix bundles, independent counts, and fresh-process replay."""

from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

from science_evidence.attempts import AttemptBudget
from science_evidence.bundle import build_bundle, canonical, compare_output, compare_source, count_matrix
from science_evidence.contract import MAX_BYTES, EvidenceStop
from science_evidence.reference import summarize
from science_evidence.report import human_report, machine_report, public_catalog


ROOT = Path(__file__).resolve().parents[1]
RIGHTS = {
    "status": "reviewed",
    "basis": "original synthetic table",
    "redistribution": "synthetic file only",
}
MATRIX = b"c1\tc2\nGENE1\t1\t0\nGENE2\t0.5\t2\nERCC-001\t3\t0\n"
EXPECTED = {
    "cell_columns": 2,
    "feature_rows": 3,
    "endogenous_feature_rows": 2,
    "ercc_feature_rows": 1,
    "non_integer_entries": 1,
    "positive_entries": 4,
    "missing_measurements": 0,
    "per_column_endogenous_positive": [2, 1],
    "per_column_ercc_positive": [1, 0],
}


def request(**overrides):
    value = {
        "format": "feature_by_cell_tsv",
        "accession": "SYNTHETIC-MATRIX-1",
        "normalization": "none",
        "rights": RIGHTS,
    }
    value.update(overrides)
    return value


class BundleTests(unittest.TestCase):
    def test_hand_count_matches_both_implementations(self) -> None:
        parsed = count_matrix(MATRIX, request())
        other = summarize(MATRIX, request())
        for key, value in EXPECTED.items():
            self.assertEqual(parsed[key], value, key)
            self.assertEqual(other[key], value, key)
        self.assertEqual(parsed["cell_identifiers"], ["c1", "c2"])

    def test_bundle_keeps_identities_separate_and_passes(self) -> None:
        bundle = build_bundle(MATRIX, request(), AttemptBudget(2))
        self.assertEqual(bundle["status"], "PASS")
        self.assertEqual(bundle["counts"], {"pass": 8, "fail": 0, "skip": 0, "not_run": 0})
        self.assertNotEqual(bundle["raw_input_sha256"], bundle["output_sha256"])
        self.assertEqual(bundle["normalization_policy"].startswith("none"), True)
        self.assertFalse(bundle["signed"])
        self.assertFalse(bundle["biological_claim_validated"])
        self.assertEqual(bundle["attempt"]["terminal"], "COMPLETED")
        text = human_report(bundle)
        self.assertIn("does not establish biological correctness", text)
        self.assertIn("SYNTHETIC-MATRIX-1", text)
        machine_report(bundle)

    def test_zero_is_retained_and_not_counted_as_a_detection(self) -> None:
        parsed = count_matrix(MATRIX, request())
        self.assertEqual(parsed["per_column_endogenous_positive"][1], 1)
        self.assertIn(b"\t0\n", MATRIX)

    def test_ercc_prefix_is_exact(self) -> None:
        raw = b"c1\nErcc-001\t1\nERCC-002\t1\n"
        parsed = count_matrix(raw, request())
        self.assertEqual(parsed["ercc_feature_rows"], 1)
        self.assertEqual(parsed["endogenous_feature_rows"], 1)
        self.assertEqual(summarize(raw, request())["ercc_feature_rows"], 1)

    def test_fresh_process_matches_this_process(self) -> None:
        directory = ROOT / "examples" / "science-evidence"
        result = subprocess.run(
            [sys.executable, "-m", "science_evidence",
             str(directory / "synthetic-matrix.tsv"), str(directory / "request.json")],
            cwd=ROOT,
            capture_output=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        fresh = json.loads(result.stdout.decode())
        local = count_matrix((directory / "synthetic-matrix.tsv").read_bytes(), request())
        self.assertEqual(fresh, local)
        self.assertEqual(canonical(fresh), canonical(local))

    def test_changed_source_and_output_are_rejected(self) -> None:
        bundle = build_bundle(MATRIX, request())
        changed = compare_source(bundle, MATRIX + b"\n")
        self.assertEqual(changed["reason"], "CHANGED_SOURCE")
        summary = dict(bundle["parsed_summary"])
        summary["cell_columns"] = 99
        self.assertEqual(compare_output(bundle, summary)["reason"], "CHANGED_OUTPUT")

    def test_cancel_is_absorbing_and_does_not_run(self) -> None:
        budget = AttemptBudget(2)
        budget.cancel()
        bundle = build_bundle(MATRIX, request(), budget)
        self.assertEqual(bundle["status"], "FAIL")
        self.assertEqual(bundle["reason"], "CANCELLED")
        self.assertEqual(bundle["counts"]["not_run"], 0)
        self.assertEqual(bundle["counts"]["fail"], 1)
        with self.assertRaises(EvidenceStop):
            budget.reserve()

    def test_attempt_limit_is_absorbing(self) -> None:
        budget = AttemptBudget(1)
        self.assertEqual(budget.reserve(), 1)
        with self.assertRaises(EvidenceStop) as caught:
            budget.reserve()
        self.assertEqual(caught.exception.reason, "ATTEMPTS_EXHAUSTED")
        with self.assertRaises(EvidenceStop):
            budget.reserve()

    def test_gse85241_is_retained_and_over_this_budget(self) -> None:
        self.assertGreater(17_005_498, MAX_BYTES)
        record = json.loads((ROOT / "examples" / "public-single-cell" / "observed-run.json").read_text(encoding="utf-8"))
        self.assertEqual(record["summary"]["cell_columns"], 3072)
        self.assertEqual(record["summary"]["endogenous_feature_rows"], 19059)
        self.assertEqual(record["summary"]["ercc_feature_rows"], 81)
        self.assertFalse(record["verification"]["signature_verified"])
        self.assertEqual(record["source_commit"], "160e39b1383a0e249399b6dfb72983b67aef7fe8")

    def test_public_catalog_has_one_narrative(self) -> None:
        catalog = public_catalog()
        self.assertEqual(len(catalog), 1)
        self.assertIn("same facts", catalog[0]["performance_narrative"])
        self.assertNotIn("revenue", json.dumps(catalog).lower())

    def test_fixtures(self) -> None:
        cases = [
            ("malformed", b"c1\nG\tabc\n", "MALFORMED_NUMBER"),
            ("nan", b"c1\nG\tnan\n", "NONFINITE_NUMBER"),
            ("inf", b"c1\nG\tinf\n", "NONFINITE_NUMBER"),
            ("negative", b"c1\nG\t-1\n", "NEGATIVE_VALUE"),
            ("duplicate_feature", b"c1\nG\t1\nG\t2\n", "DUPLICATE_IDENTIFIER"),
            ("duplicate_cell", b"c1\tc1\nG\t1\t1\n", "DUPLICATE_IDENTIFIER"),
            ("missing_accession", b"c1\nG\t1\n", "MISSING_METADATA"),
            ("short_row", b"c1\tc2\nG\t1\n", "INCOMPATIBLE_SHAPE"),
            ("long_row", b"c1\nG\t1\t2\n", "INCOMPATIBLE_SHAPE"),
            ("empty", b"", "EMPTY_INPUT"),
            ("header_only", b"c1\tc2\n", "EMPTY_INPUT"),
            ("blank_row", b"c1\tc2\n\n", "RECORD_FRAMING"),
            ("row_budget", b"c1\nG\t1\nH\t1\n", "SIZE_LIMIT"),
            ("byte_budget", b"c1\nG\t1\n", "SIZE_LIMIT"),
            ("column_budget", b"c1\tc2\nG\t1\t0\n", "SIZE_LIMIT"),
            ("raised_column_budget", b"c1\nG\t1\n", "SIZE_LIMIT"),
            ("raised_byte_budget", b"c1\nG\t1\n", "SIZE_LIMIT"),
            ("bool_budget", b"c1\nG\t1\n", "MISSING_METADATA"),
            ("mtx", b"c1\nG\t1\n", "UNSUPPORTED_FORMAT"),
            ("comma", b"c1,c2\nG,1,0\n", "UNSUPPORTED_FORMAT"),
            ("blank_measurement", b"c1\nG\t\n", "MISSING_MEASUREMENT"),
            ("bom", b"\xef\xbb\xbfc1\nG\t1\n", "RECORD_FRAMING"),
            ("spaced_token", b"c1\nG\t 1\n", "MISSING_MEASUREMENT"),
            ("exponent", b"c1\nG\t1e-1\n", "MALFORMED_NUMBER"),
            ("nul", b"c1\0\nG\t1\n", "RECORD_FRAMING"),
            ("plus_sign", b"c1\nG\t+1\n", "MALFORMED_NUMBER"),
            ("leading_zero", b"c1\nG\t01\n", "MALFORMED_NUMBER"),
            ("negative_infinity", b"c1\nG\t-infinity\n", "NONFINITE_NUMBER"),
            ("rights_basis_missing", b"c1\nG\t1\n", "MISSING_METADATA"),
            ("unreviewed", b"c1\nG\t1\n", "RIGHTS_UNREVIEWED"),
        ]
        self.assertGreaterEqual(len(cases), 24)
        for name, raw, reason in cases:
            with self.subTest(name=name):
                kwargs = {}
                if name == "missing_accession":
                    kwargs["accession"] = ""
                if name == "row_budget":
                    kwargs["max_rows"] = 1
                if name == "byte_budget":
                    kwargs["max_bytes"] = 4
                if name == "column_budget":
                    kwargs["max_columns"] = 1
                if name == "raised_column_budget":
                    kwargs["max_columns"] = 1000
                if name == "raised_byte_budget":
                    kwargs["max_bytes"] = 10_000_000
                if name == "bool_budget":
                    kwargs["max_bytes"] = True
                if name == "mtx":
                    kwargs["format"] = "mtx"
                if name == "comma":
                    kwargs["delimiter"] = ","
                if name == "rights_basis_missing":
                    kwargs["rights"] = {"status": "reviewed", "basis": "", "redistribution": "synthetic file only"}
                if name == "unreviewed":
                    kwargs["rights"] = {"status": "unknown", "basis": "none", "redistribution": "no"}
                bundle = build_bundle(raw, request(**kwargs), AttemptBudget(2))
                self.assertEqual(bundle["status"], "FAIL", name)
                self.assertEqual(bundle["reason"], reason, bundle["detail"])
                self.assertEqual(bundle["counts"]["fail"], 1)
                self.assertIsNone(bundle["parsed_summary"])
                if name not in {"missing_accession", "mtx", "comma", "unreviewed"}:
                    with self.assertRaises(EvidenceStop) as caught:
                        summarize(raw, request(**kwargs))
                    self.assertEqual(caught.exception.reason, reason)


if __name__ == "__main__":
    unittest.main()
