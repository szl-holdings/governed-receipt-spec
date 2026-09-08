# SPDX-License-Identifier: Apache-2.0
"""Synthetic regression fixtures, not measurements from the GEO dataset."""
import base64
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("single_cell_example", ROOT / "examples/public-single-cell/run_example.py")
EXAMPLE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(EXAMPLE)


def rows():
    return [["D28-1_1", "D29-1_1"], ["A__chr1", "1.5", "0"],
            ["B__chr2", "0", "2"], ["ERCC-1", "1", "0"]]


class MatrixSummaryTests(unittest.TestCase):
    def test_fractional_processed_values_are_not_rounded_or_called_raw_counts(self):
        result = EXAMPLE.summarize_rows(rows())
        self.assertEqual(result["non_integer_entries"], 1)
        self.assertEqual(result["endogenous_feature_rows"], 2)
        self.assertEqual(result["ercc_feature_rows"], 1)
        self.assertEqual(result["positive_entries"], 3)
        self.assertEqual(result["source_donor_label_count"], 2)
        self.assertFalse(result["parameters"]["differential_expression"])
        self.assertFalse(result["parameters"]["gene_signature_scoring"])

    def test_empty_input_and_header_only_are_rejected(self):
        for data in ([], [rows()[0]]):
            with self.subTest(data=data), self.assertRaises(EXAMPLE.ExampleError):
                EXAMPLE.summarize_rows(data)

    def test_duplicate_cell_and_feature_identifiers_are_rejected(self):
        a = rows()
        a[0][1] = a[0][0]
        b = rows()
        b[2][0] = b[1][0]
        for data in (a, b):
            with self.assertRaises(EXAMPLE.ExampleError):
                EXAMPLE.summarize_rows(data)

    def test_missing_values_are_not_silently_dropped(self):
        data = rows()
        data[1].pop()
        with self.assertRaises(EXAMPLE.ExampleError):
            EXAMPLE.summarize_rows(data)

    def test_nonfinite_negative_or_nonnumeric_values_are_rejected(self):
        for value in ("NaN", "inf", "-1", "missing"):
            data = rows()
            data[1][1] = value
            with self.subTest(value=value), self.assertRaises(ValueError):
                EXAMPLE.summarize_rows(data)

    def test_source_group_labels_must_match_the_declared_parser(self):
        data = rows()
        data[0][0] = "unrecognized"
        with self.assertRaises(EXAMPLE.ExampleError):
            EXAMPLE.summarize_rows(data)

    def test_summary_encoding_is_repeatable(self):
        self.assertEqual(EXAMPLE.canonical(EXAMPLE.summarize_rows(rows())),
                         EXAMPLE.canonical(EXAMPLE.summarize_rows(rows())))


class ReceiptBindingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.verifier = EXAMPLE.load_verifier()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.data, self.summary = root / "fixture", root / "summary.json"
        self.data.write_bytes(b"synthetic unit fixture; not GEO data")
        self.summary.write_bytes(b'{"fixture":true}\n')
        for name, value in (("INPUT_BYTES", self.data.stat().st_size),
                            ("INPUT_SHA256", EXAMPLE.file_sha(self.data))):
            context = patch.object(EXAMPLE, name, value)
            context.start()
            self.addCleanup(context.stop)
        self.receipt = EXAMPLE.make_receipt(self.summary.read_bytes(), self.verifier)

    def verify(self):
        return EXAMPLE.verify_bundle(self.data, self.summary, self.receipt, self.verifier)

    def test_intact_fixture_has_explicitly_no_signature(self):
        self.verify()
        self.assertFalse(self.receipt["signed"])
        self.assertEqual(self.receipt["signatures"], [])

    def test_changed_input_is_rejected(self):
        self.data.write_bytes(b"changed input")
        with self.assertRaises(EXAMPLE.ExampleError):
            self.verify()

    def test_changed_output_is_rejected(self):
        self.summary.write_bytes(b'{"fixture":false}\n')
        with self.assertRaisesRegex(EXAMPLE.ExampleError, "output file"):
            self.verify()

    def test_changed_payload_fails_existing_verifier(self):
        statement = json.loads(base64.b64decode(self.receipt["payload"]))
        statement["predicate"]["claim"] = "altered"
        self.receipt["payload"] = base64.b64encode(EXAMPLE.canonical(statement)).decode()
        with self.assertRaisesRegex(EXAMPLE.ExampleError, "existing receipt verifier"):
            self.verify()

    def test_rehashed_wrong_source_is_not_allowed_by_adapter(self):
        statement = json.loads(base64.b64decode(self.receipt["payload"]))
        statement["predicate"]["input"]["url"] = "https://example.invalid/other"
        self.receipt = EXAMPLE.envelope_for(statement, self.verifier)
        with self.assertRaisesRegex(EXAMPLE.ExampleError, "input metadata"):
            self.verify()

    def test_subject_path_substitution_is_rejected(self):
        statement = json.loads(base64.b64decode(self.receipt["payload"]))
        statement["subject"][0]["name"] = "../other.json"
        self.receipt = EXAMPLE.envelope_for(statement, self.verifier)
        with self.assertRaisesRegex(EXAMPLE.ExampleError, "output file"):
            self.verify()

    def test_example_cannot_inherit_a_signature_claim(self):
        self.receipt["signed"] = True
        with self.assertRaisesRegex(EXAMPLE.ExampleError, "unsigned"):
            self.verify()


if __name__ == "__main__":
    unittest.main()
