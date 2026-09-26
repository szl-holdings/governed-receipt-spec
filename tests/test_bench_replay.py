#!/usr/bin/env python3
"""Offline tests for scripts/replay_bench.py (governed-receipts-bench replay).

The bench layouts are built from this repo's own examples and tampered
fixtures, which are byte-identical to the corresponding bench fixtures, so no
network access is needed. The Hub download path is exercised only for its
input validation and its object-id check.

Run from the repo root:
    python -m unittest discover -s tests -v
"""

import hashlib
import importlib.util
import io
import json
import os
import shutil
import tempfile
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXAMPLES = os.path.join(REPO_ROOT, "examples")
FIXTURES = os.path.join(REPO_ROOT, "tests", "fixtures")

_spec = importlib.util.spec_from_file_location(
    "replay_bench", os.path.join(REPO_ROOT, "scripts", "replay_bench.py"))
replay_bench = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(replay_bench)

# (bench path, source file, expected_result, expected_reason)
SPEC_LAYOUT = [
    ("valid/a11oy-khipu-chain.json", os.path.join(EXAMPLES, "a11oy-khipu-chain.json"), "PASS", None),
    ("valid/readiness-audit-receipt.json", os.path.join(EXAMPLES, "readiness-audit-receipt.json"), "PASS", None),
    ("valid/daily-activity-receipt.json", os.path.join(EXAMPLES, "daily-activity-receipt.json"), "PASS", None),
    ("invalid/tampered-payload.json", os.path.join(FIXTURES, "tampered-payload.json"), "FAIL", None),
    ("invalid/broken-chain.json", os.path.join(FIXTURES, "broken-chain.json"), "FAIL", None),
    ("invalid/lake-inference-receipt.json", os.path.join(EXAMPLES, "lake-inference-receipt.json"), "FAIL", "UNBOUND"),
]


class BenchReplayTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="bench-replay-")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def _layout(self, cases, extra_rows=()):
        rows = []
        for path, source, expected, reason in cases:
            target = os.path.join(self.tmp, *path.split("/"))
            os.makedirs(os.path.dirname(target), exist_ok=True)
            shutil.copyfile(source, target)
            row = {"file": path, "category": path.split("/", 1)[0],
                   "expected_result": expected}
            if reason is not None:
                row["expected_reason"] = reason
            rows.append(row)
        rows.extend(extra_rows)
        with open(os.path.join(self.tmp, "bench.jsonl"), "w", encoding="utf-8") as fh:
            for row in rows:
                fh.write(json.dumps(row) + "\n")

    def _run(self, *extra):
        out = io.StringIO()
        code = replay_bench.main(["--bench-dir", self.tmp] + list(extra), out=out)
        return code, out.getvalue()

    def test_spec_classification_replays_clean(self):
        self._layout(SPEC_LAYOUT)
        code, out = self._run()
        self.assertEqual(code, 0, out)
        self.assertIn("bench replay: 6/6 fixtures match", out)
        self.assertNotIn("MISMATCH", out)

    def test_lake_labelled_valid_pass_is_a_mismatch(self):
        cases = [c for c in SPEC_LAYOUT if "lake" not in c[0]]
        cases.append(("valid/lake-inference-receipt.json",
                      os.path.join(EXAMPLES, "lake-inference-receipt.json"),
                      "PASS", None))
        self._layout(cases)
        code, out = self._run()
        self.assertEqual(code, 1, out)
        self.assertIn("bench replay: 5/6 fixtures match", out)
        mismatched = [ln for ln in out.splitlines() if ln.startswith("MISMATCH")]
        self.assertEqual(len(mismatched), 1, out)
        self.assertIn("valid/lake-inference-receipt.json", mismatched[0])
        self.assertIn("UNBOUND", out)

    def test_fail_for_a_different_reason_is_a_mismatch(self):
        cases = [c if "lake" not in c[0] else c[:3] + ("NOT-A-VERIFIER-TOKEN",)
                 for c in SPEC_LAYOUT]
        self._layout(cases)
        code, out = self._run()
        self.assertEqual(code, 1, out)
        self.assertIn("MISMATCH invalid/lake-inference-receipt.json", out)

    def test_unlisted_fixture_is_rejected(self):
        self._layout(SPEC_LAYOUT)
        shutil.copyfile(os.path.join(EXAMPLES, "a11oy-khipu-chain.json"),
                        os.path.join(self.tmp, "valid", "unlisted.json"))
        code, out = self._run()
        self.assertEqual(code, 2, out)
        self.assertIn("valid/unlisted.json is not listed", out)

    def test_directory_and_expectation_must_agree(self):
        cases = [c if "broken" not in c[0] else ("valid/broken-chain.json",) + c[1:]
                 for c in SPEC_LAYOUT]
        self._layout(cases)
        code, out = self._run()
        self.assertEqual(code, 2, out)
        self.assertIn("valid/ fixtures must expect PASS", out)

    def test_reason_only_allowed_on_fail_rows(self):
        cases = [c if "readiness" not in c[0] else c[:3] + ("UNBOUND",)
                 for c in SPEC_LAYOUT]
        self._layout(cases)
        code, out = self._run()
        self.assertEqual(code, 2, out)
        self.assertIn("expected_reason", out)

    def test_paths_outside_the_layout_are_rejected(self):
        self._layout(SPEC_LAYOUT, extra_rows=[
            {"file": "../verify.py", "category": "valid", "expected_result": "PASS"}])
        code, out = self._run()
        self.assertEqual(code, 2, out)
        self.assertIn("'../verify.py'", out)

    def test_revision_must_be_a_full_commit_sha(self):
        out = io.StringIO()
        code = replay_bench.main(["--revision", "main"], out=out)
        self.assertEqual(code, 2, out.getvalue())
        self.assertIn("40-hex", out.getvalue())

    def test_downloaded_bytes_are_checked_against_hub_object_ids(self):
        data = b'{"k": 1}\n'
        blob = hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()
        self.assertTrue(replay_bench._matches_hub_oid(data, {"oid": blob}))
        self.assertFalse(replay_bench._matches_hub_oid(data + b" ", {"oid": blob}))
        lfs = {"oid": "0" * 40, "lfs": {"oid": hashlib.sha256(data).hexdigest()}}
        self.assertTrue(replay_bench._matches_hub_oid(data, lfs))
        self.assertFalse(replay_bench._matches_hub_oid(data[:-1], lfs))


if __name__ == "__main__":
    unittest.main()
