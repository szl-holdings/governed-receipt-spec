"""Self-consistency of conformance/canonicalization-v1.json (offline, stdlib).

Checks every recorded sha256 against its bytes and reproduces both legacy
profiles with the stdlib json parameters they are defined by. When the
optional ``rfc8785`` reference package is installed, the rfc8785 rows are
checked against it too; otherwise that test is skipped.
"""
import hashlib
import json
import math
import unittest
from pathlib import Path

DOC = json.loads((Path(__file__).resolve().parents[1] / "conformance" /
                  "canonicalization-v1.json").read_text("utf-8"))
LEGACY = {"szl.canon/v1": True, "szl.lambda/v1": False}  # profile -> ensure_ascii


def _decode(x):
    if isinstance(x, dict):
        if set(x) == {"$float"}:
            return float(x["$float"])
        return {k: _decode(v) for k, v in x.items()}
    if isinstance(x, list):
        return [_decode(v) for v in x]
    return x


def _has_nonfinite(v):
    if isinstance(v, float):
        return not math.isfinite(v)
    if isinstance(v, dict):
        return any(_has_nonfinite(w) for w in v.values())
    if isinstance(v, list):
        return any(_has_nonfinite(w) for w in v)
    return False


def _legacy(value, ensure_ascii):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=ensure_ascii, allow_nan=False)


class CanonicalizationVectorTests(unittest.TestCase):
    def test_schema_and_ids(self):
        self.assertEqual(DOC["schema"], "szl.canonicalization.vectors/v1")
        self.assertEqual(DOC["profiles"], ["szl.canon/v1", "szl.lambda/v1", "rfc8785"])
        ids = [c["id"] for c in DOC["cases"]]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertGreaterEqual(len(ids), 18)

    def test_digests_match_bytes(self):
        for case in DOC["cases"]:
            for profile, exp in case["expected"].items():
                if exp.get("reject"):
                    continue
                with self.subTest(case=case["id"], profile=profile):
                    self.assertEqual(
                        hashlib.sha256(exp["utf8"].encode("utf-8")).hexdigest(), exp["sha256"])

    def test_legacy_profiles_reproduce_with_stdlib(self):
        for case in DOC["cases"]:
            value = _decode(case["input"])
            for profile, ensure_ascii in LEGACY.items():
                exp = case["expected"][profile]
                with self.subTest(case=case["id"], profile=profile):
                    if exp.get("reject"):
                        self.assertTrue(_has_nonfinite(value))
                        with self.assertRaises(ValueError):
                            _legacy(value, ensure_ascii)
                    else:
                        self.assertEqual(_legacy(value, ensure_ascii), exp["utf8"])

    def test_rfc8785_rows_against_reference(self):
        try:
            import rfc8785
        except ImportError:
            self.skipTest("optional rfc8785 reference package not installed")
        for case in DOC["cases"]:
            value = _decode(case["input"])
            exp = case["expected"]["rfc8785"]
            with self.subTest(case=case["id"]):
                try:
                    ref = rfc8785.dumps(value)
                except Exception:
                    self.assertTrue(exp.get("reject")
                                    or "rfc8785" in case.get("implementations_may_reject", []))
                    continue
                self.assertFalse(exp.get("reject"))
                self.assertEqual(ref.decode("utf-8"), exp["utf8"])


if __name__ == "__main__":
    unittest.main()
