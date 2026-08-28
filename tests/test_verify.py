#!/usr/bin/env python3
"""Standard-library unittest suite for verify.py.

Runs the offline verifier against the real example receipts (which must PASS)
and against tampered fixtures (which must FAIL). No third-party dependencies.

Run from the repo root:
    python -m unittest discover -s tests -v
or:
    python tests/test_verify.py
"""

import os
import sys
import tempfile
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

import verify  # noqa: E402

SCHEMA = verify.load_schema(os.path.join(REPO_ROOT, "schema",
                                         "governed-receipt.schema.json"))
EXAMPLES = os.path.join(REPO_ROOT, "examples")
FIXTURES = os.path.join(REPO_ROOT, "tests", "fixtures")


def _verify(path):
    return verify.verify_file(path, SCHEMA)


class ValidExamplesPass(unittest.TestCase):
    def test_a11oy_khipu_chain_passes(self):
        ok, lines = _verify(os.path.join(EXAMPLES, "a11oy-khipu-chain.json"))
        self.assertTrue(ok, "\n".join(lines))
        self.assertTrue(any("hash chain intact" in ln for ln in lines))

    def test_lake_inference_receipt_passes(self):
        ok, lines = _verify(os.path.join(EXAMPLES, "lake-inference-receipt.json"))
        self.assertTrue(ok, "\n".join(lines))

    def test_readiness_audit_receipt_passes(self):
        ok, lines = _verify(os.path.join(EXAMPLES, "readiness-audit-receipt.json"))
        self.assertTrue(ok, "\n".join(lines))
        self.assertTrue(any("payloadSha256 verified" in ln for ln in lines))

    def test_daily_activity_receipt_passes(self):
        ok, lines = _verify(os.path.join(EXAMPLES, "daily-activity-receipt.json"))
        self.assertTrue(ok, "\n".join(lines))


class TamperedFixturesFail(unittest.TestCase):
    def test_tampered_payload_fails_on_hash(self):
        ok, lines = _verify(os.path.join(FIXTURES, "tampered-payload.json"))
        self.assertFalse(ok)
        self.assertTrue(
            any("PAE sha256 mismatch" in ln for ln in lines),
            "expected a content-hash mismatch\n" + "\n".join(lines),
        )

    def test_broken_chain_fails_on_chain(self):
        ok, lines = _verify(os.path.join(FIXTURES, "broken-chain.json"))
        self.assertFalse(ok)
        # the fixture keeps a valid PAE hash so ONLY the chain breaks
        self.assertTrue(
            any(ln.startswith("- chain: FAIL") for ln in lines),
            "expected a chain break\n" + "\n".join(lines),
        )
        self.assertFalse(
            any("PAE sha256 mismatch" in ln for ln in lines),
            "broken-chain fixture should still pass the hash check",
        )


class FailClosedInputTests(unittest.TestCase):
    def test_empty_record_list_fails(self):
        ok, lines = verify.verify_records([], SCHEMA)
        self.assertFalse(ok)
        self.assertTrue(any("no receipt records found" in ln for ln in lines))

    def test_empty_file_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "empty.json")
            with open(path, "w", encoding="utf-8"):
                pass
            ok, lines = _verify(path)
        self.assertFalse(ok)
        self.assertTrue(any("no receipt records found" in ln for ln in lines))

    def test_unsupported_object_fails(self):
        ok, lines = verify.verify_records([{}], SCHEMA)
        self.assertFalse(ok)
        self.assertTrue(any("unsupported record" in ln for ln in lines))

    def test_payload_requires_strict_base64(self):
        envelope = {
            "payloadType": "application/json",
            "payload": "e30=!!!!",
            "payloadSha256": "0" * 64,
            "signed": False,
            "signatures": [],
        }
        decoded, error = verify._decode_envelope_payload(envelope)
        self.assertIsNone(decoded)
        self.assertIn("not valid base64", error)
        ok, message = verify.check_dsse_structure(envelope)
        self.assertFalse(ok)
        self.assertIn("not base64-decodable", message)

    def test_signed_envelope_signature_requires_strict_base64(self):
        envelope = {
            "payloadType": "application/json",
            "payload": "e30=",
            "payloadSha256": "0" * 64,
            "signed": True,
            "signatures": [{"sig": "not-base64!!!!"}],
        }
        ok, message = verify.check_dsse_structure(envelope)
        self.assertFalse(ok)
        self.assertIn("not strict base64", message)

    def test_signature_requires_strict_base64_without_signed_marker(self):
        envelope = {
            "payloadType": "application/json",
            "payload": "e30=",
            "payloadSha256": "0" * 64,
            "signatures": [{"sig": "!!!!"}],
        }
        ok, message = verify.check_dsse_structure(envelope)
        self.assertFalse(ok)
        self.assertIn("not strict base64", message)

    def test_signatures_without_marker_are_reported_as_signed(self):
        envelope = {
            "payloadType": "application/json",
            "payload": "e30=",
            "payloadSha256": "0" * 64,
            "signatures": [{"sig": "c2ln"}],
        }
        ok, message = verify.check_dsse_structure(envelope)
        self.assertTrue(ok, message)
        self.assertIn("well-formed (signed, 1 signature(s))", message)

    def test_false_signed_marker_rejects_declared_signatures(self):
        envelope = {
            "payloadType": "application/json",
            "payload": "e30=",
            "payloadSha256": "0" * 64,
            "signed": False,
            "signatures": [{"sig": "c2ln"}],
        }
        ok, message = verify.check_dsse_structure(envelope)
        self.assertFalse(ok)
        self.assertIn("signed=false but signatures is not empty", message)

    def test_true_signed_marker_requires_a_signature(self):
        envelope = {
            "payloadType": "application/json",
            "payload": "e30=",
            "payloadSha256": "0" * 64,
            "signed": True,
            "signatures": [],
        }
        ok, message = verify.check_dsse_structure(envelope)
        self.assertFalse(ok)
        self.assertIn("signed=true but signatures is empty", message)

    def test_signed_marker_rejects_non_boolean_substitutions(self):
        for marker in (1, "true"):
            with self.subTest(marker=marker):
                envelope = {
                    "payloadType": "application/json",
                    "payload": "e30=",
                    "payloadSha256": "0" * 64,
                    "signed": marker,
                    "signatures": [],
                }
                ok, message = verify.check_dsse_structure(envelope)
                self.assertFalse(ok)
                self.assertIn("signed marker must be a boolean", message)

class SchemaUnitTests(unittest.TestCase):
    def _minimal(self):
        return {
            "action": "inference",
            "ns": "a11oy",
            "seq": 0,
            "prev": "0" * 64,
            "digest": "a" * 64,
            "payload_digest": "b" * 64,
            "ts": 1782629541.5,
        }

    def test_minimal_valid(self):
        self.assertEqual(verify.validate(self._minimal(), SCHEMA), [])

    def test_missing_required_fails(self):
        rec = self._minimal()
        del rec["digest"]
        errs = verify.validate(rec, SCHEMA)
        self.assertTrue(any("digest" in e for e in errs))

    def test_bad_prev_pattern_fails(self):
        rec = self._minimal()
        rec["prev"] = "not-a-hash"
        errs = verify.validate(rec, SCHEMA)
        self.assertTrue(any("pattern" in e for e in errs))

    def test_bad_decision_enum_fails(self):
        rec = self._minimal()
        rec["decision"] = "maybe"
        errs = verify.validate(rec, SCHEMA)
        self.assertTrue(any("enum" in e for e in errs))

    def test_energy_joules_null_ok(self):
        rec = self._minimal()
        rec["energy"] = {"joules": None, "label": "UNAVAILABLE"}
        self.assertEqual(verify.validate(rec, SCHEMA), [])

    def test_iso_timestamp_ok(self):
        rec = self._minimal()
        rec["ts"] = "2026-06-28T00:00:59Z"
        self.assertEqual(verify.validate(rec, SCHEMA), [])

    def test_dsse_pae_matches_real_value(self):
        # DSSE PAE is the documented content-hash scheme; check the primitive.
        body = b'{"hello":"world"}'
        pae = verify.dsse_pae("application/vnd.szl.khipu+json", body)
        self.assertTrue(pae.startswith(b"DSSEv1 "))
        self.assertIn(str(len(body)).encode("ascii"), pae)


if __name__ == "__main__":
    unittest.main(verbosity=2)
