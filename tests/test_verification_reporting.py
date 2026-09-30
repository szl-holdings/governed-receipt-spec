"""Negative reporting regressions using inert receipts and public-key fixtures."""

import base64
import contextlib
import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import verify  # noqa: E402


class VerificationReportingTests(unittest.TestCase):
    def setUp(self):
        self.schema = verify.load_schema(verify.DEFAULT_SCHEMA)
        self.key = (ROOT / "tests/fixtures/cosign.pub").read_bytes()

    @staticmethod
    def envelope(signed=True):
        body = b'{"operation":"list","synthetic":true}'
        return {
            "payloadType": "application/json",
            "payload": base64.b64encode(body).decode("ascii"),
            "payloadSha256": hashlib.sha256(body).hexdigest(),
            "signed": signed,
            "signatures": [{"sig": "c3ludGhldGlj"}] if signed else [],
        }

    def run_cli(self, records, with_key=False):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "receipt.json"
            path.write_text(json.dumps(records), encoding="utf-8")
            args = [str(path)]
            if with_key:
                args += ["--verify-key", str(ROOT / "tests/fixtures/cosign.pub")]
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                status = verify.main(args)
        return status, output.getvalue()

    def test_skipped_signature_is_not_a_true_result(self):
        for envelope in (None, self.envelope(), self.envelope(False)):
            with self.subTest(envelope=envelope):
                status, _ = verify.check_signatures(envelope, None)
                self.assertIsNone(status)

    def test_integrity_mode_labels_signature_skip_without_pass(self):
        for signed in (True, False):
            with self.subTest(signed=signed):
                ok, lines = verify.verify_records([self.envelope(signed)], self.schema)
                self.assertTrue(ok, "\n".join(lines))
                signatures = [line.strip() for line in lines if "sig:" in line]
                self.assertEqual(len(signatures), 1)
                self.assertTrue(signatures[0].startswith("sig:    SKIP "))
                self.assertNotIn("PASS", signatures[0])

    def test_integrity_cli_success_is_explicitly_unauthenticated(self):
        status, output = self.run_cli([self.envelope()])
        self.assertEqual(status, 0, output)
        for label in ("RESULT", "OVERALL"):
            self.assertIn(
                label + ": PASS (integrity-only; signatures not authenticated)", output
            )

    def test_key_requires_an_envelope_and_nonempty_signatures(self):
        for envelope in (None, self.envelope(False)):
            with self.subTest(envelope=envelope):
                status, _ = verify.check_signatures(envelope, self.key)
                self.assertIs(status, False)

    def test_key_rejects_unsigned_cli_input(self):
        status, output = self.run_cli([self.envelope(False)], with_key=True)
        self.assertEqual(status, 1, output)
        self.assertIn("sig:    FAIL", output)
        self.assertIn("OVERALL: FAIL", output)

    def test_key_rejects_decoded_decision_without_envelope(self):
        decision = {
            "action": "inference", "ns": "synthetic", "seq": 0,
            "prev": "0" * 64, "digest": "a" * 64,
            "payload_digest": "b" * 64, "ts": 1,
        }
        ok, lines = verify.verify_records([decision], self.schema, self.key)
        self.assertFalse(ok, "\n".join(lines))
        self.assertTrue(any("sig:    FAIL" in line for line in lines))

    def test_invalid_signature_with_key_still_fails(self):
        status, output = self.run_cli([self.envelope()], with_key=True)
        self.assertEqual(status, 1, output)
        self.assertIn("sig:    FAIL", output)
        self.assertIn("OVERALL: FAIL", output)

    def test_verified_public_fixture_reports_supplied_key_scope(self):
        records = json.loads((ROOT / "examples/a11oy-khipu-chain.json").read_text())
        status, output = self.run_cli(records, with_key=True)
        self.assertEqual(status, 0, output)
        self.assertEqual(output.count("sig:    PASS"), len(records))
        self.assertIn("OVERALL: PASS (signatures verified with supplied key; "
                      "trust/authorization not assessed)", output)

    def test_unsigned_record_cannot_inherit_verified_peer_result(self):
        records = json.loads((ROOT / "examples/a11oy-khipu-chain.json").read_text())
        records.append(self.envelope(False))
        status, output = self.run_cli(records, with_key=True)
        self.assertEqual(status, 1, output)
        self.assertIn("sig:    FAIL", output)
        self.assertIn("OVERALL: FAIL", output)

    def test_malformed_signature_list_never_returns_true(self):
        for signatures in (None, {}, "synthetic"):
            for key in (None, self.key):
                with self.subTest(signatures=signatures, key_supplied=key is not None):
                    envelope = self.envelope()
                    envelope["signatures"] = signatures
                    status, _ = verify.check_signatures(envelope, key)
                    self.assertIs(status, False)


if __name__ == "__main__":
    unittest.main()
