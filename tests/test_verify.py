#!/usr/bin/env python3
"""Standard-library unittest suite for verify.py.

Runs the offline verifier against bound examples, a documented legacy unbound
example, and tampered fixtures. No third-party dependencies.

Run from the repo root:
    python -m unittest discover -s tests -v
or:
    python tests/test_verify.py
"""

import base64
import hashlib
import json
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

    def test_legacy_lake_clear_claims_fail_unbound(self):
        ok, lines = _verify(os.path.join(EXAMPLES, "lake-inference-receipt.json"))
        self.assertFalse(ok)
        self.assertTrue(any("UNBOUND" in line for line in lines), "\n".join(lines))

    def test_lake_clear_claim_tampering_stays_unbound(self):
        path = os.path.join(EXAMPLES, "lake-inference-receipt.json")
        with open(path, "r", encoding="utf-8") as receipt:
            record = json.load(receipt)
        record["payload"]["decision"] = "deny"
        record["payload"]["authorization"] = "arbitrary"
        ok, lines = verify.verify_records([record], SCHEMA)
        self.assertFalse(ok)
        self.assertTrue(any("decision" in line and "UNBOUND" in line for line in lines))
        self.assertTrue(any("authorization" in line for line in lines), "\n".join(lines))

    def test_outer_wrapper_rejects_unsealed_authorization(self):
        path = os.path.join(EXAMPLES, "a11oy-khipu-chain.json")
        with open(path, "r", encoding="utf-8") as receipts:
            records = json.load(receipts)
        records[0]["payload"]["authorization"] = "arbitrary"
        ok, lines = verify.verify_records(records, SCHEMA)
        self.assertFalse(ok)
        self.assertTrue(
            any("authorization" in line and "UNBOUND" in line for line in lines),
            "\n".join(lines),
        )

    def test_top_level_envelope_rejects_unsealed_clear_claim(self):
        path = os.path.join(EXAMPLES, "lake-inference-receipt.json")
        with open(path, "r", encoding="utf-8") as receipt:
            lake = json.load(receipt)
        record = {"dsse": lake["payload"]["dsse"], "decision": "deny"}
        ok, lines = verify.verify_records([record], SCHEMA)
        self.assertFalse(ok)
        self.assertTrue(any("decision" in line and "UNBOUND" in line for line in lines))

    def test_envelope_rejects_unbound_extension_claim(self):
        path = os.path.join(EXAMPLES, "a11oy-khipu-chain.json")
        with open(path, "r", encoding="utf-8") as receipts:
            records = json.load(receipts)
        records[0]["payload"]["envelope"]["authorization"] = "arbitrary"
        ok, lines = verify.verify_records(records, SCHEMA)
        self.assertFalse(ok)
        self.assertTrue(
            any("authorization" in line and "UNBOUND" in line for line in lines),
            "\n".join(lines),
        )

    def test_parent_wrapper_rejects_unsealed_authorization(self):
        path = os.path.join(EXAMPLES, "a11oy-khipu-chain.json")
        with open(path, "r", encoding="utf-8") as receipts:
            records = json.load(receipts)
        records[0]["authorization"] = "arbitrary"
        ok, lines = verify.verify_records(records, SCHEMA)
        self.assertFalse(ok)
        self.assertTrue(any("authorization" in line and "UNBOUND" in line for line in lines))

    def test_nested_receipt_field_is_not_exempt_metadata(self):
        path = os.path.join(EXAMPLES, "lake-inference-receipt.json")
        with open(path, "r", encoding="utf-8") as receipt:
            lake = json.load(receipt)
        record = {"payload": {"dsse": lake["payload"]["dsse"], "ts": "arbitrary"}}
        ok, lines = verify.verify_records([record], SCHEMA)
        self.assertFalse(ok)
        self.assertTrue(any("ts" in line and "UNBOUND" in line for line in lines))

    def test_rejects_unselected_sibling_envelope(self):
        path = os.path.join(EXAMPLES, "a11oy-khipu-chain.json")
        with open(path, "r", encoding="utf-8") as receipts:
            records = json.load(receipts)
        records[0]["payload"]["dsse"] = {"payloadType": "application/json"}
        ok, lines = verify.verify_records(records, SCHEMA)
        self.assertFalse(ok)
        self.assertTrue(any("ambiguous envelope" in line for line in lines), "\n".join(lines))

    def test_rejects_envelopes_across_wrapper_levels(self):
        path = os.path.join(EXAMPLES, "a11oy-khipu-chain.json")
        with open(path, "r", encoding="utf-8") as receipts:
            records = json.load(receipts)
        records[0]["envelope"] = dict(records[0]["payload"]["envelope"])
        ok, lines = verify.verify_records(records, SCHEMA)
        self.assertFalse(ok)
        self.assertTrue(any("ambiguous envelope" in line for line in lines), "\n".join(lines))

    def test_flat_envelope_accepts_opaque_payload(self):
        body = b"opaque receipt bytes"
        envelope = {
            "payloadType": "application/octet-stream",
            "payload": base64.b64encode(body).decode("ascii"),
            "payloadSha256": hashlib.sha256(body).hexdigest(),
            "signed": False,
            "signatures": [],
        }
        ok, lines = verify.verify_records([envelope], SCHEMA)
        self.assertTrue(ok, "\n".join(lines))
        self.assertTrue(any("payloadSha256 verified" in line for line in lines))

    def test_bound_claim_comparison_is_json_type_aware(self):
        path = os.path.join(EXAMPLES, "lake-inference-receipt.json")
        with open(path, "r", encoding="utf-8") as receipt:
            original = json.load(receipt)
        for sealed_value, clear_value in ((True, 1), (False, 0)):
            with self.subTest(sealed=sealed_value, clear=clear_value):
                record = json.loads(json.dumps(original))
                envelope = record["payload"]["dsse"]
                body = json.loads(base64.b64decode(envelope["payload"], validate=True))
                body["authorization"] = sealed_value
                raw = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
                envelope["payload"] = base64.b64encode(raw).decode("ascii")
                envelope["_pae_sha256"] = hashlib.sha256(
                    verify.dsse_pae(envelope["payloadType"], raw)
                ).hexdigest()
                record["payload"]["authorization"] = clear_value
                ok, lines = verify.verify_records([record], SCHEMA)
                self.assertFalse(ok)
                self.assertTrue(
                    any("authorization" in line and "UNBOUND" in line for line in lines),
                    "\n".join(lines),
                )

    def test_spoofed_provenance_markers_do_not_exempt_receipt_fields(self):
        path = os.path.join(EXAMPLES, "readiness-audit-receipt.json")
        with open(path, "r", encoding="utf-8") as receipt:
            envelope = json.load(receipt)
        sealed = json.loads(base64.b64decode(envelope["payload"], validate=True))
        record = {
            "payload": {
                "dsse": envelope,
                "payload": sealed["payload"],
                "id": "attacker-controlled",
                "kind": "receipt",
                "schema": "attacker-controlled",
                "source": "attacker-controlled",
                "ts": "arbitrary",
            }
        }
        ok, lines = verify.verify_records([record], SCHEMA)
        self.assertFalse(ok)
        self.assertTrue(any("ts" in line and "UNBOUND" in line for line in lines))

    def test_top_level_publication_uid_must_match_envelope_pae(self):
        path = os.path.join(EXAMPLES, "a11oy-khipu-chain.json")
        with open(path, "r", encoding="utf-8") as receipts:
            source = json.load(receipts)[0]["payload"]
        for receipt_uid, expected_ok in (
            (source["receipt_uid"], True),
            ("f" * 64, False),
        ):
            with self.subTest(receipt_uid=receipt_uid, expected_ok=expected_ok):
                record = {
                    "envelope": json.loads(json.dumps(source["envelope"])),
                    "asset": "receipt",
                    "receipt_uid": receipt_uid,
                    "scheme": "ecdsa-p256-dsse-pae",
                    "schema": "szl.a11oy.corpus.record/v1",
                }
                ok, lines = verify.verify_records([record], SCHEMA)
                self.assertEqual(expected_ok, ok, "\n".join(lines))
                if not expected_ok:
                    self.assertTrue(
                        any("receipt_uid" in line and "UNBOUND" in line for line in lines),
                        "\n".join(lines),
                    )

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


class DssePaeRuleTests(unittest.TestCase):
    """The spec-pinned PAE encoding: decimal lengths over DECODED payload bytes."""

    def test_dsse_spec_worked_vector(self):
        # The worked example from the DSSE v1 protocol specification.
        self.assertEqual(
            verify.dsse_pae("http://example.com/HelloWorld", b"hello world"),
            b"DSSEv1 29 http://example.com/HelloWorld 11 hello world",
        )

    def test_pae_rejects_non_bytes_payload(self):
        with self.assertRaises(TypeError):
            verify.dsse_pae("application/json", "not-bytes")

    def test_pae_rejects_empty_payload_type(self):
        with self.assertRaises(ValueError):
            verify.dsse_pae("", b"body")


class SignatureVerificationTests(unittest.TestCase):
    """ECDSA P-256 signature verification over the decoded-bytes PAE."""

    @staticmethod
    def _cosign_pub():
        with open(os.path.join(FIXTURES, "cosign.pub"), "rb") as fh:
            return fh.read()

    def _signed_envelope(self):
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec

        priv = ec.generate_private_key(ec.SECP256R1())
        pub_pem = priv.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        payload = b'{"k":"v","n":3600}'
        ptype = "application/vnd.in-toto+json"
        sig = priv.sign(verify.dsse_pae(ptype, payload), ec.ECDSA(hashes.SHA256()))
        envelope = {
            "payloadType": ptype,
            "payload": base64.b64encode(payload).decode("ascii"),
            "signatures": [
                {"keyid": "test", "sig": base64.b64encode(sig).decode("ascii")}
            ],
        }
        return envelope, priv, pub_pem, payload

    def test_pae_length_is_over_decoded_payload_bytes(self):
        envelope, _, pub_pem, payload = self._signed_envelope()
        # base64 text is strictly longer than the decoded payload, so the two
        # length fields can never coincide — a LEN over the base64 text would
        # be a signature-verify bypass.
        self.assertNotEqual(len(envelope["payload"]), len(payload))
        ok, msg = verify.check_signatures(envelope, pub_pem)
        self.assertTrue(ok, msg)
        self.assertIn("1 signature(s) verified", msg)

    def test_signature_over_base64_text_pae_fails(self):
        # Sign a PAE whose LEN covers the base64 TEXT (the bypass class):
        # the verifier must reject it because it recomputes over decoded bytes.
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec

        priv = ec.generate_private_key(ec.SECP256R1())
        pub_pem = priv.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        payload = b'{"k":"v"}'
        ptype = "application/vnd.in-toto+json"
        b64 = base64.b64encode(payload).decode("ascii")
        bad_sig = priv.sign(
            verify.dsse_pae(ptype, b64.encode("ascii")), ec.ECDSA(hashes.SHA256())
        )
        envelope = {
            "payloadType": ptype,
            "payload": b64,
            "signatures": [{"keyid": "x", "sig": base64.b64encode(bad_sig).decode("ascii")}],
        }
        ok, msg = verify.check_signatures(envelope, pub_pem)
        self.assertFalse(ok)
        self.assertIn("mismatch", msg)

    def test_shipped_chain_signatures_verify_with_vendored_key(self):
        ok, lines = verify.verify_file(
            os.path.join(EXAMPLES, "a11oy-khipu-chain.json"),
            SCHEMA,
            self._cosign_pub(),
        )
        self.assertTrue(ok, "\n".join(lines))
        verified = [ln for ln in lines if "signature(s) verified" in ln]
        self.assertEqual(len(verified), 5, "\n".join(lines))

    def test_wrong_key_fails(self):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec

        wrong = ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        ok, lines = verify.verify_file(
            os.path.join(EXAMPLES, "a11oy-khipu-chain.json"), SCHEMA, wrong
        )
        self.assertFalse(ok)
        self.assertTrue(any("signature[0] mismatch" in ln for ln in lines))

    def test_tampered_signature_fails(self):
        with open(os.path.join(EXAMPLES, "a11oy-khipu-chain.json"), "r",
                  encoding="utf-8") as fh:
            records = json.load(fh)
        raw = bytearray(
            base64.b64decode(records[0]["payload"]["envelope"]["signatures"][0]["sig"])
        )
        raw[-1] ^= 0x01
        records[0]["payload"]["envelope"]["signatures"][0]["sig"] = (
            base64.b64encode(bytes(raw)).decode("ascii")
        )
        ok, lines = verify.verify_records(records, SCHEMA, self._cosign_pub())
        self.assertFalse(ok)
        self.assertTrue(any("signature[0]" in ln and "FAIL" in ln for ln in lines),
                        "\n".join(lines))

    def test_no_key_reports_skip_never_pass(self):
        ok, lines = _verify(os.path.join(EXAMPLES, "a11oy-khipu-chain.json"))
        self.assertTrue(ok, "\n".join(lines))
        skips = [ln for ln in lines if "sig:" in ln and "SKIP" in ln]
        self.assertEqual(len(skips), 5, "\n".join(lines))
        self.assertFalse(any("signature(s) verified" in ln for ln in skips))

    def test_non_p256_verify_key_fails(self):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec

        p384 = ec.generate_private_key(ec.SECP384R1()).public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        ok, msg = verify.check_signatures(
            {"payloadType": "application/json",
             "payload": base64.b64encode(b"{}").decode("ascii"),
             "signatures": [{"sig": base64.b64encode(b"x").decode("ascii")}]},
            p384,
        )
        self.assertFalse(ok)
        self.assertIn("not an ECDSA P-256 public key", msg)


class IntotoStatementTests(unittest.TestCase):
    """ITE-6 structural validation via the pinned in-toto-attestation bindings."""

    @staticmethod
    def _statement_envelope(statement):
        body = json.dumps(
            statement, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
        return {
            "payloadType": "application/vnd.in-toto+json",
            "payload": base64.b64encode(body).decode("ascii"),
            "signatures": [],
        }

    def _valid_statement(self):
        return {
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [{"name": "release-42", "digest": {"sha256": "ab" * 32}}],
            "predicateType": "https://szl.dev/GovernedAction/v1",
            "predicate": {"kind": "probe"},
        }

    def test_valid_statement_passes(self):
        ok, msg = verify.check_intoto_statement(
            self._statement_envelope(self._valid_statement())
        )
        self.assertTrue(ok, msg)
        self.assertIn("in-toto-attestation 0.9.3", msg)

    def test_statement_head_matches_locked_demo_format(self):
        # v11 §7.5: b'DSSEv1 28 application/vnd.in-toto+json <len> {"_type":"https://in'
        statement = self._valid_statement()
        body = json.dumps(
            statement, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
        preimage = verify.dsse_pae("application/vnd.in-toto+json", body)
        self.assertRegex(
            preimage,
            rb'^DSSEv1 28 application/vnd\.in-toto\+json \d+ \{"_type":"https://in',
        )

    def test_subject_without_digest_fails(self):
        statement = self._valid_statement()
        statement["subject"] = [{"name": "release-42", "digest": {}}]
        ok, msg = verify.check_intoto_statement(self._statement_envelope(statement))
        self.assertFalse(ok)
        self.assertIn("statement-ite6-invalid", msg)

    def test_empty_predicate_fails(self):
        statement = self._valid_statement()
        statement["predicate"] = {}
        ok, msg = verify.check_intoto_statement(self._statement_envelope(statement))
        self.assertFalse(ok)
        self.assertIn("statement-ite6-invalid", msg)

    def test_non_intoto_payload_is_na(self):
        envelope = {
            "payloadType": "application/vnd.szl.khipu+json",
            "payload": base64.b64encode(b'{"k":"v"}').decode("ascii"),
            "signatures": [],
        }
        ok, msg = verify.check_intoto_statement(envelope)
        self.assertTrue(ok)
        self.assertIn("n/a", msg)


if __name__ == "__main__":
    unittest.main(verbosity=2)
