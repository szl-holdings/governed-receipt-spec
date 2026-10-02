"""Cryptographically valid bytes still require unambiguous, typed JSON evidence."""

import base64
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import governed_action as strict_json
import verify


ROOT = Path(__file__).resolve().parents[1]
SCHEMA = verify.load_schema(str(ROOT / "schema/governed-receipt.schema.json"))


def decision():
    return {"action": "inference", "ns": "synthetic", "seq": 0, "prev": "0" * 64,
            "digest": "a" * 64, "payload_digest": "b" * 64, "ts": 1.0, "decision": "allow"}


def envelope(raw, payload_type="application/json"):
    return {"payloadType": payload_type, "payload": base64.b64encode(raw).decode("ascii"),
            "payloadSha256": hashlib.sha256(raw).hexdigest(), "signed": False, "signatures": []}


class TestVerifierJSONBoundary(unittest.TestCase):
    def assert_rejected(self, records, key=None):
        first = verify.verify_records(records, SCHEMA, key)
        self.assertIs(type(first[0]), bool)
        self.assertFalse(first[0], first[1])
        self.assertEqual(first, verify.verify_records(records, SCHEMA, key))

    def test_real_signed_chain_rejects_duplicate_outer_markers_in_both_orders(self):
        raw = (ROOT / "examples/a11oy-khipu-chain.json").read_text(encoding="utf-8")
        key = (ROOT / "tests/fixtures/cosign.pub").read_bytes()
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "receipts.json"
            for replacement in ('"signed": false, "signed": true', '"signed": true, "signed": false'):
                text = raw.replace('"signed": true', replacement, 1)
                self.assertNotEqual(text, raw)
                path.write_text(text, encoding="utf-8")
                ok, lines = verify.verify_file(str(path), SCHEMA, key)
                self.assertFalse(ok, lines)

    def test_matching_hashes_do_not_authorize_ambiguous_or_nonfinite_json(self):
        positive = json.dumps(decision()).encode()
        self.assertTrue(verify.verify_records([envelope(positive)], SCHEMA)[0])
        cases = [
            positive.replace(b'"decision": "allow"', b'"decision":"deny","decision":"allow"'),
            positive.replace(b'"decision": "allow"', b'"decision":"allow","decision":"deny"'),
            positive.replace(b'"decision": "allow"', b'"decision":"deny","\\u0064ecision":"allow"'),
            *[positive.replace(b'"ts": 1.0', b'"ts":' + token) for token in
              (b"NaN", b"Infinity", b"-Infinity", b"1e10000")],
            b'{"extension":"\\ud800"}',
        ]
        for raw in cases:
            with self.subTest(raw=raw[:40]):
                self.assert_rejected([envelope(raw)])

    def test_declared_json_must_parse_but_opaque_payload_support_is_preserved(self):
        for media_type in ("application/json", "application/vnd.szl.khipu+json", "Application/JSON; charset=utf-8"):
            self.assert_rejected([envelope(b'{"secret-marker":', media_type)])
        self.assertTrue(verify.verify_records([envelope(b"opaque receipt bytes", "application/octet-stream")], SCHEMA)[0])

    def test_nonfinite_outer_values_and_non_json_python_extensions_are_rejected(self):
        for value in (float("nan"), float("inf"), float("-inf"), (), set(), b"bytes"):
            record = decision()
            record["extension"] = value
            self.assert_rejected([record])
        cycle = decision()
        cycle["extension"] = cycle
        self.assert_rejected([cycle])
        for records in (None, False, "records", {}, ()):
            self.assert_rejected(records)

    def test_custom_python_hooks_are_not_invoked(self):
        calls = []

        class Hostile:
            def trap(self, *args):
                calls.append(True)
                raise RuntimeError("custom object hook invoked")
            __bool__ = __eq__ = __str__ = __repr__ = trap

        record = decision()
        record["extension"] = Hostile()
        self.assert_rejected([record])
        class HostileDict(dict):
            __iter__ = __len__ = __bool__ = __eq__ = __str__ = __repr__ = Hostile.trap

        class HostileList(list):
            __iter__ = __len__ = __bool__ = __eq__ = __str__ = __repr__ = Hostile.trap

        for hostile in (HostileDict(), HostileList()):
            record["extension"] = hostile
            self.assert_rejected([record])
            self.assert_rejected(hostile)
        self.assertEqual(calls, [])

    def test_work_nesting_and_unicode_bounds_fail_before_interpretation(self):
        nested = 0
        for _ in range(strict_json.MAX_JSON_DEPTH + 1):
            nested = [nested]
        for extension in (nested, [0] * strict_json.MAX_JSON_NODES, "\ud800"):
            record = decision()
            record["extension"] = extension
            self.assert_rejected([record])
        # Small ordinary extensions still conform, without implying identity
        # or cryptographic provenance for this synthetic clear decision.
        self.assertTrue(verify.verify_records([dict(decision(), extension=[{"ok": True}])], SCHEMA)[0])

    def test_direct_python_integer_cannot_raise_during_diagnostics(self):
        huge = 10 ** 5000
        for value in (huge, -huge):
            self.assert_rejected([dict(decision(), seq=value)])
            self.assert_rejected([dict(decision(), extension=value)])
            for field in ("_pae_sha256", "payloadSha256"):
                record = envelope(json.dumps(decision()).encode())
                record[field] = value
                self.assert_rejected([record])
        # Values within the text profile remain valid as opaque extensions;
        # this does not claim exact protobuf numeric preservation.
        self.assertTrue(verify.verify_records([dict(decision(), extension=10 ** 1000)], SCHEMA)[0])

    def test_wrong_typed_envelope_metadata_and_chain_fields_return_failure(self):
        for kind in ([], {}, True, 42):
            self.assert_rejected([{"dsse": envelope(b'{"kind":"synthetic"}'), "kind": kind}])
        for payload_type in (42, [], None, ""):
            record = envelope(json.dumps(decision()).encode())
            record["payloadType"] = payload_type
            record["_pae_sha256"] = "0" * 64
            self.assert_rejected([record])
        for seq in ("1", [], None, True):
            second = decision()
            second.update(seq=seq, prev="a" * 64)
            self.assert_rejected([decision(), second])

    def test_ite6_conversion_overflow_returns_typed_failure(self):
        good = {"_type": verify.IN_TOTO_STATEMENT_TYPE,
                "subject": [{"digest": {"sha256": "a" * 64}}],
                "predicateType": "https://example.invalid/synthetic", "predicate": {"synthetic": True}}
        for location in ("predicate", "annotations"):
            document = copy.deepcopy(good)
            if location == "predicate":
                document["predicate"]["huge"] = 10 ** 1000
            else:
                document["subject"][0]["annotations"] = {"huge": 10 ** 1000}
            self.assert_rejected([envelope(json.dumps(document).encode(), verify.IN_TOTO_PAYLOAD_TYPE)])

    def test_declared_malformed_envelopes_cannot_disappear_beside_clear_decision(self):
        for payload in ({}, [], None):
            record = dict(decision(), payloadType="application/json", payload=payload,
                          signed=True, signatures=[])
            self.assert_rejected([record])
        for marker in ("dsse", "envelope"):
            for value in (None, [], 42, {"payload": "e30=", "signatures": []},
                          {"signed": True, "signatures": []}):
                for record in ({"payload": decision(), marker: value},
                               {"payload": dict(decision(), **{marker: value})}):
                    self.assert_rejected([record])
        self.assert_rejected([dict(decision(), payloadType="application/json")])

    def test_ite6_input_types_are_not_coerced_into_valid_statements(self):
        good = {"_type": verify.IN_TOTO_STATEMENT_TYPE,
                "subject": [{"digest": {"sha256": "a" * 64}}],
                "predicateType": "https://example.invalid/synthetic", "predicate": {"synthetic": True}}
        for field, value in (("_type", "other"), ("_type", None), ("predicateType", 42),
                             ("predicate", []), ("subject", {})):
            document = copy.deepcopy(good)
            document[field] = value
            self.assert_rejected([envelope(json.dumps(document).encode(), verify.IN_TOTO_PAYLOAD_TYPE)])
        for media_type in (verify.IN_TOTO_PAYLOAD_TYPE, "Application/Vnd.In-Toto+JSON; charset=utf-8"):
            self.assertTrue(verify.verify_records([envelope(json.dumps(good).encode(), media_type)], SCHEMA)[0])
            wrong = dict(good, _type="wrong")
            self.assert_rejected([envelope(json.dumps(wrong).encode(), media_type)])
        for digest in (42, True, None, [], {}, ""):
            document = copy.deepcopy(good)
            document["subject"][0]["digest"]["sha256"] = digest
            self.assert_rejected([envelope(json.dumps(document).encode(), verify.IN_TOTO_PAYLOAD_TYPE)])
        for field in ("name", "uri", "mediaType", "downloadLocation", "content", "annotations"):
            document = copy.deepcopy(good)
            document["subject"][0][field] = 42
            self.assert_rejected([envelope(json.dumps(document).encode(), verify.IN_TOTO_PAYLOAD_TYPE)])
        for content in ("not base64!", "é"):
            document = copy.deepcopy(good)
            document["subject"][0]["content"] = content
            self.assert_rejected([envelope(json.dumps(document).encode(), verify.IN_TOTO_PAYLOAD_TYPE)])
        document = copy.deepcopy(good)
        document["subject"][0].update(uri="https://example.invalid/synthetic", content="YWJj",
                                      mediaType="text/plain", annotations={"synthetic": True})
        self.assertTrue(verify.verify_records([envelope(json.dumps(document).encode(), verify.IN_TOTO_PAYLOAD_TYPE)], SCHEMA)[0])
        self.assertTrue(verify.verify_records([envelope(json.dumps(good).encode(), verify.IN_TOTO_PAYLOAD_TYPE)], SCHEMA)[0])

    def test_json_arrays_and_ndjson_remain_supported_without_relaxing_parser(self):
        rows = [decision(), dict(decision(), seq=1, prev="a" * 64)]
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "records.ndjson"
            for text in (json.dumps(rows), "\n".join(map(json.dumps, rows)) + "\n"):
                path.write_text(text, encoding="utf-8")
                self.assertEqual(verify.load_records(str(path)), rows)
                self.assertTrue(verify.verify_file(str(path), SCHEMA)[0])
            path.write_text(json.dumps(rows[0]) + '\n{"seq":0,"seq":1}', encoding="utf-8")
            self.assertFalse(verify.verify_file(str(path), SCHEMA)[0])

    def test_cli_reports_sanitized_failure_for_invalid_utf8_or_oversized_file(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "input.json"
            for raw in (b'\xff', b" " * (strict_json.MAX_JSON_TEXT_BYTES + 1)):
                path.write_bytes(raw)
                run = subprocess.run([sys.executable, "-B", str(ROOT / "verify.py"), str(path)],
                                     capture_output=True, text=True, timeout=10)
                self.assertEqual(run.returncode, 1, run.stdout + run.stderr)
                self.assertIn("OVERALL: FAIL", run.stdout)
                self.assertNotIn("Traceback", run.stderr)
            path.write_text('{"properties":{},"properties":{}}', encoding="utf-8")
            run = subprocess.run([sys.executable, "-B", str(ROOT / "verify.py"), "--schema", str(path), str(path)],
                                 capture_output=True, text=True, timeout=10)
            self.assertEqual(run.returncode, 1)
            self.assertNotIn("Traceback", run.stderr)


if __name__ == "__main__":
    unittest.main()
