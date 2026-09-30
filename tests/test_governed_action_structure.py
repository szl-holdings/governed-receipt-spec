"""Offline regressions for malformed governance evidence and JSON boundaries."""

import copy
import json
import math
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from decimal import Decimal, Inexact, ROUND_HALF_EVEN, ROUND_UP, localcontext
from pathlib import Path
import unittest

import governed_action as receipt
from governed_action import Verdict, validate_predicate, validate_statement


ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 9, 19, tzinfo=timezone.utc)
MALFORMED = (None, False, True, 0, 42, 4.2, [], ["x"], {}, {"x": "y"})


def statement():
    return json.loads((ROOT / "examples/governed-action-v1-statement.json").read_text(encoding="utf-8"))


class TestGovernedStructure(unittest.TestCase):
    def assert_failure(self, doc, path, *, envelope=False):
        verify = validate_statement if envelope else validate_predicate
        first = verify(copy.deepcopy(doc), now=NOW)
        second = verify(copy.deepcopy(doc), now=NOW)
        self.assertIsInstance(first, Verdict)
        self.assertEqual(first.state, "FAIL", first.reasons)
        self.assertEqual(first, second)
        self.assertTrue(any(reason.startswith(path) for reason in first.reasons), first.reasons)

    def test_required_and_optional_identity_strings_reject_non_strings(self):
        for parent, field in (
            ("action", "description"), ("action", "target"), ("action", "idempotency_key"),
            ("principal", "id"), ("principal", "auth_token_digest"), ("authority", "policy_ref"),
        ):
            for value in MALFORMED:
                with self.subTest(parent=parent, field=field, value=value):
                    p = statement()["predicate"]
                    p[parent][field] = value
                    self.assert_failure(p, f"{parent}.{field}")

    def test_present_approval_must_be_object_even_for_read_only(self):
        for value in MALFORMED:
            if isinstance(value, dict):
                continue
            with self.subTest(value=value):
                p = statement()["predicate"]
                p["authority"]["human_approval"] = value
                self.assert_failure(p, "authority.human_approval")

    def test_approval_required_fields_validate_independently_of_effect_class(self):
        for effect in ("READ_ONLY", "IRREVERSIBLE", "EXTERNALLY_VISIBLE"):
            for field in ("approver_id", "approved_at", "approval_digest"):
                for value in MALFORMED:
                    with self.subTest(effect=effect, field=field, value=value):
                        p = statement()["predicate"]
                        p["side_effect_class"] = effect
                        p["authority"]["human_approval"][field] = value
                        self.assert_failure(p, f"authority.human_approval.{field}")
                p = statement()["predicate"]
                p["side_effect_class"] = effect
                del p["authority"]["human_approval"][field]
                self.assert_failure(p, f"authority.human_approval.{field}")

    def test_approval_digest_requires_whole_lowercase_sha256(self):
        for value in ("", "f" * 63, "f" * 65, "A" * 64, "g" * 64, "f" * 64 + "\n"):
            with self.subTest(value=value):
                p = statement()["predicate"]
                p["authority"]["human_approval"]["approval_digest"] = value
                self.assert_failure(p, "authority.human_approval.approval_digest")

    def test_subject_container_and_entries_are_typed(self):
        for value in (*MALFORMED, "subject"):
            if isinstance(value, list):
                continue
            with self.subTest(container=value):
                doc = statement()
                doc["subject"] = value
                self.assert_failure(doc, "statement.subject", envelope=True)
        for value in (*MALFORMED, "subject"):
            if isinstance(value, dict):
                continue
            with self.subTest(entry=value):
                doc = statement()
                doc["subject"] = [value]
                self.assert_failure(doc, "statement.subject[0]", envelope=True)

    def test_subject_digest_map_and_values_are_typed(self):
        for value in (*MALFORMED, "digest"):
            with self.subTest(digest=value):
                doc = statement()
                doc["subject"][0]["digest"] = value
                if isinstance(value, dict) and value:
                    continue  # Nonstandard immutable-reference algorithms remain extensible.
                self.assert_failure(doc, "statement.subject[0].digest", envelope=True)
        for value in (*MALFORMED, "", "f" * 63, "f" * 65, "F" * 64, "f" * 64 + "\n"):
            with self.subTest(sha256=value):
                doc = statement()
                doc["subject"][0]["digest"]["sha256"] = value
                self.assert_failure(doc, "statement.subject[0].digest", envelope=True)
        doc = statement()
        del doc["subject"][0]["digest"]
        self.assert_failure(doc, "statement.subject[0].digest", envelope=True)

    def test_subject_optional_resource_fields_are_typed(self):
        for field in ("name", "uri", "mediaType", "downloadLocation", "content"):
            for value in MALFORMED:
                with self.subTest(field=field, value=value):
                    doc = statement()
                    doc["subject"][0][field] = value
                    self.assert_failure(doc, f"statement.subject[0].{field}", envelope=True)
        doc = statement()
        doc["subject"][0]["annotations"] = 42
        self.assert_failure(doc, "statement.subject[0].annotations", envelope=True)

    def test_valid_optional_fields_and_digest_agility_are_preserved(self):
        for subject in (
            {"digest": {"sha256": "a" * 64}},
            {"name": "_", "digest": {"sha512": "b" * 128}},
            {"digest": {"gitCommit": "c" * 40}, "annotations": {"measured": False}},
            {"digest": {"custom-immutable-ref": "version-one"}},
        ):
            with self.subTest(subject=subject):
                doc = statement()
                doc["subject"] = [subject]
                self.assertEqual(validate_statement(doc, now=NOW).state, "PASS")
        p = statement()["predicate"]
        del p["authority"]["human_approval"]
        del p["action"]["target"]
        del p["action"]["idempotency_key"]
        self.assertEqual(validate_predicate(p, now=NOW).state, "PASS")

    def test_missing_or_empty_subject_remains_incomplete(self):
        for remove in (True, False):
            doc = statement()
            if remove:
                del doc["subject"]
            else:
                doc["subject"] = []
            self.assertEqual(validate_statement(doc, now=NOW).state, "INCOMPLETE")

    def test_malformed_subject_failure_cannot_be_downgraded(self):
        doc = statement()
        doc["subject"] = 42
        doc["predicate"]["timestamp"]["ntp_synced"] = False
        self.assert_failure(doc, "statement.subject", envelope=True)

    def test_obligation_shapes_and_scalar_artifact_digests_fail_closed(self):
        for value in MALFORMED:
            with self.subTest(obligation=value):
                p = statement()["predicate"]
                p["evidence"]["obligations"] = [value]
                self.assert_failure(p, "evidence.obligations[0]")
        for value in (*MALFORMED, "a" * 64):
            if type(value) is list:
                continue
            with self.subTest(digests=value):
                p = statement()["predicate"]
                p["evidence"]["obligations"][0]["artifact_digests"] = value
                self.assert_failure(p, "evidence.obligations[0].artifact_digests")
        for value in (None, 1, "true", [], {}):
            p = statement()["predicate"]
            p["evidence"]["obligations"][0]["satisfied"] = value
            self.assert_failure(p, "evidence.obligations[0].satisfied")

    def test_schema_optional_fields_reject_wrong_json_types(self):
        for parent, field in (
            ("timestamp", "rfc3161_token"), ("context", "source_revision"),
            ("context", "deployment_revision"),
        ):
            for value in MALFORMED:
                with self.subTest(parent=parent, field=field, value=value):
                    p = statement()["predicate"]
                    p.setdefault(parent, {})[field] = value
                    self.assert_failure(p, f"{parent}.{field}")
        for value in (*MALFORMED, "none", [42]):
            if type(value) is list and all(type(item) is str for item in value):
                continue
            p = statement()["predicate"]
            p["limitations"] = value
            self.assert_failure(p, "limitations")
        p = statement()["predicate"]
        p["context"] = None
        self.assert_failure(p, "context")

    def test_schema_closed_objects_reject_extra_members(self):
        for parent in (None, "action", "principal", "authority", "evidence", "timestamp", "context"):
            with self.subTest(parent=parent):
                p = statement()["predicate"]
                target = p if parent is None else p.setdefault(parent, {})
                target["unexpected"] = "json-but-forbidden"
                self.assert_failure(p, parent or "predicate")

    def test_invalid_completeness_and_ntp_types_cannot_pass(self):
        for value in (*MALFORMED, "OTHER"):
            p = statement()["predicate"]
            p["evidence"]["completeness"] = value
            self.assert_failure(p, "evidence.completeness")
        for value in (None, 0, 1, "true", [], {}):
            p = statement()["predicate"]
            p["timestamp"]["ntp_synced"] = value
            self.assert_failure(p, "timestamp.ntp_synced")

    def test_date_time_profile_rejects_malformed_approval_and_evidence(self):
        invalid = (
            "", "not-a-time", "2026-08-31", "2026-08-31T19:59:30",
            "2026-02-30T00:00:00Z", "0000-01-01T00:00:00Z",
            "2026-W01-1T00:00:00Z", "2026-08-31 19:59:30Z",
            "2026-08-31T19:59:30,5Z", "2026-08-31T19:59:30Z\n",
            "2026-08-31T19:59:30+24:00", "2026-08-31T19:59:30+00:60",
            "2026-08-31T19:59:30+00:00:00", "2026-08-31T19:59:60Z",
        )
        for value in invalid:
            for parent, field in (("timestamp", "utc"), ("authority", "human_approval")):
                with self.subTest(value=value, parent=parent):
                    p = statement()["predicate"]
                    if parent == "timestamp":
                        p[parent][field] = value
                        path = "timestamp.utc"
                    else:
                        p[parent][field]["approved_at"] = value
                        path = "authority.human_approval.approved_at"
                    self.assert_failure(p, path)

    def test_explicit_zone_and_exact_fraction_controls(self):
        for value in (
            "2026-08-31t19:59:30z", "2026-08-31T19:59:30-00:00",
            "2026-08-31T21:59:30+02:00", "2026-08-31T19:59:30.123456789Z",
            "0001-01-01T00:00:00+23:59",
        ):
            p = statement()["predicate"]
            p["timestamp"]["utc"] = value
            self.assertEqual(validate_predicate(p, now=NOW).state, "PASS", value)
        p = statement()["predicate"]
        p["timestamp"]["utc"] = "2026-09-19T00:00:00.000000001Z"
        self.assert_failure(p, "timestamp.utc")

    def test_verification_clock_is_independent_of_decimal_context(self):
        now = NOW.replace(microsecond=149999)
        for precision, rounding in ((1, ROUND_UP), (2, ROUND_HALF_EVEN)):
            with localcontext() as context:
                context.prec = precision
                context.rounding = rounding
                context.traps[Inexact] = True
                for fraction, expected in (("149999", "PASS"), ("149998999", "PASS"), ("149999001", "FAIL"), ("15", "FAIL")):
                    with self.subTest(precision=precision, fraction=fraction):
                        p = statement()["predicate"]
                        p["timestamp"]["utc"] = f"2026-09-19T00:00:00.{fraction}Z"
                        self.assertEqual(validate_predicate(p, now=now).state, expected)
        p["timestamp"]["utc"] = "9999-12-31T23:59:59-23:59"
        self.assert_failure(p, "timestamp.utc")

    def test_schema_valid_assertions_do_not_imply_external_authenticity(self):
        p = statement()["predicate"]
        p["authority"]["human_approval"]["approver_id"] = ""
        p["authority"]["human_approval"]["approved_at"] = "2099-01-01T00:00:00Z"
        p["timestamp"]["rfc3161_token"] = "unverified-token-assertion"
        self.assertEqual(validate_predicate(p, now=NOW).state, "PASS")
        for remove in (False, True):
            q = copy.deepcopy(p)
            if remove:
                del q["timestamp"]["rfc3161_token"]
            else:
                q["timestamp"]["rfc3161_token"] = ""
            self.assertEqual(validate_predicate(q, now=NOW).state, "INCOMPLETE")

    def test_standard_variable_digest_encodings_and_lengths(self):
        for algorithm, maximum in (("shake128", None), ("shake256", None), ("blake2b", 128), ("blake2s", 64), ("gost", None), ("dirHash1", 64)):
            invalid = ["", "x" * 64, "AA", "a", "aa\n", 42, {}, []]
            if maximum:
                invalid.append("a" * (maximum + 2))
            if algorithm == "dirHash1":
                invalid.append("aa")
            for digest in invalid:
                with self.subTest(algorithm=algorithm, digest=digest):
                    doc = statement()
                    doc["subject"] = [{"digest": {algorithm: digest}}]
                    self.assert_failure(doc, "statement.subject[0].digest", envelope=True)
            for length in ((64,) if algorithm == "dirHash1" else (2, maximum or 258)):
                doc = statement()
                doc["subject"] = [{"digest": {algorithm: "a" * length}}]
                self.assertEqual(validate_statement(doc, now=NOW).state, "PASS")

    def assert_json_failure(self, value, *, envelope=True):
        verify = validate_statement if envelope else validate_predicate
        first = verify(value, now=NOW)
        self.assertIsInstance(first, Verdict)
        self.assertEqual(first.state, "FAIL", first.reasons)
        self.assertEqual(first, verify(value, now=NOW))

    def test_cycles_and_non_json_extensions_return_stable_failure(self):
        for value in (set(), (), b"bytes", bytearray(), Decimal("1"), NOW):
            doc = statement()
            doc["subject"][0]["annotations"] = {"unsupported": value}
            self.assert_json_failure(doc)
        cyclic_dict = {}
        cyclic_dict["self"] = cyclic_dict
        cyclic_list = []
        cyclic_list.append(cyclic_list)
        indirect = {"child": []}
        indirect["child"].append(indirect)
        for value in (cyclic_dict, cyclic_list, indirect):
            doc = statement()
            doc["subject"][0]["annotations"] = {"cyclic": value}
            self.assert_json_failure(doc)
        p = statement()["predicate"]
        p["unexpected"] = object()
        self.assert_json_failure(p, envelope=False)

    def test_custom_objects_are_rejected_without_invoking_their_methods(self):
        calls = []

        class Hostile:
            def trap(self, *args):
                calls.append(True)
                raise RuntimeError("custom code executed")
            __bool__ = __str__ = __repr__ = __eq__ = trap

        class HostileDict(dict):
            def items(self):
                raise RuntimeError("custom mapping executed")

        class HostileList(list):
            def __iter__(self):
                raise RuntimeError("custom sequence executed")

        class HostileString(str):
            def __len__(self):
                raise RuntimeError("custom string executed")

        class HostileMeta(type):
            def __eq__(self, other):
                calls.append(True)
                raise RuntimeError("metaclass equality executed")

        class HostileClass(metaclass=HostileMeta):
            pass

        for value in (Hostile(), HostileDict(), HostileList(), HostileString("human"), HostileClass()):
            p = statement()["predicate"]
            p["action"]["description"] = value
            self.assert_json_failure(p, envelope=False)
        self.assertEqual(calls, [])

    def test_unpaired_unicode_is_rejected_before_rendering_a_verdict(self):
        for value in ("\ud800", "\udfff"):
            doc = statement()
            doc["predicate"]["evidence"]["obligations"][0]["id"] = value
            doc["predicate"]["evidence"]["obligations"][0]["satisfied"] = False
            self.assert_json_failure(doc)
            with self.assertRaises(receipt.MalformedJSON):
                receipt.parse_json_document(json.dumps(doc))
        doc = statement()
        doc["subject"][0]["annotations"] = {"\ud800": "bad-key"}
        self.assert_json_failure(doc)
        doc["subject"][0]["annotations"] = {"unicode": "é / 🦙"}
        self.assertEqual(validate_statement(doc, now=NOW).state, "PASS")

    def test_text_limits_measure_utf8_bytes(self):
        text = '"' + "é" * (receipt.MAX_JSON_TEXT_BYTES // 2) + '"'
        with self.assertRaises(receipt.MalformedJSON):
            receipt.parse_json_document(text)
        doc = statement()
        doc["subject"][0]["annotations"] = {"text": "é" * (receipt.MAX_JSON_TEXT_BYTES // 2 + 1)}
        self.assert_json_failure(doc)

    def test_non_string_keys_and_non_finite_numbers_are_rejected(self):
        for key in (None, False, 42, ("tuple",), object()):
            doc = statement()
            doc["subject"][0]["annotations"] = {key: "value"}
            self.assert_json_failure(doc)
        for value in (math.nan, math.inf, -math.inf):
            doc = statement()
            doc["subject"][0]["annotations"] = {"value": value}
            self.assert_json_failure(doc)

    def test_shared_acyclic_json_and_finite_scalars_are_valid(self):
        shared = {"values": [None, True, False, 0, -42, 1.5, -0.0]}
        doc = statement()
        doc["subject"][0]["annotations"] = {"left": shared, "right": shared}
        doc["subject"].append(doc["subject"][0])
        self.assertEqual(validate_statement(doc, now=NOW).state, "PASS")

    def test_json_work_and_nesting_limits_are_bounded(self):
        def nested(depth):
            value = None
            for _ in range(depth):
                value = [value]
            return value
        self.assertIsNone(receipt._json_error(nested(receipt.MAX_JSON_DEPTH), "document"))
        for value in (nested(receipt.MAX_JSON_DEPTH + 1), nested(1500), [0] * receipt.MAX_JSON_NODES):
            self.assert_json_failure(value)
        # Reusing an alias must not bypass the bound at a deeper occurrence.
        alias = nested(receipt.MAX_JSON_DEPTH - 1)
        self.assert_json_failure([alias, [[alias]]])
        dag = []
        for _ in range(20):
            dag = [dag, dag]
        self.assert_json_failure(dag)

    def test_strict_text_parser_rejects_duplicate_keys_and_non_finite_numbers(self):
        texts = (
            '{"satisfied":true,"satisfied":false}',
            '{"satisfied":false,"satisfied":true}',
            '{"same":1,"same":1}', '{"a":1,"\\u0061":2}',
            '{"nested":{"digest":"a","digest":"b"}}',
            '{"value":NaN}', '{"value":Infinity}', '{"value":-Infinity}',
            '{"value":1e10000}', '{"value":-1e10000}',
            '[' * 1500 + '0' + ']' * 1500,
        )
        for text in texts:
            with self.subTest(text=text[:70]):
                with self.assertRaises(receipt.MalformedJSON):
                    receipt.parse_json_document(text)
        self.assertEqual(receipt.parse_json_document('{"a":{"x":1},"b":{"x":2},"A":0}'), {"a": {"x": 1}, "b": {"x": 2}, "A": 0})
        self.assertEqual(receipt.parse_json_document('1e-10000'), 0.0)
        self.assertEqual(validate_statement(receipt.parse_json_document(json.dumps(statement())), now=NOW).state, "PASS")

    def test_cli_returns_failure_without_traceback_for_ambiguous_or_invalid_bytes(self):
        valid = json.dumps(statement()).encode("utf-8")
        cases = (
            valid.replace(b'"ntp_synced": true', b'"ntp_synced": false, "ntp_synced": true'),
            valid.replace(b'"ntp_synced": true', b'"ntp_synced": true, "ntp_synced": false'),
            b'{"value":NaN}', b'\xff',
        )
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "input.json"
            for raw in cases:
                with self.subTest(raw=raw[:60]):
                    path.write_bytes(raw)
                    result = subprocess.run([sys.executable, "-B", str(ROOT / "governed_action.py"), str(path)], capture_output=True, text=True, timeout=10)
                    self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                    self.assertIn("FAIL", result.stdout)
                    self.assertNotIn("Traceback", result.stderr)


if __name__ == "__main__":
    unittest.main()
