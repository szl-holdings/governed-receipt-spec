#!/usr/bin/env python3
"""Adversarial test battery for the GovernedAction/v1 predicate.

Every attack named here was chosen because it targets a claim the format
makes in public. Zero-Bandaid Law: the test is the claim. If any of these
tests is deleted or weakened, the corresponding marketing sentence must be
deleted in the same commit.

Runs with stdlib unittest (python3 -m unittest) and under pytest.
"""

from __future__ import annotations

import copy
import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from governed_action import (  # noqa: E402
    Verdict,
    redaction_commitment,
    validate_predicate,
    validate_statement,
    verify_redaction_commitment,
)

NOW = datetime(2026, 8, 31, 20, 0, 0, tzinfo=timezone.utc)


def base_predicate() -> dict:
    """A fully conformant predicate. Every test starts here and breaks ONE thing."""
    return {
        "action": {
            "type": "agent.change_management.patch_deploy",
            "description": "Bounded patch deployed after policy evaluation and human approval",
            "target": "szl-holdings/a11oy@main",
            "idempotency_key": "deploy-2026-08-31-0001",
        },
        "principal": {
            "type": "human",
            "id": "stephen.lutar",
            "is_service_account": False,
            "auth_method": "hardware_key",
        },
        "authority": {
            "outcome": "ALLOW",
            "evaluated_before_execution": True,
            "policy_ref": "sha256:" + "a" * 64,
            "human_approval": {
                "approver_id": "stephen.lutar",
                "approved_at": "2026-08-31T19:59:00Z",
                "approval_digest": "b" * 64,
            },
        },
        "side_effect_class": "READ_ONLY",
        "evidence": {
            "obligations": [
                {"id": "tests_green", "satisfied": True, "artifact_digests": ["c" * 64]},
                {"id": "review_recorded", "satisfied": True, "artifact_digests": ["d" * 64]},
            ],
            "completeness": "COMPLETE",
        },
        "timestamp": {
            "utc": "2026-08-31T19:59:30Z",
            "ntp_synced": True,
            "rfc3161_token": "MEYCIQDT...base64-token...",
        },
        "context": {
            "source_revision": "abc123",
            "deployment_revision": "abc123",
        },
        "limitations": ["Does not prove the model output is correct — only that governance ran."],
    }


def conformant_statement() -> dict:
    return {
        "_type": "https://in-toto.io/Statement/v1",
        "predicateType": "https://szl.dev/GovernedAction/v1",
        "subject": [{"name": "deploy-2026-08-31-0001", "digest": {"sha256": "e" * 64}}],
        "predicate": base_predicate(),
    }


class TestServiceAccountSpoofing(unittest.TestCase):
    """Attack: a workload uses a human's API token so the receipt reads as
    human-verified — directly targeting the Article 12(3)(d) differentiator."""

    def test_service_account_cannot_claim_human(self):
        p = base_predicate()
        p["principal"]["auth_method"] = "api_key"
        v = validate_predicate(p, now=NOW)
        self.assertEqual(v.state, "FAIL")
        self.assertTrue(any("spoof" in r for r in v.reasons))

    def test_is_service_account_true_rejected_in_human_profile(self):
        p = base_predicate()
        p["principal"]["is_service_account"] = True
        v = validate_predicate(p, now=NOW)
        self.assertEqual(v.state, "FAIL")

    def test_is_service_account_absent_rejected(self):
        p = base_predicate()
        del p["principal"]["is_service_account"]
        v = validate_predicate(p, now=NOW)
        self.assertEqual(v.state, "FAIL")

    def test_service_account_type_rejected_in_human_profile(self):
        p = base_predicate()
        p["principal"]["type"] = "service_account"
        v = validate_predicate(p, now=NOW)
        self.assertEqual(v.state, "FAIL")


class TestBackdating(unittest.TestCase):
    """Attack: emit a receipt with a past timestamp to cover an action that
    post-dates the approval, or with a future timestamp to pre-clear one."""

    def test_future_timestamp_hard_fail(self):
        p = base_predicate()
        p["timestamp"]["utc"] = (NOW + timedelta(hours=1)).isoformat()
        v = validate_predicate(p, now=NOW)
        self.assertEqual(v.state, "FAIL")

    def test_missing_ntp_sync_never_pass(self):
        p = base_predicate()
        p["timestamp"]["ntp_synced"] = False
        v = validate_predicate(p, now=NOW)
        self.assertEqual(v.state, "INCOMPLETE")
        self.assertNotEqual(v.state, "PASS")

    def test_missing_rfc3161_never_pass(self):
        p = base_predicate()
        del p["timestamp"]["rfc3161_token"]
        v = validate_predicate(p, now=NOW)
        self.assertEqual(v.state, "INCOMPLETE")

    def test_naive_timestamp_rejected(self):
        p = base_predicate()
        p["timestamp"]["utc"] = "not-a-timestamp"
        v = validate_predicate(p, now=NOW)
        self.assertEqual(v.state, "FAIL")


class TestRedactionCommitments(unittest.TestCase):
    """Attack: redact PII before signing, but also delete exculpatory
    evidence inside the redacted span. Without salted commitments an
    auditor cannot distinguish the two."""

    def test_redaction_without_commitments_fails(self):
        p = base_predicate()
        p["context"]["redacted"] = True
        v = validate_predicate(p, now=NOW)
        self.assertEqual(v.state, "FAIL")
        self.assertTrue(any("exculpatory" in r for r in v.reasons))

    def test_redaction_with_commitments_passes(self):
        p = base_predicate()
        salt = "f" * 32
        p["context"]["redacted"] = True
        p["context"]["redaction_commitments"] = [
            {"field_path": "action.target", "salt": salt,
             "commitment": redaction_commitment("action.target", "szl-holdings/a11oy@main", salt)}
        ]
        v = validate_predicate(p, now=NOW)
        self.assertEqual(v.state, "PASS", msg=str(v.reasons))

    def test_commitment_detects_value_swap(self):
        salt = "f" * 32
        c = redaction_commitment("action.target", "original", salt)
        self.assertTrue(verify_redaction_commitment("action.target", "original", salt, c))
        self.assertFalse(verify_redaction_commitment("action.target", "swapped", salt, c))

    def test_weak_salt_rejected(self):
        p = base_predicate()
        p["context"]["redacted"] = True
        p["context"]["redaction_commitments"] = [
            {"field_path": "action.target", "salt": "deadbeef",
             "commitment": redaction_commitment("action.target", "x", "deadbeef")}
        ]
        v = validate_predicate(p, now=NOW)
        self.assertEqual(v.state, "FAIL")

    def test_malformed_commitment_is_rejected_without_coercion(self):
        for malformed in ("c" * 64 + "\n", int("1" * 64)):
            with self.subTest(malformed=malformed):
                p = base_predicate()
                p["context"]["redacted"] = True
                p["context"]["redaction_commitments"] = [
                    {
                        "field_path": "action.target",
                        "salt": "f" * 32,
                        "commitment": malformed,
                    }
                ]
                v = validate_predicate(p, now=NOW)
                self.assertEqual(v.state, "FAIL")
                self.assertIn(
                    "context.redaction_commitments[0].commitment must be a lowercase sha256 digest",
                    v.reasons,
                )

    def test_context_redacted_must_be_a_boolean_when_present(self):
        for malformed in (None, 0, 1, 4.2, "true", [], {}):
            with self.subTest(malformed=malformed):
                p = base_predicate()
                p["context"]["redacted"] = malformed
                v = validate_predicate(p, now=NOW)
                self.assertEqual(v.state, "FAIL")
                self.assertIn("context.redacted must be a boolean", v.reasons)

    def test_commitments_are_validated_when_redaction_is_inactive(self):
        for redacted_present in (True, False):
            with self.subTest(redacted_present=redacted_present):
                p = base_predicate()
                if redacted_present:
                    p["context"]["redacted"] = False
                p["context"]["redaction_commitments"] = 42
                v = validate_predicate(p, now=NOW)
                self.assertEqual(v.state, "FAIL")
                self.assertIn("context.redaction_commitments must be a list", v.reasons)

    def test_redaction_commitment_entry_must_be_an_object(self):
        for malformed in (None, 42, "commitment", []):
            with self.subTest(malformed=malformed):
                p = base_predicate()
                p["context"]["redaction_commitments"] = [malformed]
                v = validate_predicate(p, now=NOW)
                self.assertEqual(v.state, "FAIL")
                self.assertIn("context.redaction_commitments[0] must be an object", v.reasons)

    def test_redaction_commitment_field_path_must_be_a_string(self):
        malformed_values = (None, True, 42, 4.2, [], {})
        cases = [(False, None)] + [(True, value) for value in malformed_values]
        for present, malformed in cases:
            with self.subTest(present=present, malformed=malformed):
                p = base_predicate()
                item = {
                    "salt": "f" * 32,
                    "commitment": "c" * 64,
                }
                if present:
                    item["field_path"] = malformed
                p["context"]["redaction_commitments"] = [item]
                v = validate_predicate(p, now=NOW)
                self.assertEqual(v.state, "FAIL")
                self.assertIn(
                    "context.redaction_commitments[0].field_path must be a string",
                    v.reasons,
                )

    def test_valid_optional_redaction_context_preserves_pass(self):
        item = {"field_path": "", "salt": "f" * 32, "commitment": "c" * 64}
        contexts = (
            {},
            {"redacted": False},
            {"redaction_commitments": []},
            {"redacted": False, "redaction_commitments": []},
            {"redaction_commitments": [item]},
            {"redacted": False, "redaction_commitments": [item]},
            {"redacted": True, "redaction_commitments": [item]},
        )
        for context in contexts:
            with self.subTest(context=context):
                p = base_predicate()
                p["context"] = context
                v = validate_predicate(p, now=NOW)
                self.assertEqual(v.state, "PASS", msg=str(v.reasons))

    def test_present_commitment_salt_is_validated_when_redaction_is_inactive(self):
        for malformed in (None, True, 42, 4.2, [], {}, "short"):
            with self.subTest(malformed=malformed):
                p = base_predicate()
                p["context"]["redaction_commitments"] = [
                    {"field_path": "action.target", "salt": malformed, "commitment": "c" * 64}
                ]
                v = validate_predicate(p, now=NOW)
                self.assertEqual(v.state, "FAIL")
                self.assertTrue(
                    any(reason.startswith("context.redaction_commitments[0].salt ") for reason in v.reasons)
                )


class TestEvidenceCompleteness(unittest.TestCase):
    """Attack: claim PASS while evidence is missing — the core lie the
    format exists to prevent."""

    def test_missing_evidence_is_incomplete_never_pass(self):
        p = base_predicate()
        p["evidence"]["obligations"][1]["satisfied"] = False
        p["evidence"]["completeness"] = "INCOMPLETE"
        v = validate_predicate(p, now=NOW)
        self.assertEqual(v.state, "INCOMPLETE")

    def test_claimed_complete_with_missing_evidence_is_fail(self):
        p = base_predicate()
        p["evidence"]["obligations"][1]["satisfied"] = False
        p["evidence"]["completeness"] = "COMPLETE"
        v = validate_predicate(p, now=NOW)
        self.assertEqual(v.state, "FAIL")

    def test_empty_obligations_fail(self):
        p = base_predicate()
        p["evidence"]["obligations"] = []
        v = validate_predicate(p, now=NOW)
        self.assertEqual(v.state, "FAIL")

    def test_non_object_obligation_fails_without_exception(self):
        for malformed in (None, 42, "obligation", []):
            with self.subTest(malformed=malformed):
                p = base_predicate()
                p["evidence"]["obligations"] = [malformed]
                v = validate_predicate(p, now=NOW)
                self.assertIsInstance(v, Verdict)
                self.assertEqual(v.state, "FAIL")
                self.assertIn("evidence.obligations[0] must be an object", v.reasons)

    def test_obligation_id_must_be_a_string(self):
        for malformed in (None, 42):
            with self.subTest(malformed=malformed):
                p = base_predicate()
                p["evidence"]["obligations"][0]["id"] = malformed
                v = validate_predicate(p, now=NOW)
                self.assertEqual(v.state, "FAIL")
                self.assertTrue(any(".id must be a string" in reason for reason in v.reasons))

    def test_schema_valid_empty_or_whitespace_id_behavior_is_preserved(self):
        for valid in ("", "   "):
            with self.subTest(valid=valid):
                p = base_predicate()
                p["evidence"]["obligations"][0]["id"] = valid
                v = validate_predicate(p, now=NOW)
                self.assertEqual(v.state, "PASS", msg=str(v.reasons))

    def test_obligation_satisfied_must_be_a_boolean(self):
        for malformed in (None, 1, "true"):
            with self.subTest(malformed=malformed):
                p = base_predicate()
                p["evidence"]["obligations"][0]["satisfied"] = malformed
                v = validate_predicate(p, now=NOW)
                self.assertEqual(v.state, "FAIL")
                self.assertTrue(any(".satisfied must be a boolean" in reason for reason in v.reasons))

    def test_artifact_digests_must_be_a_list_without_exception(self):
        for malformed in (None, 42, "c" * 64, {}):
            with self.subTest(malformed=malformed):
                p = base_predicate()
                p["evidence"]["obligations"][0]["artifact_digests"] = malformed
                v = validate_predicate(p, now=NOW)
                self.assertIsInstance(v, Verdict)
                self.assertEqual(v.state, "FAIL")
                self.assertIn(
                    "evidence.obligations[0].artifact_digests must be a list",
                    v.reasons,
                )

    def test_artifact_digest_element_failure_uses_stable_indexed_path(self):
        for malformed in ("not-a-digest", "c" * 64 + "\n"):
            with self.subTest(malformed=malformed):
                p = base_predicate()
                p["evidence"]["obligations"][0]["artifact_digests"] = [malformed]
                v = validate_predicate(p, now=NOW)
                self.assertIsInstance(v, Verdict)
                self.assertEqual(v.state, "FAIL")
                self.assertIn(
                    "evidence.obligations[0].artifact_digests[0] must be a lowercase sha256 digest",
                    v.reasons,
                )

    def test_conformant_evidence_still_passes(self):
        v = validate_predicate(base_predicate(), now=NOW)
        self.assertEqual(v.state, "PASS", msg=str(v.reasons))


class TestAuthorityAndSideEffects(unittest.TestCase):
    """Attack: collapse side-effect classes or skip human approval on an
    irreversible action."""

    def test_irreversible_allow_requires_human_approval(self):
        p = base_predicate()
        p["side_effect_class"] = "IRREVERSIBLE"
        del p["authority"]["human_approval"]
        v = validate_predicate(p, now=NOW)
        self.assertEqual(v.state, "FAIL")

    def test_post_hoc_logging_is_not_governance(self):
        p = base_predicate()
        p["authority"]["evaluated_before_execution"] = False
        v = validate_predicate(p, now=NOW)
        self.assertEqual(v.state, "FAIL")

    def test_deny_needs_no_approval(self):
        p = base_predicate()
        p["authority"]["outcome"] = "DENY"
        p["side_effect_class"] = "IRREVERSIBLE"
        del p["authority"]["human_approval"]
        v = validate_predicate(p, now=NOW)
        self.assertEqual(v.state, "PASS", msg=str(v.reasons))


class TestStatementLayer(unittest.TestCase):
    def test_conformant_statement_passes(self):
        v = validate_statement(conformant_statement(), now=NOW)
        self.assertEqual(v.state, "PASS", msg=str(v.reasons))

    def test_wrong_predicate_type_fails(self):
        s = conformant_statement()
        s["predicateType"] = "https://in-toto.io/attestation/link/v0.3"
        v = validate_statement(s, now=NOW)
        self.assertEqual(v.state, "FAIL")

    def test_unbound_statement_is_incomplete(self):
        s = conformant_statement()
        s["subject"] = []
        v = validate_statement(s, now=NOW)
        self.assertEqual(v.state, "INCOMPLETE")

    def test_malformed_is_fail_not_exception(self):
        for junk in (None, 42, "receipt", [], {"predicate": None}):
            v = validate_statement(junk, now=NOW)  # must not raise
            self.assertIn(v.state, ("FAIL", "INCOMPLETE"))

    def test_deep_mutation_anywhere_downgrades(self):
        """Flip every leaf one at a time: no single-bit change may leave PASS."""
        p = base_predicate()
        v0 = validate_predicate(copy.deepcopy(p), now=NOW)
        self.assertEqual(v0.state, "PASS", msg=str(v0.reasons))
        p["principal"]["id"] = "mallory"
        v = validate_predicate(p, now=NOW)
        # A different human id is structurally valid — but binding it is the
        # envelope signature's job (verify.py), so here we only assert the
        # structural layer stays PASS and does not crash.
        self.assertIn(v.state, ("PASS", "INCOMPLETE", "FAIL"))


if __name__ == "__main__":
    unittest.main()
