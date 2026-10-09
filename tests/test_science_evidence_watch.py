# SPDX-License-Identifier: Apache-2.0
"""Watch-list transitions. No scientific-validity state is minted."""

from __future__ import annotations

import unittest

from science_evidence.contract import EvidenceStop
from science_evidence.watch import WatchList


def spec(**overrides):
    value = {
        "item_id": "GAP-1",
        "question": "Which measurement is still missing?",
        "source_id": "SRC-1",
        "revision": "rev-a",
        "category": "COVERAGE_MISSING",
        "blocker": "the cited release has no variant coverage",
        "unblock_condition": "a later release contains the named variant and a reviewer accepts it",
        "assumptions": ["one source is not independent corroboration"],
        "external_checks": ["qualified statistical review remains outside this software"],
        "rate_policy": "manual_only",
        "reviewer": "named-reviewer",
        "rights": {"status": "reviewed", "redistribution": "private"},
        "next_permitted_check": "2026-10-09T00:00:00Z",
    }
    value.update(overrides)
    return value


def observation(**overrides):
    value = {
        "event_id": "obs-1",
        "observed_at": "2026-10-09T01:00:00Z",
        "completed": True,
        "accessible": True,
        "source_present": True,
        "metadata_sufficient": True,
        "source_id": "SRC-1",
        "release": "rev-a",
        "condition_met": False,
    }
    value.update(overrides)
    return value


class WatchTests(unittest.TestCase):
    def test_unchanged_release_is_not_scientific_validity(self) -> None:
        watch = WatchList()
        item = watch.add(spec())
        watch.observe("GAP-1", observation())
        self.assertEqual(item["category"], "RELEASE_UNCHANGED")
        self.assertEqual(item["scientific_validity"], "NOT_ESTABLISHED")
        self.assertEqual(item["last_successfully_checked"], "2026-10-09T01:00:00Z")

    def test_changed_release_requires_review(self) -> None:
        watch = WatchList()
        item = watch.add(spec())
        watch.observe("GAP-1", observation(event_id="obs-change", release="rev-b"))
        self.assertEqual(item["machine_state"], "REVIEW_REQUIRED")
        self.assertEqual(item["review_state"], "REVIEW_REQUIRED")
        self.assertNotEqual(item["scientific_validity"], "SCIENTIFICALLY_VALID")

    def test_missing_source_is_unavailable_not_counterevidence(self) -> None:
        watch = WatchList()
        item = watch.add(spec())
        watch.observe("GAP-1", observation(event_id="obs-miss", accessible=False, source_present=False))
        self.assertEqual(item["machine_state"], "UNAVAILABLE")
        self.assertFalse(item["evidence_against_hypothesis"])
        self.assertIsNone(item["last_successfully_checked"])

    def test_insufficient_metadata_does_not_advance_success(self) -> None:
        watch = WatchList()
        item = watch.add(spec())
        watch.observe("GAP-1", observation(event_id="obs-meta", metadata_sufficient=False))
        self.assertEqual(item["category"], "METADATA_INSUFFICIENT")
        self.assertIsNone(item["last_successfully_checked"])

    def test_changed_identifier_requires_review(self) -> None:
        watch = WatchList()
        item = watch.add(spec())
        watch.observe("GAP-1", observation(event_id="obs-id", source_id="SRC-2"))
        self.assertEqual(item["machine_state"], "REVIEW_REQUIRED")
        self.assertEqual(item["history"][-1]["kind"], "IDENTIFIER_CHANGED")

    def test_duplicate_event_does_not_extend_history(self) -> None:
        watch = WatchList()
        item = watch.add(spec())
        watch.observe("GAP-1", observation())
        before = len(item["history"])
        with self.assertRaises(EvidenceStop):
            watch.observe("GAP-1", observation())
        self.assertEqual(len(item["history"]), before)

    def test_interrupted_check_preserves_success_time(self) -> None:
        watch = WatchList()
        item = watch.add(spec())
        watch.observe("GAP-1", observation())
        watch.observe("GAP-1", observation(event_id="obs-stop", observed_at="2026-10-09T02:00:00Z", completed=False))
        self.assertEqual(item["last_successfully_checked"], "2026-10-09T01:00:00Z")
        self.assertEqual(item["freshness"], "INCOMPLETE")

    def test_stale_observation_does_not_advance_success(self) -> None:
        watch = WatchList()
        item = watch.add(spec())
        watch.note_stale("GAP-1", "2026-10-09T03:00:00Z")
        self.assertEqual(item["freshness"], "STALE")
        self.assertIsNone(item["last_successfully_checked"])

    def test_access_loss_after_success_does_not_move_success_time(self) -> None:
        watch = WatchList()
        item = watch.add(spec())
        watch.observe("GAP-1", observation())
        watch.observe("GAP-1", observation(event_id="obs-loss", observed_at="2026-10-09T02:00:00Z", accessible=False))
        self.assertEqual(item["machine_state"], "UNAVAILABLE")
        self.assertEqual(item["last_successfully_checked"], "2026-10-09T01:00:00Z")
        self.assertFalse(item["evidence_against_hypothesis"])

    def test_condition_met_still_needs_human_review(self) -> None:
        watch = WatchList()
        item = watch.add(spec())
        watch.observe("GAP-1", observation(event_id="obs-met", condition_met=True))
        self.assertEqual(item["machine_state"], "UNBLOCK_PENDING_REVIEW")
        self.assertEqual(item["review_state"], "REVIEW_OUTSTANDING")
        self.assertEqual(item["scientific_validity"], "NOT_ESTABLISHED")
        with self.assertRaises(EvidenceStop):
            watch.record_review("GAP-1", {
                "event_id": "rev-1",
                "observed_at": "2026-10-09T04:00:00Z",
                "decision": "SCIENTIFICALLY_VALID",
                "evidence_ref": "external-note",
                "reviewer": "named-reviewer",
            })
        watch.record_review("GAP-1", {
            "event_id": "rev-1",
            "observed_at": "2026-10-09T04:00:00Z",
            "decision": "REVIEW_RECORDED",
            "evidence_ref": "external-note",
            "reviewer": "named-reviewer",
        })
        self.assertEqual(item["machine_state"], "UNBLOCK_RECORDED_BY_REVIEWER")
        self.assertEqual(item["scientific_validity"], "NOT_ESTABLISHED")
        self.assertTrue(item["external_checks"])

    def test_repeated_citation_is_not_independent(self) -> None:
        watch = WatchList()
        item = watch.add(spec())
        watch.cite("GAP-1", "SRC-1")
        watch.cite("GAP-1", "SRC-1")
        self.assertFalse(item["independent_corroboration"])

    def test_checkpoint_does_not_claim_every_observation_ran(self) -> None:
        watch = WatchList()
        item = watch.add(spec())
        watch.advance_checkpoint("GAP-1", "cp-1")
        self.assertEqual(item["checkpoint"], "cp-1")
        self.assertFalse(item["checkpoint_covers_all_observations"])

    def test_private_watch_list_is_not_published(self) -> None:
        watch = WatchList()
        watch.add(spec())
        self.assertEqual(watch.public_projection(), [])


if __name__ == "__main__":
    unittest.main()
