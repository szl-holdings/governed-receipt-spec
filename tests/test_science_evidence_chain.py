# SPDX-License-Identifier: Apache-2.0
"""Evidence chain slots and recovery classification."""

from __future__ import annotations

import unittest

from science_evidence.chain import classify_recovery, evidence_chain
from science_evidence.contract import EvidenceStop


DIGEST = "a" * 64


def verified(**overrides):
    value = {
        "kind": "INDEPENDENTLY_VERIFIED",
        "before_state": "serving-down",
        "detector": "named-check",
        "policy_approval": "recorded-approval",
        "actual_action": "restart-one-process",
        "after_state": "serving-up",
        "source_identity": "repo@abc",
        "independent_readback": "serving-up",
        "infrastructure_repaired": True,
    }
    value.update(overrides)
    return value


class ChainTests(unittest.TestCase):
    def test_missing_slots_stay_missing(self) -> None:
        chain = evidence_chain({})
        self.assertEqual([chain["slots"][name]["state"] for name in (
            "source", "tests", "publication", "runtime", "integrity", "authority",
        )], ["MISSING"] * 6)
        self.assertEqual(chain["observation_time"], "MISSING")
        self.assertEqual(chain["ui_refresh_time"], "MISSING")
        self.assertIsNone(chain["times_are_distinct"])
        self.assertEqual(chain["stale"], "UNKNOWN")

    def test_full_digest_is_kept_and_clocks_stay_separate(self) -> None:
        chain = evidence_chain({
            "source": {"state": "OBSERVED", "digest": DIGEST, "observed_at": "2026-10-09T16:00:00Z"},
            "observation_time": "2026-10-09T16:00:00Z",
            "ui_refresh_time": "2026-10-09T16:00:05Z",
            "stale": False,
        })
        self.assertEqual(chain["slots"]["source"]["digest"], DIGEST)
        self.assertEqual(len(chain["slots"]["source"]["digest"]), 64)
        self.assertTrue(chain["times_are_distinct"])
        self.assertFalse(chain["digests_truncated"])
        self.assertEqual(chain["slots"]["runtime"]["state"], "MISSING")
        self.assertIs(chain["stale"], False)

    def test_short_digest_is_rejected(self) -> None:
        with self.assertRaises(EvidenceStop) as caught:
            evidence_chain({"integrity": {"state": "OBSERVED", "digest": "abc"}})
        self.assertEqual(caught.exception.reason, "RECORD_FRAMING")

    def test_modeled_replay_cannot_claim_a_repair(self) -> None:
        result = classify_recovery({"kind": "MODELED_REPLAY", "infrastructure_repaired": True})
        self.assertFalse(result["infrastructure_repaired"])
        self.assertEqual(result["repair_conclusion"], "NOT_CONCLUDED")
        self.assertIn("not an infrastructure repair", result["claim_limit"])

    def test_posture_correction_does_not_touch_serving(self) -> None:
        result = classify_recovery({"kind": "POSTURE_CORRECTION"})
        self.assertFalse(result["infrastructure_repaired"])
        self.assertIn("serving flow is untouched", result["claim_limit"])

    def test_verified_record_without_readback_stops(self) -> None:
        record = verified()
        record["independent_readback"] = ""
        with self.assertRaises(EvidenceStop) as caught:
            classify_recovery(record)
        self.assertEqual(caught.exception.reason, "INCOMPLETE_EXECUTION")

    def test_complete_readback_still_does_not_conclude_repair(self) -> None:
        matched = classify_recovery(verified())
        self.assertEqual(matched["readback"], "MATCH")
        self.assertFalse(matched["infrastructure_repaired"])
        self.assertEqual(matched["repair_conclusion"], "NOT_CONCLUDED")
        divergent = classify_recovery(verified(independent_readback="serving-down"))
        self.assertEqual(divergent["readback"], "DIVERGENT")
        self.assertFalse(divergent["infrastructure_repaired"])


if __name__ == "__main__":
    unittest.main()
