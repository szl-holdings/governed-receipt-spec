# SPDX-License-Identifier: Apache-2.0
"""Blocked adapters, routing labels, and the synthetic retrieval baseline."""

from __future__ import annotations

import unittest

from science_evidence.registry import classify, legacy_promotable_cannot_override, production_enabled
from science_evidence.retrieval import bm25, evaluate
from science_evidence.triage import route_request


class RegistryTests(unittest.TestCase):
    def test_study5_block_survives_a_legacy_promotable_flag(self) -> None:
        record = classify("SZLHOLDINGS/szl-triage-qwen3.5-0.8b-lora-study5")
        self.assertEqual(record["classification"], "BLOCKED")
        self.assertEqual(record["leakage"]["gate"], "NOT_PROMOTABLE")
        self.assertEqual(record["leakage"]["seed_11_contamination"], "REFUSED")
        self.assertTrue(legacy_promotable_cannot_override(record["model_id"]))
        self.assertFalse(production_enabled(record["model_id"]))
        self.assertEqual(record["safe_loader"], "DO_NOT_LOAD")

    def test_khipu_oac_and_minimembed_are_not_paid_science_models(self) -> None:
        self.assertEqual(classify("SZLHOLDINGS/SZL-Khipu-1.5B")["classification"], "BLOCKED")
        self.assertEqual(classify("SZLHOLDINGS/szl-kernels")["classification"], "RESEARCH_ONLY")
        self.assertEqual(classify("SZLHOLDINGS/oac-system-health-v1")["classification"], "RESEARCH_ONLY")
        self.assertIn("clinical", classify("SZLHOLDINGS/oac-system-health-v1")["prohibited_uses"])
        self.assertEqual(classify("SZLHOLDINGS/oac-ops-health-v2")["classification"], "UNKNOWN")
        self.assertEqual(classify("SZLHOLDINGS/not-a-real-model")["classification"], "UNKNOWN")

    def test_routing_is_not_clinical_and_ambiguous_requests_review(self) -> None:
        reproduce = route_request("Please reproduce this summary")
        self.assertEqual(reproduce["label"], "REPRODUCE_SUMMARY")
        self.assertTrue(reproduce["review_required"])
        self.assertFalse(reproduce["clinical_triage"])
        self.assertEqual(reproduce["science_domain_accuracy"], "NOT_ESTABLISHED")
        self.assertEqual(route_request("check this artifact")["label"], "CHECK_ARTIFACT")
        self.assertEqual(route_request("review this missing-evidence condition")["label"], "REVIEW_EVIDENCE_GAP")
        self.assertEqual(route_request("reproduce this summary and check this artifact")["label"], "REVIEW")
        self.assertEqual(route_request("hello")["label"], "REVIEW")

    def test_bm25_ranks_the_repeated_term_first_and_recall_is_hand_checkable(self) -> None:
        ranked = [doc_id for doc_id, score in bm25("alpha") if score > 0]
        self.assertEqual(ranked[0], "d2")
        self.assertEqual(ranked[1], "d1")
        self.assertNotIn("d3", ranked)
        scored = evaluate("alpha digest", k=2)
        self.assertEqual(scored["recall_at_k"], 1)
        self.assertEqual(scored["embedding_adapter"], "DISABLED")
        self.assertEqual(evaluate("omega unknown")["status"], "ABSTAIN")
        self.assertEqual(evaluate("not in the frozen set")["reason"], "UNJUDGED_QUERY")


if __name__ == "__main__":
    unittest.main()
