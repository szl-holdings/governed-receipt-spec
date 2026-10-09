# SPDX-License-Identifier: Apache-2.0
"""Deterministic research-work routing.

These labels are not a clinical triage policy and do not establish
science-domain accuracy. Ambiguous requests stay in REVIEW.
"""

from __future__ import annotations


_LABELS = (
    ("REPRODUCE_SUMMARY", ("reproduce this summary", "reproduce summary")),
    ("CHECK_ARTIFACT", ("check this artifact", "check artifact")),
    ("REVIEW_EVIDENCE_GAP", ("review this missing-evidence condition", "missing evidence", "missing-evidence")),
)


def route_request(text: str) -> dict:
    folded = " ".join(str(text or "").casefold().split())
    hits = [label for label, phrases in _LABELS if any(phrase in folded for phrase in phrases)]
    if len(hits) != 1:
        label = "REVIEW"
        margin = "ambiguous" if hits else "no_label"
    else:
        label = hits[0]
        margin = "single_label"
    return {
        "label": label,
        "margin": margin,
        "review_required": True,
        "clinical_triage": False,
        "science_domain_accuracy": "NOT_ESTABLISHED",
        "qualified_scope": "routing_label_only",
    }
