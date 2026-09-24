"""
governed-receipt-spec — attribution claim taxonomy validator (v1).

Three separable identity facts for any AI-assisted change:

  implementation_authorship   who/what wrote the bytes
  automated_review_event      which automated review ran, on which head
  merge_authority             which authority admitted the change to main

A commit message or receipt that UPGRADES a recorded non-approval event
(e.g. "review unavailable", "usage limit, not approval") into an approval
claim is UNSAFE — that is the laundering this taxonomy exists to catch.

States: MEASURED (facts present or negative evidence honestly recorded),
        INCOMPLETE (some facts missing), UNSAFE (contradiction detected),
        BLOCKED (nothing claimable present).

 stdlib only. Scope honesty: this module asserts provenance only —
it does not certify correctness. Doctrine v11. Apache-2.0.
"""

from __future__ import annotations

import hashlib
import json
import re

SCHEMA = "szl.attribution/v1"

AUTHORED_RE = re.compile(r"authored-by-agent:\s*([A-Za-z0-9_.\-]+)")
REVIEWED_RE = re.compile(r"reviewed-by-automation:\s*([A-Za-z0-9_.\-]+)\s*\(scope:\s*([^)]+?)\s*\)")
MERGED_RE = re.compile(r"merged-by:\s*([A-Za-z0-9_.\-]+)")

NON_APPROVAL_PHRASES = (
    "usage limit", "quota-blocked", "unavailable", "not approval",
    "not an approval", "no independent approval", "not counted as approval",
)
HUMAN_APPROVAL_PHRASES = ("human approval", "manually approved", "human-reviewed", "human approved")


def assess(text) -> dict:
    """Attribution audit of one commit message or receipt body."""
    if not isinstance(text, str) or not text.strip():
        return _result("BLOCKED", {}, {}, "empty or non-text input")

    low = text.lower()
    non_approval = [p for p in NON_APPROVAL_PHRASES if p in low]
    claims_human = [p for p in HUMAN_APPROVAL_PHRASES if p in low]

    facts = {}
    m = AUTHORED_RE.search(text)
    if m:
        facts["implementation_authorship"] = m.group(1)
    elif "codex" in low or "chatgpt" in low or "ai agent" in low:
        facts["implementation_authorship_note"] = "ai agent mentioned without marker"

    m = REVIEWED_RE.search(text)
    if m:
        facts["automated_review_event"] = {"tool": m.group(1), "scope": m.group(2)}

    m = MERGED_RE.search(text)
    if m:
        facts["merge_authority"] = m.group(1)

    if non_approval and claims_human:
        return _result("UNSAFE", facts,
                       {"non_approval_phrases": non_approval, "human_approval_claims": claims_human},
                       "recorded non-approval event contradicted by approval claim")

    if len(facts) >= 3:
        return _result("MEASURED", facts, {"non_approval_phrases": non_approval},
                       "all three identity facts carry vocabulary markers")
    if non_approval:
        return _result("MEASURED", facts, {"non_approval_phrases": non_approval},
                       "honest negative evidence recorded: " + ", ".join(non_approval))
    if facts:
        return _result("INCOMPLETE", facts, {"non_approval_phrases": non_approval},
                       "partial attribution; add markers for missing facts")
    return _result("BLOCKED", facts, {}, "no attribution facts present")


def _result(state, facts, flags, reason):
    out = {"schema": SCHEMA, "state": state, "facts": facts, "flags": flags, "reason": reason}
    out["claim_digest"] = hashlib.sha256(
        json.dumps(out, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
    return out
