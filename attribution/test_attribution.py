import os, sys
sys.path.insert(0, os.path.dirname(__file__))
from attribution import assess

MARKED = (
    "authored-by-agent: codex-session\n"
    "reviewed-by-automation: github-codex-review (scope: head 0eaa171, 2026-09-24, no major issue)\n"
    "merged-by: human-controlled-protection-rules"
)


def test_fully_marked_is_measured():
    r = assess(MARKED)
    assert r["state"] == "MEASURED"
    assert r["facts"]["implementation_authorship"] == "codex-session"
    assert r["facts"]["automated_review_event"]["tool"] == "github-codex-review"
    assert r["facts"]["merge_authority"] == "human-controlled-protection-rules"


def test_honest_negative_is_measured():
    r = assess("Codex returned a usage limit on this successor, not approval.")
    assert r["state"] == "MEASURED"
    assert "usage limit" in r["flags"]["non_approval_phrases"]


def test_laundering_is_unsafe():
    r = assess("Review was quota-blocked, not approval. Manually approved by reviewer.")
    assert r["state"] == "UNSAFE"
    assert "contradicted" in r["reason"]


def test_empty_and_none_blocked():
    assert assess("")["state"] == "BLOCKED"
    assert assess(None)["state"] == "BLOCKED"


def test_partial_is_incomplete():
    assert assess("merged-by: human-controlled-protection-rules")["state"] == "INCOMPLETE"


def test_determinism():
    assert assess(MARKED)["claim_digest"] == assess(MARKED)["claim_digest"]
