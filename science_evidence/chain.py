# SPDX-License-Identifier: Apache-2.0
"""Evidence-chain and recovery records.

A modeled replay and a posture correction stay separate from an
independently read back recovery. This module does not conclude that
infrastructure was repaired.
"""

from __future__ import annotations

from science_evidence.contract import EvidenceStop


SLOTS = ("source", "tests", "publication", "runtime", "integrity", "authority")
KINDS = frozenset({"MODELED_REPLAY", "POSTURE_CORRECTION", "INDEPENDENTLY_VERIFIED"})
VERIFIED_FIELDS = (
    "before_state",
    "detector",
    "policy_approval",
    "actual_action",
    "after_state",
    "source_identity",
    "independent_readback",
)
LIMITS = {
    "MODELED_REPLAY": "modeled replay only; this is not an infrastructure repair",
    "POSTURE_CORRECTION": "posture correction within the supplied record; serving flow is untouched by this conclusion",
    "INDEPENDENTLY_VERIFIED": "fields are present; repair is not concluded by this software",
}


def evidence_chain(slots: dict) -> dict:
    """Keep source, tests, publication, runtime, integrity, and authority apart."""

    if not isinstance(slots, dict):
        raise EvidenceStop("MISSING_METADATA", "chain must be an object")
    rendered = {}
    for name in SLOTS:
        raw = slots.get(name)
        if not isinstance(raw, dict) or not raw.get("state"):
            rendered[name] = {
                "state": "MISSING",
                "detail": None,
                "digest": None,
                "observed_at": None,
            }
            continue
        digest = raw.get("digest")
        if digest is not None and (not isinstance(digest, str) or len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest)):
            raise EvidenceStop("RECORD_FRAMING", "digest must be a full lowercase sha256")
        rendered[name] = {
            "state": str(raw["state"]),
            "detail": raw.get("detail"),
            "digest": digest,
            "observed_at": raw.get("observed_at"),
        }
    observed = slots.get("observation_time") or None
    refreshed = slots.get("ui_refresh_time") or None
    if slots.get("stale") is None:
        stale = "UNKNOWN"
    else:
        stale = bool(slots.get("stale"))
    distinct = None
    if observed and refreshed:
        distinct = observed != refreshed
    return {
        "schema": "szl-science-evidence-chain/v1",
        "slots": rendered,
        "observation_time": observed or "MISSING",
        "ui_refresh_time": refreshed or "MISSING",
        "times_are_distinct": distinct,
        "stale": stale,
        "digests_truncated": False,
    }


def classify_recovery(record: dict) -> dict:
    """Classify a recovery record without granting a repair conclusion."""

    if not isinstance(record, dict):
        raise EvidenceStop("MISSING_METADATA", "recovery record must be an object")
    kind = record.get("kind")
    if kind not in KINDS:
        raise EvidenceStop("UNSUPPORTED_FORMAT", "recovery kind")
    result = {
        "kind": kind,
        "infrastructure_repaired": False,
        "repair_conclusion": "NOT_CONCLUDED",
        "scientific_validity": "NOT_ESTABLISHED",
        "claim_limit": LIMITS[kind],
    }
    if kind != "INDEPENDENTLY_VERIFIED":
        return result
    missing = [field for field in VERIFIED_FIELDS if not record.get(field)]
    if missing:
        raise EvidenceStop("INCOMPLETE_EXECUTION", ",".join(missing))
    result["before_state"] = record["before_state"]
    result["detector"] = record["detector"]
    result["policy_approval"] = record["policy_approval"]
    result["actual_action"] = record["actual_action"]
    result["after_state"] = record["after_state"]
    result["source_identity"] = record["source_identity"]
    result["independent_readback"] = record["independent_readback"]
    result["readback"] = "MATCH" if record["independent_readback"] == record["after_state"] else "DIVERGENT"
    return result
