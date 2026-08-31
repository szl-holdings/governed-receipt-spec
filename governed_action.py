#!/usr/bin/env python3
"""GovernedAction/v1 predicate — stdlib-only, fail-closed validator.

Predicate type: https://szl.dev/GovernedAction/v1
Envelope: in-toto Statement (ITE-6), payloadType application/vnd.in-toto+json.

This module validates the predicate object and emits a verification verdict
WITHOUT network access and WITHOUT any dependency beyond the Python standard
library. It is the reference check behind the four fail-closed laws:

  1. Missing evidence => completeness INCOMPLETE; a non-COMPLETE receipt
     NEVER yields verdict PASS.
  2. principal.is_service_account must be false, and a principal claiming
     type "human" while authenticating with "api_key" is rejected as a
     service-account spoof (Article 12(3)(d) posture: verification of a
     consequential action requires an identified natural person).
  3. Verdict PASS requires timestamp.ntp_synced is true AND an
     rfc3161_token present (anti-backdating). A timestamp in the future
     relative to verification time is a hard FAIL.
  4. context.redacted == true without salted-hash redaction_commitments
     is a hard FAIL: an auditor must be able to detect that redaction did
     not remove exculpatory evidence.

Verdicts: PASS / INCOMPLETE / FAIL / UNSIGNED. Malformed input is FAIL with
reasons, never an exception escaping to the caller. Signature verification
is out of scope for this module (see verify.py for the DSSE/ECDSA layer);
a predicate that passes every structural check but carries no envelope
signature is reported UNSIGNED-adjacent via require_signature=False callers
— this module's PASS means "structurally and semantically conformant".

Zero-Bandaid Law: no claim without evidence. UNKNOWN is an audited state;
an absent field is a violation, not a null.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

PREDICATE_TYPE = "https://szl.dev/GovernedAction/v1"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"

SIDE_EFFECT_CLASSES = ("READ_ONLY", "REVERSIBLE", "IRREVERSIBLE", "EXTERNALLY_VISIBLE")
HUMAN_AUTH_METHODS = ("hardware_key", "oidc_interactive", "sso_mfa")
AUTH_METHODS = HUMAN_AUTH_METHODS + ("api_key",)
VERDICTS = ("PASS", "INCOMPLETE", "FAIL", "UNSIGNED")

_SHA256 = re.compile(r"^[0-9a-f]{64}$")


@dataclass
class Verdict:
    state: str = "FAIL"
    reasons: list = field(default_factory=list)

    def fail(self, why: str) -> None:
        if why not in self.reasons:
            self.reasons.append(why)
        self.state = "FAIL"

    def incomplete(self, why: str) -> None:
        if why not in self.reasons:
            self.reasons.append(why)
        if self.state != "FAIL":
            self.state = "INCOMPLETE"

    def ok(self) -> bool:
        return self.state == "PASS"


def _parse_ts(value: Any) -> Optional[datetime]:
    if not isinstance(value, str):
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def redaction_commitment(field_path: str, original_value: str, salt: str) -> str:
    """sha256(salt || field_path || original_value) — the only sanctioned form."""
    h = hashlib.sha256()
    h.update(salt.encode("utf-8"))
    h.update(b"\x00")
    h.update(field_path.encode("utf-8"))
    h.update(b"\x00")
    h.update(original_value.encode("utf-8"))
    return h.hexdigest()


def verify_redaction_commitment(field_path: str, candidate_value: str, salt: str, commitment: str) -> bool:
    """An auditor re-derives the commitment over a candidate original value."""
    return redaction_commitment(field_path, candidate_value, salt) == commitment


def validate_predicate(p: Any, *, now: Optional[datetime] = None) -> Verdict:
    """Fail-closed structural + semantic validation of one predicate object."""
    v = Verdict(state="PASS")
    now = now or datetime.now(timezone.utc)

    if not isinstance(p, dict):
        v.fail("predicate is not an object")
        return v

    # --- action ---
    action = p.get("action")
    if not isinstance(action, dict) or not isinstance(action.get("type"), str) or len(action.get("type", "")) < 3:
        v.fail("action.type missing or too short")
    if not isinstance(action, dict) or not action.get("description"):
        v.fail("action.description missing")

    # --- principal (Article 12(3)(d) posture) ---
    principal = p.get("principal")
    if not isinstance(principal, dict):
        v.fail("principal missing")
    else:
        if principal.get("is_service_account") is not False:
            v.fail("principal.is_service_account must be explicitly false for the human-principal profile")
        ptype = principal.get("type")
        auth = principal.get("auth_method")
        if ptype != "human":
            v.fail(f"principal.type must be 'human' in this profile, got {ptype!r}")
        if auth not in AUTH_METHODS:
            v.fail(f"principal.auth_method unrecognized: {auth!r}")
        elif auth == "api_key":
            # The spoof: a bearer API key is not an identified natural person.
            v.fail("service-account spoof: principal.type=human cannot authenticate with auth_method=api_key")
        if not principal.get("id"):
            v.fail("principal.id missing")

    # --- authority ---
    authority = p.get("authority")
    if not isinstance(authority, dict):
        v.fail("authority missing")
    else:
        if authority.get("outcome") not in ("ALLOW", "DENY", "REQUIRE_HUMAN_APPROVAL"):
            v.fail(f"authority.outcome invalid: {authority.get('outcome')!r}")
        if authority.get("evaluated_before_execution") is not True:
            v.fail("authority.evaluated_before_execution must be true — post-hoc logging is not governance")
        if not authority.get("policy_ref"):
            v.fail("authority.policy_ref missing")

    # --- side effects ---
    sec = p.get("side_effect_class")
    if sec not in SIDE_EFFECT_CLASSES:
        v.fail(f"side_effect_class must be one of {SIDE_EFFECT_CLASSES}, got {sec!r}")
    if sec in ("IRREVERSIBLE", "EXTERNALLY_VISIBLE") and isinstance(authority, dict):
        if authority.get("outcome") == "ALLOW" and not isinstance(authority.get("human_approval"), dict):
            v.fail(f"side_effect_class={sec} with outcome ALLOW requires human_approval")

    # --- evidence ---
    evidence = p.get("evidence")
    if not isinstance(evidence, dict):
        v.fail("evidence missing")
    else:
        obligations = evidence.get("obligations")
        if not isinstance(obligations, list) or not obligations:
            v.fail("evidence.obligations must be a non-empty list")
            obligations = []
        unsatisfied = [o.get("id", "?") for o in obligations if isinstance(o, dict) and o.get("satisfied") is not True]
        completeness = evidence.get("completeness")
        if unsatisfied:
            v.incomplete(f"evidence obligations unsatisfied: {', '.join(map(str, unsatisfied))}")
            if completeness == "COMPLETE":
                v.fail("evidence.completeness claims COMPLETE while obligations are unsatisfied — derived state must never be asserted")
        elif completeness != "COMPLETE":
            v.incomplete("evidence.completeness is not COMPLETE")
        for o in obligations:
            if isinstance(o, dict):
                for d in o.get("artifact_digests", []) or []:
                    if not isinstance(d, str) or not _SHA256.match(d):
                        v.fail(f"obligation {o.get('id', '?')} carries a non-sha256 artifact digest")

    # --- timestamp (anti-backdating) ---
    ts = p.get("timestamp")
    if not isinstance(ts, dict):
        v.fail("timestamp missing")
    else:
        dt = _parse_ts(ts.get("utc"))
        if dt is None:
            v.fail("timestamp.utc missing or not ISO-8601")
        elif dt > now:
            v.fail("timestamp.utc is in the future relative to verification time (backdating/clock attack)")
        if ts.get("ntp_synced") is not True:
            v.incomplete("timestamp.ntp_synced is not true — cannot exclude clock manipulation")
        if not ts.get("rfc3161_token"):
            v.incomplete("timestamp.rfc3161_token absent — no independent time anchor")

    # --- context / redaction ---
    context = p.get("context")
    if context is not None and not isinstance(context, dict):
        v.fail("context must be an object when present")
    if isinstance(context, dict) and context.get("redacted") is True:
        commitments = context.get("redaction_commitments")
        if not isinstance(commitments, list) or not commitments:
            v.fail("context.redacted is true but no redaction_commitments present — redaction could hide exculpatory evidence")
        else:
            for c in commitments:
                if not isinstance(c, dict) or not _SHA256.match(str(c.get("commitment", ""))):
                    v.fail("redaction_commitment entry malformed")
                elif not isinstance(c.get("salt"), str) or len(c["salt"]) < 32:
                    v.fail("redaction_commitment salt too short (<32 hex chars)")

    if v.state == "PASS" and v.reasons:
        v.state = "INCOMPLETE"
    return v


def validate_statement(stmt: Any, *, now: Optional[datetime] = None) -> Verdict:
    """Validate a full in-toto Statement wrapping a GovernedAction/v1 predicate."""
    v = Verdict(state="PASS")
    if not isinstance(stmt, dict):
        v.fail("statement is not an object")
        return v
    if stmt.get("_type") != STATEMENT_TYPE:
        v.fail(f"statement _type must be {STATEMENT_TYPE}")
    if stmt.get("predicateType") != PREDICATE_TYPE:
        v.fail(f"predicateType must be {PREDICATE_TYPE}")
    sub = validate_predicate(stmt.get("predicate"), now=now)
    for r in sub.reasons:
        (v.fail if sub.state == "FAIL" else v.incomplete)(r)
    if sub.state == "FAIL":
        v.state = "FAIL"
    elif sub.state == "INCOMPLETE" and v.state != "FAIL":
        v.state = "INCOMPLETE"
    if not stmt.get("subject"):
        v.incomplete("statement.subject empty — the action is not bound to any artifact digest")
    return v


def main() -> int:
    import json
    import sys

    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    worst = 0
    order = {"PASS": 0, "UNSIGNED": 0, "INCOMPLETE": 1, "FAIL": 2}
    for path in sys.argv[1:]:
        try:
            with open(path, "r", encoding="utf-8") as f:
                doc = json.load(f)
        except (OSError, json.JSONDecodeError) as e:
            print(f"{path}: FAIL (unreadable: {type(e).__name__})")
            worst = max(worst, 2)
            continue
        v = validate_statement(doc) if isinstance(doc, dict) and "_type" in doc else validate_predicate(doc)
        print(f"{path}: {v.state}" + ("" if not v.reasons else " — " + "; ".join(v.reasons)))
        worst = max(worst, order.get(v.state, 2))
    return 1 if worst >= 1 else 0


if __name__ == "__main__":
    raise SystemExit(main())
