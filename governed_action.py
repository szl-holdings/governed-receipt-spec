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
PASS covers this module's structural/profile checks, not signature authenticity,
artifact matching, or RFC 3161 token verification. Token presence and claimed
clock synchronization are assertions, not a verified independent time anchor.
Python callers parsing text must use parse_json_document before validation:
duplicate keys cannot be recovered from an already-collapsed dictionary.

Zero-Bandaid Law: no claim without evidence. UNKNOWN is an audited state;
an absent field is a violation, not a null.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any, Optional

PREDICATE_TYPE = "https://szl.dev/GovernedAction/v1"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"

SIDE_EFFECT_CLASSES = ("READ_ONLY", "REVERSIBLE", "IRREVERSIBLE", "EXTERNALLY_VISIBLE")
HUMAN_AUTH_METHODS = ("hardware_key", "oidc_interactive", "sso_mfa")
AUTH_METHODS = HUMAN_AUTH_METHODS + ("api_key",)
VERDICTS = ("PASS", "INCOMPLETE", "FAIL", "UNSIGNED")

_SHA256 = re.compile(r"[0-9a-f]{64}")
_LOWER_HEX = re.compile(r"[0-9a-f]+")
_DIGEST_LENGTHS = {
    "sha224": (56,), "sha256": (64,), "sha384": (96,), "sha512": (128,),
    "sha512_224": (56,), "sha512_256": (64,), "sha3_224": (56,),
    "sha3_256": (64,), "sha3_384": (96,), "sha3_512": (128,),
    "sha1": (40,), "md5": (32,), "ripemd160": (40,), "sm3": (64,),
    "gitCommit": (40, 64), "gitTree": (40, 64), "gitBlob": (40, 64),
    "gitTag": (40, 64),
    # The upstream heading uses dirHash; its example uses dirHash1.
    "dirHash": (64,), "dirHash1": (64,),
}
_VARIABLE_HEX_DIGESTS = {"shake128": None, "shake256": None, "blake2b": 128, "blake2s": 64, "gost": None}
# Generic GOST is encoding-only: upstream does not select a variant/length.
_DATE_TIME = re.compile(
    r"([0-9]{4})-([0-9]{2})-([0-9]{2})[Tt]([0-9]{2}):([0-9]{2}):([0-9]{2})"
    r"(?:\.([0-9]+))?([Zz]|[+-][0-9]{2}:[0-9]{2})"
)
MAX_JSON_DEPTH = 64  # Root is depth zero; includes scalar leaves.
MAX_JSON_NODES = 100_000  # Count occurrences, not unique object identities.
MAX_JSON_TEXT_BYTES = 4 * 1024 * 1024


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


def _parse_ts(value: Any) -> Optional[tuple[int, Decimal]]:
    """Explicit-zone date-time profile, exact fractions; leap seconds unsupported.

    No silent UTC assumption or truncation of sub-microsecond evidence. This is
    syntax/calendar validation, not timestamp-authority verification.
    """
    if type(value) is not str:
        return None
    match = _DATE_TIME.fullmatch(value)
    if match is None:
        return None
    year, month, day, hour, minute, second, fraction, zone = match.groups()
    try:
        dt = datetime(int(year), int(month), int(day), int(hour), int(minute), int(second))
        offset = 0
        if zone not in ("Z", "z"):
            hours, minutes = int(zone[1:3]), int(zone[4:6])
            if hours > 23 or minutes > 59:
                return None
            offset = (hours * 3600 + minutes * 60) * (1 if zone[0] == "+" else -1)
        seconds = dt.toordinal() * 86400 + dt.hour * 3600 + dt.minute * 60 + dt.second - offset
        return seconds, Decimal("0." + (fraction or "0"))
    except (ValueError, OverflowError):
        return None


def _json_error(value: Any, root: str) -> Optional[str]:
    """Bounded iterative strict-JSON check without invoking custom Python code."""
    stack = [(value, root, 0, False)]
    active = set()
    nodes = 0
    text_bytes = 0
    while stack:
        item, path, depth, leaving = stack.pop()
        if leaving:
            active.remove(id(item))
            continue
        nodes += 1
        if nodes > MAX_JSON_NODES or depth > MAX_JSON_DEPTH:
            return f"{root} exceeds JSON nesting or work limit"
        kind = type(item)
        if kind is str:
            if len(item) > MAX_JSON_TEXT_BYTES:
                return f"{root} exceeds JSON text limit"
            try:
                text_bytes += len(item.encode("utf-8"))
            except UnicodeError:
                return f"{path} contains an invalid Unicode scalar"
        elif kind is float:
            if not math.isfinite(item):
                return f"{path} contains a non-finite JSON number"
        elif kind is dict or kind is list:
            if id(item) in active:
                return f"{path} contains a JSON cycle"
            # Bound the stack before expanding a very broad object/array.
            if len(item) + nodes + len(stack) > MAX_JSON_NODES:
                return f"{root} exceeds JSON nesting or work limit"
            active.add(id(item))
            stack.append((item, path, depth, True))
            if kind is dict:
                for key in item:
                    if type(key) is not str:
                        return f"{path} contains a non-string JSON key"
                    if len(key) > MAX_JSON_TEXT_BYTES:
                        return f"{root} exceeds JSON text limit"
                    try:
                        text_bytes += len(key.encode("utf-8"))
                    except UnicodeError:
                        return f"{path} contains an invalid Unicode scalar"
                for index, child in reversed(list(enumerate(item.values()))):
                    stack.append((child, f"{path}.value[{index}]", depth + 1, False))
            else:
                for index in range(len(item) - 1, -1, -1):
                    stack.append((item[index], f"{path}[{index}]", depth + 1, False))
        elif kind is not type(None) and kind is not bool and kind is not int:
            return f"{path} contains a non-JSON value"
        if text_bytes > MAX_JSON_TEXT_BYTES:
            return f"{root} exceeds JSON text limit"
    return None


def _closed_fields(v: Verdict, obj: dict, path: str, allowed) -> None:
    if any(key not in allowed for key in obj):
        v.fail(f"{path} contains unexpected fields")


class MalformedJSON(ValueError):
    """Sanitized strict-parser failure; never include the input payload."""


def parse_json_document(text: str) -> Any:
    """Reject ambiguous keys/non-finite numbers before receipt interpretation."""
    if type(text) is not str or len(text) > MAX_JSON_TEXT_BYTES:
        raise MalformedJSON("JSON text type or size invalid")
    try:
        if len(text.encode("utf-8")) > MAX_JSON_TEXT_BYTES:
            raise MalformedJSON("JSON byte limit exceeded")
    except UnicodeError:
        raise MalformedJSON("invalid JSON Unicode scalar") from None

    def object_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise MalformedJSON("duplicate JSON member")
            result[key] = value
        return result

    def reject_constant(_value):
        raise MalformedJSON("non-standard JSON numeric constant")

    try:
        result = json.loads(text, object_pairs_hook=object_pairs, parse_constant=reject_constant)
    except MalformedJSON:
        raise
    except (ValueError, RecursionError):
        raise MalformedJSON("malformed or excessively nested JSON") from None
    reason = _json_error(result, "document")
    if reason:
        raise MalformedJSON(reason)
    return result


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


def _string_fields(v: Verdict, obj: dict, path: str, required=(), optional=()) -> None:
    """Check types before truthiness; absent optional evidence remains optional."""
    for name in required:
        if not isinstance(obj.get(name), str):
            v.fail(f"{path}.{name} must be a string")
    for name in optional:
        if name in obj and not isinstance(obj[name], str):
            v.fail(f"{path}.{name} must be a string")


def _validate_subject(v: Verdict, stmt: dict) -> None:
    """Validate Statement/v1 shapes, not signatures or artifact authenticity.

    ResourceDescriptor name is optional; digest is required for a subject.
    Unknown immutable-reference algorithms remain extensible. Checking their
    acceptability and matching a real artifact remain the consumer's policy.
    """
    if "subject" not in stmt or stmt["subject"] == []:
        v.incomplete("statement.subject empty — the action is not bound to any artifact digest")
        return
    subjects = stmt["subject"]
    if not isinstance(subjects, list):
        v.fail("statement.subject must be a list")
        return
    for index, subject in enumerate(subjects):
        path = f"statement.subject[{index}]"
        if not isinstance(subject, dict):
            v.fail(f"{path} must be an object")
            continue
        _string_fields(v, subject, path, optional=("name", "uri", "mediaType", "downloadLocation", "content"))
        if "annotations" in subject and not isinstance(subject["annotations"], dict):
            v.fail(f"{path}.annotations must be an object")
        digests = subject.get("digest")
        if not isinstance(digests, dict) or not digests:
            v.fail(f"{path}.digest must be a non-empty object")
            continue
        for algorithm, digest in digests.items():
            # Avoid reflecting untrusted keys/values into indexed reasons.
            if not isinstance(algorithm, str) or not algorithm:
                v.fail(f"{path}.digest algorithm must be a non-empty string")
            elif not isinstance(digest, str) or not digest:
                v.fail(f"{path}.digest values must be non-empty strings")
            elif algorithm in _DIGEST_LENGTHS and (
                len(digest) not in _DIGEST_LENGTHS[algorithm] or not _LOWER_HEX.fullmatch(digest)
            ):
                v.fail(f"{path}.digest has an invalid standard digest encoding or length")
            elif algorithm in _VARIABLE_HEX_DIGESTS and (
                not _LOWER_HEX.fullmatch(digest) or len(digest) % 2
                or (_VARIABLE_HEX_DIGESTS[algorithm] is not None and len(digest) > _VARIABLE_HEX_DIGESTS[algorithm])
            ):
                v.fail(f"{path}.digest has an invalid standard digest encoding or length")


def validate_predicate(p: Any, *, now: Optional[datetime] = None) -> Verdict:
    """Fail-closed structural + semantic validation of one predicate object."""
    v = Verdict(state="PASS")
    reason = _json_error(p, "predicate")
    if reason:
        v.fail(reason)
        return v
    if now is None:
        now = datetime.now(timezone.utc)
    try:
        if type(now) is not datetime or now.tzinfo is None or now.utcoffset() is None:
            raise ValueError("invalid verification clock")
        current = now.astimezone(timezone.utc)
        now_point = (current.toordinal() * 86400 + current.hour * 3600 + current.minute * 60 + current.second,
                     Decimal(f"0.{current.microsecond:06d}"))
    except Exception:
        v.fail("verification time must be a supported timezone-aware datetime")
        return v

    if not isinstance(p, dict):
        v.fail("predicate is not an object")
        return v
    _closed_fields(v, p, "predicate", ("action", "principal", "authority", "side_effect_class", "evidence", "timestamp", "context", "limitations"))

    # --- action ---
    action = p.get("action")
    if isinstance(action, dict):
        _closed_fields(v, action, "action", ("type", "description", "target", "idempotency_key"))
        _string_fields(v, action, "action", required=("type", "description"), optional=("target", "idempotency_key"))
    if not isinstance(action, dict) or not isinstance(action.get("type"), str) or len(action.get("type", "")) < 3:
        v.fail("action.type missing or too short")
    if not isinstance(action, dict) or not action.get("description"):
        v.fail("action.description missing")

    # --- principal (Article 12(3)(d) posture) ---
    principal = p.get("principal")
    if not isinstance(principal, dict):
        v.fail("principal missing")
    else:
        _closed_fields(v, principal, "principal", ("type", "id", "is_service_account", "auth_method", "auth_token_digest"))
        _string_fields(v, principal, "principal", required=("type", "id", "auth_method"), optional=("auth_token_digest",))
        if principal.get("is_service_account") is not False:
            v.fail("principal.is_service_account must be explicitly false for the human-principal profile")
        ptype = principal.get("type")
        auth = principal.get("auth_method")
        if ptype != "human":
            v.fail("principal.type must be 'human' in this profile")
        if auth not in AUTH_METHODS:
            v.fail("principal.auth_method unrecognized")
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
        _closed_fields(v, authority, "authority", ("outcome", "evaluated_before_execution", "policy_ref", "human_approval"))
        _string_fields(v, authority, "authority", required=("outcome", "policy_ref"))
        if authority.get("outcome") not in ("ALLOW", "DENY", "REQUIRE_HUMAN_APPROVAL"):
            v.fail("authority.outcome invalid")
        if authority.get("evaluated_before_execution") is not True:
            v.fail("authority.evaluated_before_execution must be true — post-hoc logging is not governance")
        if not authority.get("policy_ref"):
            v.fail("authority.policy_ref missing")
        if "human_approval" in authority:
            approval = authority["human_approval"]
            path = "authority.human_approval"
            if not isinstance(approval, dict):
                v.fail(f"{path} must be an object")
            else:
                _string_fields(v, approval, path, required=("approver_id", "approved_at", "approval_digest"))
                if _parse_ts(approval.get("approved_at")) is None:
                    v.fail(f"{path}.approved_at must be an explicit-zone date-time; leap seconds unsupported")
                digest = approval.get("approval_digest")
                if not isinstance(digest, str) or not _SHA256.fullmatch(digest):
                    v.fail(f"{path}.approval_digest must be a lowercase sha256 digest")

    # --- side effects ---
    sec = p.get("side_effect_class")
    if sec not in SIDE_EFFECT_CLASSES:
        v.fail(f"side_effect_class must be one of {SIDE_EFFECT_CLASSES}")
    if sec in ("IRREVERSIBLE", "EXTERNALLY_VISIBLE") and isinstance(authority, dict):
        if authority.get("outcome") == "ALLOW" and not isinstance(authority.get("human_approval"), dict):
            v.fail(f"side_effect_class={sec} with outcome ALLOW requires human_approval")

    # --- evidence ---
    evidence = p.get("evidence")
    if not isinstance(evidence, dict):
        v.fail("evidence missing")
    else:
        _closed_fields(v, evidence, "evidence", ("obligations", "completeness"))
        obligations = evidence.get("obligations")
        if not isinstance(obligations, list) or not obligations:
            v.fail("evidence.obligations must be a non-empty list")
            obligations = []
        unsatisfied = []
        for index, obligation in enumerate(obligations):
            if not isinstance(obligation, dict):
                v.fail(f"evidence.obligations[{index}] must be an object")
                continue

            obligation_id = obligation.get("id")
            if not isinstance(obligation_id, str):
                v.fail(f"evidence.obligations[{index}].id must be a string")
                obligation_id = f"index {index}"

            satisfied = obligation.get("satisfied")
            if not isinstance(satisfied, bool):
                v.fail(f"evidence.obligations[{index}].satisfied must be a boolean")
            elif not satisfied:
                unsatisfied.append(obligation_id)

            digests = obligation.get("artifact_digests", [])
            if not isinstance(digests, list):
                v.fail(f"evidence.obligations[{index}].artifact_digests must be a list")
                continue
            for digest_index, digest in enumerate(digests):
                if not isinstance(digest, str) or not _SHA256.fullmatch(digest):
                    v.fail(
                        f"evidence.obligations[{index}].artifact_digests[{digest_index}] "
                        "must be a lowercase sha256 digest"
                    )

        completeness = evidence.get("completeness")
        if completeness not in ("COMPLETE", "INCOMPLETE"):
            v.fail("evidence.completeness must be COMPLETE or INCOMPLETE")
        if unsatisfied:
            v.incomplete(f"evidence obligations unsatisfied: {', '.join(map(str, unsatisfied))}")
            if completeness == "COMPLETE":
                v.fail("evidence.completeness claims COMPLETE while obligations are unsatisfied — derived state must never be asserted")
        elif completeness != "COMPLETE":
            v.incomplete("evidence.completeness is not COMPLETE")

    # --- timestamp (anti-backdating) ---
    ts = p.get("timestamp")
    if not isinstance(ts, dict):
        v.fail("timestamp missing")
    else:
        _closed_fields(v, ts, "timestamp", ("utc", "ntp_synced", "rfc3161_token"))
        _string_fields(v, ts, "timestamp", required=("utc",), optional=("rfc3161_token",))
        dt = _parse_ts(ts.get("utc"))
        if dt is None:
            v.fail("timestamp.utc must be an explicit-zone date-time; leap seconds unsupported")
        elif dt > now_point:
            v.fail("timestamp.utc is in the future relative to verification time (backdating/clock attack)")
        if ts.get("ntp_synced") is not True:
            v.incomplete("timestamp.ntp_synced is not true — cannot exclude clock manipulation")
        if type(ts.get("ntp_synced")) is not bool:
            v.fail("timestamp.ntp_synced must be a boolean")
        if not ts.get("rfc3161_token"):
            v.incomplete("timestamp.rfc3161_token absent — no independent time anchor")

    # --- context / redaction ---
    context = p.get("context")
    if "context" in p and not isinstance(context, dict):
        v.fail("context must be an object when present")
    if isinstance(context, dict):
        _closed_fields(v, context, "context", ("redacted", "redaction_commitments", "deployment_revision", "source_revision"))
        _string_fields(v, context, "context", optional=("deployment_revision", "source_revision"))
        redacted = context.get("redacted")
        if "redacted" in context and not isinstance(redacted, bool):
            v.fail("context.redacted must be a boolean")

        commitments_present = "redaction_commitments" in context
        commitments = context.get("redaction_commitments")
        if redacted is True and (
            not commitments_present or (isinstance(commitments, list) and not commitments)
        ):
            v.fail("context.redacted is true but no redaction_commitments present — redaction could hide exculpatory evidence")

        if commitments_present and not isinstance(commitments, list):
            v.fail("context.redaction_commitments must be a list")
        elif isinstance(commitments, list):
            for index, item in enumerate(commitments):
                path = f"context.redaction_commitments[{index}]"
                if not isinstance(item, dict):
                    v.fail(f"{path} must be an object")
                    continue

                if not isinstance(item.get("field_path"), str):
                    v.fail(f"{path}.field_path must be a string")

                salt = item.get("salt")
                if not isinstance(salt, str):
                    v.fail(f"{path}.salt must be a string")
                elif len(salt) < 32:
                    v.fail(f"{path}.salt must contain at least 32 characters")

                commitment = item.get("commitment")
                if not isinstance(commitment, str) or not _SHA256.fullmatch(commitment):
                    v.fail(f"{path}.commitment must be a lowercase sha256 digest")

    if "limitations" in p:
        if not isinstance(p["limitations"], list):
            v.fail("limitations must be a list of strings")
        elif any(type(item) is not str for item in p["limitations"]):
            v.fail("limitations must be a list of strings")

    if v.state == "PASS" and v.reasons:
        v.state = "INCOMPLETE"
    return v


def validate_statement(stmt: Any, *, now: Optional[datetime] = None) -> Verdict:
    """Validate a full in-toto Statement wrapping a GovernedAction/v1 predicate."""
    v = Verdict(state="PASS")
    reason = _json_error(stmt, "statement")
    if reason:
        v.fail(reason)
        return v
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
    _validate_subject(v, stmt)
    return v


def main() -> int:
    import sys

    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    worst = 0
    order = {"PASS": 0, "UNSIGNED": 0, "INCOMPLETE": 1, "FAIL": 2}
    for path in sys.argv[1:]:
        try:
            with open(path, "rb") as f:
                raw = f.read(MAX_JSON_TEXT_BYTES + 1)
            if len(raw) > MAX_JSON_TEXT_BYTES:
                raise MalformedJSON("JSON byte limit exceeded")
            doc = parse_json_document(raw.decode("utf-8"))
        except (OSError, UnicodeError, MalformedJSON) as e:
            print(f"{path}: FAIL (unreadable: {type(e).__name__})")
            worst = max(worst, 2)
            continue
        v = validate_statement(doc) if isinstance(doc, dict) and "_type" in doc else validate_predicate(doc)
        print(f"{path}: {v.state}" + ("" if not v.reasons else " — " + "; ".join(v.reasons)))
        worst = max(worst, order.get(v.state, 2))
    return 1 if worst >= 1 else 0


if __name__ == "__main__":
    raise SystemExit(main())
