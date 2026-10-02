#!/usr/bin/env python3
"""Offline verifier for SZL Governed Agent Change Management Receipts.

Offline (no network access). Pinned maintained dependencies per the v11
doctrine (§7.1 / B-08 — no hand-rolled DSSE/crypto):

    in-toto-attestation == 0.9.3   (ITE-6 Statement/predicate validation)
    cryptography         == 50.0.1 (ECDSA P-256 signature verification)

Verifies receipts published by the SZL Holdings estate
(e.g. SZLHOLDINGS/a11oy-verifiable-corpus, SZLHOLDINGS/readiness-runs,
SZLHOLDINGS/szl-evidence).

For each receipt the verifier:
  (a) validates the decoded decision object against schema/governed-receipt.schema.json,
  (b) recomputes the content hash and checks it:
        - DSSE receipts: sha256(PAE) == envelope._pae_sha256 (== receipt_uid),
        - readiness receipts: sha256(payload bytes) == payloadSha256,
  (c) checks the prev-hash chain across a receipt list (prev == previous.digest,
      genesis prev is 64 zeros, seq increments),
  (d) structurally checks the DSSE envelope,
  (e) when the payload is an in-toto Statement, validates it through the
      pinned in-toto-attestation bindings (ITE-6 minimums), and
  (f) when --verify-key is given, cryptographically verifies every envelope
      signature: ECDSA P-256 SHA-256 over the DSSE PAE of the DECODED payload
      bytes. Without a key the check is reported as SKIP — never as a pass.

It prints a clear PASS / FAIL per receipt and per file with reasons.

Honesty note: this verifier does NOT re-derive the runtime's internal `digest`
(that serialization is internal to the emitting runtime). It verifies the
relations that an outside party can independently reproduce: the DSSE PAE
content hash, the payload-bytes hash, the prev<->digest chain, and — with a
public key supplied — the envelope signature itself. A receipt is an honest,
replayable audit record -- it is NOT a zero-knowledge proof.

Usage:
    python verify.py <receipt.json> [<receipt2.json> ...]
    python verify.py --schema schema/governed-receipt.schema.json examples/*.json
    python verify.py --verify-key tests/fixtures/cosign.pub examples/a11oy-khipu-chain.json
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import math
import os
import re

import governed_action as strict_json

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from in_toto_attestation.v1.resource_descriptor import ResourceDescriptor
from in_toto_attestation.v1.statement import STATEMENT_TYPE_URI, Statement

ZERO_HASH = "0" * 64
MAX_JSON_INTEGER_DIGITS = 4300  # Match the supported Python strict-text boundary.
IN_TOTO_STATEMENT_TYPE = STATEMENT_TYPE_URI
IN_TOTO_PAYLOAD_TYPE = "application/vnd.in-toto+json"
DEFAULT_SCHEMA = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "schema",
    "governed-receipt.schema.json",
)


# --------------------------------------------------------------------------- #
# Minimal JSON Schema (draft 2020-12) validator                               #
# Covers the keyword subset used by governed-receipt.schema.json:             #
# type, required, properties, additionalProperties, enum, const, pattern,     #
# minimum, items, oneOf, anyOf, $ref / $defs, and nullable via type arrays.   #
# --------------------------------------------------------------------------- #
class SchemaError(Exception):
    pass


def _type_ok(value, t):
    if t == "object":
        return isinstance(value, dict)
    if t == "array":
        return isinstance(value, list)
    if t == "string":
        return isinstance(value, str)
    if t == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if t == "number":
        return type(value) is int or (type(value) is float and math.isfinite(value))
    if t == "boolean":
        return isinstance(value, bool)
    if t == "null":
        return value is None
    raise SchemaError("unknown type in schema: %r" % t)


def _resolve_ref(ref, root):
    if not ref.startswith("#/"):
        raise SchemaError("only local #/ refs are supported: %r" % ref)
    node = root
    for part in ref[2:].split("/"):
        part = part.replace("~1", "/").replace("~0", "~")
        node = node[part]
    return node


def validate(value, schema, root=None, path="$", errors=None):
    """Return a list of error strings (empty == valid)."""
    if root is None:
        root = schema
    if errors is None:
        errors = []

    if "$ref" in schema:
        schema = _resolve_ref(schema["$ref"], root)

    # type
    if "type" in schema:
        types = schema["type"]
        if isinstance(types, str):
            types = [types]
        if not any(_type_ok(value, t) for t in types):
            errors.append("%s: expected type %s, got %s"
                          % (path, "|".join(types), type(value).__name__))
            return errors  # further checks are meaningless

    # const / enum
    if "const" in schema and value != schema["const"]:
        errors.append("%s: must equal const %r" % (path, schema["const"]))
    if "enum" in schema and value not in schema["enum"]:
        errors.append("%s: %r not in enum %r" % (path, value, schema["enum"]))

    # oneOf / anyOf
    if "oneOf" in schema:
        matches = sum(
            1 for sub in schema["oneOf"]
            if not validate(value, sub, root, path, [])
        )
        if matches != 1:
            errors.append("%s: matched %d of oneOf branches (need exactly 1)"
                          % (path, matches))
    if "anyOf" in schema:
        if not any(not validate(value, sub, root, path, [])
                   for sub in schema["anyOf"]):
            errors.append("%s: matched none of anyOf branches" % path)

    # strings
    if isinstance(value, str):
        pat = schema.get("pattern")
        if pat is not None and re.search(pat, value) is None:
            errors.append("%s: %r does not match pattern %r" % (path, value, pat))

    # numbers
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if "minimum" in schema and value < schema["minimum"]:
            errors.append("%s: %r < minimum %r" % (path, value, schema["minimum"]))

    # objects
    if isinstance(value, dict):
        for req in schema.get("required", []):
            if req not in value:
                errors.append("%s: missing required property %r" % (path, req))
        props = schema.get("properties", {})
        for key, sub in props.items():
            if key in value:
                validate(value[key], sub, root, "%s.%s" % (path, key), errors)
        addl = schema.get("additionalProperties", True)
        if addl is False:
            for key in value:
                if key not in props:
                    errors.append("%s: additional property %r not allowed"
                                  % (path, key))
        elif isinstance(addl, dict):
            for key in value:
                if key not in props:
                    validate(value[key], addl, root,
                             "%s.%s" % (path, key), errors)

    # arrays
    if isinstance(value, list):
        items = schema.get("items")
        if isinstance(items, dict) and items:
            for i, item in enumerate(value):
                validate(item, items, root, "%s[%d]" % (path, i), errors)

    return errors


# --------------------------------------------------------------------------- #
# Receipt loading & shape extraction                                          #
# --------------------------------------------------------------------------- #
def _read_json_text(path):
    """Bound bytes before decoding; never reflect receipt contents in errors."""
    with open(path, "rb") as fh:
        raw = fh.read(strict_json.MAX_JSON_TEXT_BYTES + 1)
    if len(raw) > strict_json.MAX_JSON_TEXT_BYTES:
        raise strict_json.MalformedJSON("JSON byte limit exceeded")
    try:
        return raw.decode("utf-8")
    except UnicodeError:
        raise strict_json.MalformedJSON("invalid JSON UTF-8") from None


def load_records(path):
    """Load one path into a list of top-level records.

    Supports a single JSON object, a JSON array, or NDJSON (one JSON per line).
    """
    text = _read_json_text(path)
    text_stripped = text.strip()
    if not text_stripped:
        return []
    try:
        data = strict_json.parse_json_document(text_stripped)
        return data if isinstance(data, list) else [data]
    except strict_json.MalformedJSON:
        records = []
        for line in text_stripped.splitlines():
            line = line.strip()
            if line:
                records.append(strict_json.parse_json_document(line))
        # NDJSON must not bypass the aggregate nesting/work/text bounds.
        reason = strict_json._json_error(records, "records")
        if reason:
            raise strict_json.MalformedJSON(reason)
        return records


def _find_envelope(record):
    """Locate the DSSE / signed envelope inside a record, if any."""
    if isinstance(record, dict):
        # Explicit declarations must reach validation, even when malformed.
        if "payloadType" in record:
            return record
        payload = record.get("payload")
        if isinstance(payload, dict):
            for key in ("envelope", "dsse"):
                env = payload.get(key)
                if isinstance(env, dict):
                    return env
        for key in ("envelope", "dsse"):
            env = record.get(key)
            if isinstance(env, dict):
                return env
    return None


def _decode_envelope_payload(envelope):
    try:
        raw = base64.b64decode(envelope["payload"], validate=True)
    except Exception as exc:  # noqa: BLE001
        return None, "payload is not valid base64 (%s)" % type(exc).__name__
    try:
        return strict_json.parse_json_document(raw.decode("utf-8")), None
    except Exception as exc:  # noqa: BLE001
        return None, "decoded payload is not valid JSON (%s)" % type(exc).__name__


def extract_decision(record, envelope):
    """Return (decision_object, note).

    The decision object is what the schema describes. For lake receipts the
    governance fields are already in the clear on `payload`; for khipu receipts
    they live in the base64 DSSE payload; flat DSSE receipts carry them in the
    decoded payload too.
    """
    if isinstance(record, dict):
        payload = record.get("payload")
        if isinstance(payload, dict) and "seq" in payload and "prev" in payload:
            return payload, "decision fields read from record.payload (lake form)"
    if envelope is not None:
        decoded, err = _decode_envelope_payload(envelope)
        if decoded is not None:
            return decoded, "decision fields decoded from DSSE envelope payload"
        return None, err or "could not decode envelope payload"
    if isinstance(record, dict) and "seq" in record and "prev" in record:
        return record, "record is already a decoded decision object"
    return record if isinstance(record, dict) else None, "no envelope; using record as-is"


def is_inference_receipt(decision):
    return (
        isinstance(decision, dict)
        and "seq" in decision
        and "prev" in decision
        and "digest" in decision
    )


# --------------------------------------------------------------------------- #
# Content-hash & DSSE checks                                                   #
# --------------------------------------------------------------------------- #
def dsse_pae(payload_type, body_bytes):
    """DSSE v1 Pre-Authentication Encoding (spec-exact, cosign-compatible).

    PAE(type, body) = "DSSEv1" SP LEN(type) SP type SP LEN(body) SP body
    with ASCII decimal lengths over the DECODED payload bytes (never the
    base64 text). This is the single spec-pinned implementation used by every
    check in this verifier: the pinned in-toto-attestation 0.9.3 wheel ships
    the Statement/predicate bindings only — no DSSE envelope/PAE code
    (verified by inspection) — so the encoding is pinned here by the DSSE
    spec's worked test vector (see tests/test_verify.py).
    """
    if not isinstance(payload_type, str) or not payload_type:
        raise ValueError("payload_type must be a non-empty string")
    if not isinstance(body_bytes, bytes):
        raise TypeError("body_bytes must be bytes")
    return (
        b"DSSEv1 "
        + str(len(payload_type.encode("utf-8"))).encode("ascii")
        + b" "
        + payload_type.encode("utf-8")
        + b" "
        + str(len(body_bytes)).encode("ascii")
        + b" "
        + body_bytes
    )


def _intoto_statement_errors(statement):
    """Fail-soft ITE-6 structural validation via in-toto-attestation 0.9.3.

    Returns a list of reason strings (empty == structurally valid). Never
    raises: malformed input is a verification failure, not an exception.
    """
    if not isinstance(statement, dict):
        return ["statement is not an object"]
    if statement.get("_type") != IN_TOTO_STATEMENT_TYPE:
        return ["statement-ite6-invalid: _type must be Statement/v1"]
    if not isinstance(statement.get("subject"), list):
        return ["statement-ite6-invalid: subject must be a list"]
    if not isinstance(statement.get("predicateType"), str):
        return ["statement-ite6-invalid: predicateType must be a string"]
    if not isinstance(statement.get("predicate"), dict):
        return ["statement-ite6-invalid: predicate must be an object"]
    try:
        subjects = statement.get("subject")
        descriptors = []
        for index, subject in enumerate(subjects):
            if not isinstance(subject, dict):
                return ["statement-ite6-invalid: subject %d is not an object" % index]
            name = subject.get("name")
            digest = subject.get("digest")
            for field in ("name", "uri", "mediaType", "downloadLocation", "content"):
                if field in subject and not isinstance(subject[field], str):
                    return ["statement-ite6-invalid: subject %d %s must be a string" % (index, field)]
            if "annotations" in subject and not isinstance(subject["annotations"], dict):
                return ["statement-ite6-invalid: subject %d annotations must be an object" % index]
            if not isinstance(digest, dict) or any(
                not isinstance(k, str) or not k or not isinstance(v, str) or not v
                for k, v in digest.items()
            ):
                return ["statement-ite6-invalid: subject %d digest must map non-empty strings to non-empty strings" % index]
            try:
                content = base64.b64decode(subject.get("content", ""), validate=True)
            except (ValueError, UnicodeError):
                return ["statement-ite6-invalid: subject %d content must be strict base64" % index]
            descriptor = ResourceDescriptor(
                name=name if name is not None else "",
                uri=subject.get("uri", ""),
                digest=digest,
                content=content,
                download_location=subject.get("downloadLocation", ""),
                media_type=subject.get("mediaType", ""),
                annotations=subject.get("annotations"),
            )
            descriptor.validate()
            descriptors.append(descriptor.pb)
        predicate = statement.get("predicate")
        stmt = Statement(
            subjects=descriptors,
            predicate_type=statement["predicateType"],
            predicate=predicate,
        )
        stmt.validate()
    except (ValueError, TypeError, OverflowError) as exc:
        return ["statement-ite6-invalid: conversion rejected (%s)" % type(exc).__name__]
    return []


def check_intoto_statement(envelope):
    """ITE-6 validation for in-toto Statement payloads. Returns (ok, message)."""
    if envelope is None:
        return True, "no envelope to check (n/a)"
    ptype = envelope.get("payloadType")
    media_type = ptype.split(";", 1)[0].strip().lower() if isinstance(ptype, str) else ""
    decoded, err = _decode_envelope_payload(envelope)
    is_intoto = media_type == IN_TOTO_PAYLOAD_TYPE or (
        isinstance(decoded, dict) and decoded.get("_type") == IN_TOTO_STATEMENT_TYPE
    )
    if not is_intoto:
        return True, "not an in-toto Statement payload (n/a)"
    if decoded is None:
        return False, "in-toto payload undecodable: %s" % err
    errors = _intoto_statement_errors(decoded)
    if errors:
        return False, "; ".join(errors)
    return True, "in-toto Statement v1 validated via in-toto-attestation 0.9.3"


def check_signatures(envelope, public_key_pem):
    """Verify signatures; return (True=verified, False=failed, None=SKIP, message).

    Each signature is verified as ECDSA P-256 SHA-256 over the DSSE PAE of the
    DECODED payload bytes (never the base64 text), using the pinned
    ``cryptography`` 50.0.1 library. Without a key the check is an honest
    SKIP: it never claims a pass it did not perform. Supplying a key requires
    an envelope with at least one signature on every record.
    """
    if envelope is None:
        if public_key_pem is not None:
            return False, "--verify-key requires a signed envelope on every record"
        return None, "no envelope; signature authenticity not checked"
    sigs = envelope.get("signatures")
    if not isinstance(sigs, list):
        return False, "signatures missing/not a list"
    if not sigs:
        if public_key_pem is not None:
            return False, "--verify-key requires at least one envelope signature"
        return None, "unsigned envelope; signature authenticity not checked"
    if public_key_pem is None:
        return None, (
            "%d signature(s) present but no --verify-key supplied; "
            "signature not cryptographically verified" % len(sigs)
        )
    try:
        body = base64.b64decode(envelope["payload"], validate=True)
        preimage = dsse_pae(envelope.get("payloadType", ""), body)
    except Exception as exc:  # noqa: BLE001
        return False, "cannot reconstruct PAE preimage: %s" % exc
    try:
        public_key = serialization.load_pem_public_key(
            public_key_pem.encode("utf-8")
            if isinstance(public_key_pem, str)
            else public_key_pem
        )
    except Exception as exc:  # noqa: BLE001
        return False, "verify key unreadable: %s" % exc
    if not isinstance(public_key, ec.EllipticCurvePublicKey) or not isinstance(
        public_key.curve, ec.SECP256R1
    ):
        return False, "verify key is not an ECDSA P-256 public key"
    failures = []
    for i, entry in enumerate(sigs):
        if not isinstance(entry, dict) or not isinstance(entry.get("sig"), str):
            failures.append("signature[%d] malformed" % i)
            continue
        try:
            signature = base64.b64decode(entry["sig"], validate=True)
            public_key.verify(signature, preimage, ec.ECDSA(hashes.SHA256()))
        except InvalidSignature:
            failures.append("signature[%d] mismatch" % i)
        except Exception as exc:  # noqa: BLE001
            failures.append("signature[%d] invalid (%s)" % (i, exc))
    if failures:
        return False, "; ".join(failures)
    return True, (
        "%d signature(s) verified: ECDSA P-256 SHA-256 over DSSE PAE "
        "(decoded payload bytes)" % len(sigs)
    )


def check_content_hash(record, envelope):
    """Recompute and check the content hash. Returns (ok, message)."""
    if envelope is not None:
        try:
            body = base64.b64decode(envelope["payload"], validate=True)
        except Exception as exc:  # noqa: BLE001
            return False, "envelope payload not base64: %s" % exc
        ptype = envelope.get("payloadType", "")
        # DSSE PAE hash
        if "_pae_sha256" in envelope:
            try:
                got = hashlib.sha256(dsse_pae(ptype, body)).hexdigest()
            except (ValueError, TypeError, UnicodeError) as exc:
                return False, "cannot reconstruct content-hash PAE (%s)" % type(exc).__name__
            want = envelope["_pae_sha256"]
            if got != want:
                return False, ("DSSE PAE sha256 mismatch: recomputed %s != _pae_sha256 %s"
                               % (got, want))
            # receipt_uid, when present, must equal the PAE hash
            uid = None
            if isinstance(record, dict) and isinstance(record.get("payload"), dict):
                uid = record["payload"].get("receipt_uid")
            if uid is not None and uid != got:
                return False, ("receipt_uid %s != recomputed PAE hash %s" % (uid, got))
            return True, "DSSE PAE sha256 verified (%s)" % got[:16]
        # readiness form: sha256 over raw payload bytes
        if "payloadSha256" in envelope:
            got = hashlib.sha256(body).hexdigest()
            want = envelope["payloadSha256"]
            if got != want:
                return False, ("payloadSha256 mismatch: recomputed %s != %s" % (got, want))
            return True, "payloadSha256 verified (%s)" % got[:16]
        return True, "no content-hash field present on envelope (n/a)"
    return True, "no DSSE/signed envelope (n/a)"


def check_dsse_structure(envelope):
    """Structural checks on a DSSE envelope. Returns (ok, message)."""
    if envelope is None:
        return True, "no envelope to check (n/a)"
    problems = []
    ptype = envelope.get("payloadType")
    if not isinstance(ptype, str) or not ptype:
        problems.append("payloadType missing/empty")
    if not isinstance(envelope.get("payload"), str):
        problems.append("payload missing/not a string")
    else:
        try:
            base64.b64decode(envelope["payload"], validate=True)
        except Exception:  # noqa: BLE001
            problems.append("payload not base64-decodable")
    if isinstance(ptype, str):
        media_type = ptype.split(";", 1)[0].strip().lower()
        if media_type == "application/json" or media_type.endswith("+json"):
            _decoded, error = _decode_envelope_payload(envelope)
            if error:
                problems.append(error)
    sigs = envelope.get("signatures")
    if not isinstance(sigs, list):
        problems.append("signatures missing/not a list")
        sigs = []
    signed_present = "signed" in envelope
    signed = envelope.get("signed")
    if signed_present and type(signed) is not bool:
        problems.append("signed marker must be a boolean when present")
    elif signed is True:
        if not sigs:
            problems.append("signed=true but signatures is empty")
    elif signed is False and sigs:
        problems.append("signed=false but signatures is not empty")
    for i, s in enumerate(sigs):
        if not isinstance(s, dict) or "sig" not in s:
            problems.append("signature[%d] missing 'sig'" % i)
            continue
        sig = s["sig"]
        if not isinstance(sig, str) or not sig:
            problems.append("signature[%d] 'sig' missing/empty" % i)
            continue
        try:
            base64.b64decode(sig, validate=True)
        except Exception:  # noqa: BLE001
            problems.append("signature[%d] 'sig' not strict base64" % i)
    if problems:
        return False, "; ".join(problems)
    kind = (
        "signed"
        if signed is True or (not signed_present and bool(sigs))
        else "unsigned"
    )
    return True, "DSSE envelope well-formed (%s, %d signature(s))" % (kind, len(sigs))


def check_clear_claim_binding(record, envelope, schema):
    """Require clear schema claims to be present identically in sealed bytes.

    Some legacy lake records duplicate a decoded decision beside a nested DSSE
    envelope. The envelope authenticates only its decoded payload; clear-only
    governance fields must therefore never inherit the envelope's PASS state.
    """
    if not isinstance(record, dict) or envelope is None:
        return True, "no clear/envelope claim boundary (n/a)"

    envelope_fields = {
        "_dsse", "_pae_sha256", "_signed_at", "honesty", "payload",
        "payloadSha256", "payloadType", "signatures", "signed", "signing",
        "verify_key_url",
    }
    unknown_envelope_fields = sorted(set(envelope) - envelope_fields)
    if unknown_envelope_fields:
        return False, "UNBOUND envelope extension claim(s): %s" % ", ".join(
            unknown_envelope_fields
        )

    if record is envelope:
        return True, "flat envelope contains no external clear claims (n/a)"

    payload = record.get("payload")
    envelope_locations = []
    for wrapper_name, wrapper in (("record", record), ("payload", payload)):
        if not isinstance(wrapper, dict):
            continue
        for key in ("envelope", "dsse"):
            if key in wrapper:
                envelope_locations.append("%s.%s" % (wrapper_name, key))
    if len(envelope_locations) != 1:
        return False, "UNBOUND ambiguous envelope locations: %s" % ", ".join(
            envelope_locations or ["none"]
        )

    sealed, error = _decode_envelope_payload(envelope)
    if not isinstance(sealed, dict):
        return False, "cannot bind clear claims: %s" % (
            error or "sealed payload is not an object"
        )
    sealed_bytes = base64.b64decode(envelope["payload"], validate=True)
    envelope_pae_sha256 = hashlib.sha256(
        dsse_pae(envelope.get("payloadType", ""), sealed_bytes)
    ).hexdigest()

    layers = []
    if isinstance(payload, dict) and (
        payload.get("envelope") is envelope or payload.get("dsse") is envelope
    ):
        layers.append((payload, {"envelope", "dsse"}))
        layers.append((record, {"payload"}))
    elif record.get("envelope") is envelope or record.get("dsse") is envelope:
        layers.append((record, {"envelope", "dsse"}))
    else:
        return True, "no clear/envelope claim boundary (n/a)"

    unbound = []
    for clear, transport in layers:
        metadata = set()
        publication_role = (
            clear.get("asset") == "receipt"
            and clear.get("scheme") == "ecdsa-p256-dsse-pae"
            and clear.get("schema") == "szl.a11oy.corpus.record/v1"
            and isinstance(clear.get("receipt_uid"), str)
            and re.fullmatch(r"[0-9a-f]{64}", clear["receipt_uid"]) is not None
            and clear["receipt_uid"] == envelope_pae_sha256
        )
        dataset_role = (
            clear.get("kind") in ("receipt", "lake_receipt")
            and clear.get("schema") == "szl.hf.bucket.record/v1"
            and clear.get("source") == "a11oy"
            and isinstance(clear.get("id"), str)
            and re.fullmatch(r"[0-9a-f]{64}", clear["id"]) is not None
            and isinstance(clear.get("ts"), str)
            and re.fullmatch(
                r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z",
                clear["ts"],
            ) is not None
        )
        if publication_role:
            metadata = {
                "asset", "honesty", "meta", "published_at", "receipt_uid",
                "schema", "scheme", "verify",
            }
        elif "payload" in clear and dataset_role:
            metadata = {"id", "kind", "schema", "source", "ts"}
        for key in set(clear) - transport - metadata:
            same_json = key in sealed and json.dumps(
                clear[key], sort_keys=True, separators=(",", ":"),
                ensure_ascii=False,
            ) == json.dumps(
                sealed[key], sort_keys=True, separators=(",", ":"),
                ensure_ascii=False,
            )
            if not same_json:
                unbound.append(key)
    unbound = sorted(set(unbound))
    if unbound:
        return False, (
            "UNBOUND clear claim(s) absent or different in sealed "
            "payload: %s" % ", ".join(unbound)
        )
    return True, "all clear claims across wrapper ancestors match sealed payload"


# --------------------------------------------------------------------------- #
# Chain check                                                                  #
# --------------------------------------------------------------------------- #
def check_chain(decisions):
    """Check the prev-hash chain across an ordered list of decision objects.

    Returns (ok, [messages]).
    """
    msgs = []
    ok = True
    chainable = [d for d in decisions if isinstance(d, dict) and "prev" in d and "digest" in d]
    if len(chainable) < 1:
        return True, ["no chainable receipts (n/a)"]
    # order by seq when available
    if all("seq" in d for d in chainable):
        chainable = sorted(chainable, key=lambda d: d["seq"])
    first = chainable[0]
    if first.get("seq") == 0 and first.get("prev") != ZERO_HASH:
        ok = False
        msgs.append("genesis (seq 0) prev must be 64 zeros, got %s" % first.get("prev"))
    for i in range(1, len(chainable)):
        prev_rec = chainable[i - 1]
        cur = chainable[i]
        if cur.get("prev") != prev_rec.get("digest"):
            ok = False
            msgs.append(
                "seq %s prev %s != seq %s digest %s"
                % (cur.get("seq"), cur.get("prev"),
                   prev_rec.get("seq"), prev_rec.get("digest"))
            )
        if "seq" in cur and "seq" in prev_rec and cur["seq"] != prev_rec["seq"] + 1:
            ok = False
            msgs.append("seq not contiguous: %s follows %s"
                        % (cur["seq"], prev_rec["seq"]))
    if ok:
        msgs.append("hash chain intact across %d receipt(s)" % len(chainable))
    return ok, msgs


# --------------------------------------------------------------------------- #
# Top-level verification                                                       #
# --------------------------------------------------------------------------- #
def _integer_text_error(records):
    """After strict-JSON validation, bound integer formatting without hooks.

    Direct Python callers can supply ints larger than the parser accepts. A
    cheap bit bound precedes decimal conversion so failure reports cannot
    raise Python's integer-string-limit exception or do unbounded work.
    """
    pending = [records]
    while pending:
        item = pending.pop()
        if type(item) is dict:
            pending.extend(item.values())
        elif type(item) is list:
            pending.extend(item)
        elif type(item) is int:
            if item.bit_length() > MAX_JSON_INTEGER_DIGITS * 4:
                return "JSON integer exceeds supported decimal text limit"
            try:
                if len(str(abs(item))) > MAX_JSON_INTEGER_DIGITS:
                    return "JSON integer exceeds supported decimal text limit"
            except ValueError:
                return "JSON integer exceeds supported decimal text limit"
    return None


def verify_records(records, schema, public_key_pem=None):
    """Return (ok, report_lines) for the selected verification mode.

    Without a key, ok covers only the applicable integrity/structure checks.
    With a key, ok also requires verified signatures on every record. Neither
    mode establishes signer trust, authorization, or correctness of execution.
    """
    reason = strict_json._json_error(records, "records")
    if reason:
        return False, ["- records: FAIL malformed input: %s" % reason]
    reason = _integer_text_error(records)
    if reason:
        return False, ["- records: FAIL malformed input: %s" % reason]
    if type(records) is not list:
        return False, ["- records: FAIL expected a list of receipt records"]
    if not records:
        return False, ["- records: FAIL no receipt records found"]

    lines = []
    ok = True
    decisions = []
    invalid_decision = False
    for idx, record in enumerate(records):
        tag = "receipt[%d]" % idx
        if isinstance(record, dict):
            wrappers = (record, record.get("payload"))
            if any(key in wrapper and not isinstance(wrapper[key], dict)
                   for wrapper in wrappers if isinstance(wrapper, dict)
                   for key in ("dsse", "envelope")):
                ok = False
                invalid_decision = True
                lines.append("- %s: FAIL declared DSSE/envelope must be an object" % tag)
                continue
        envelope = _find_envelope(record)
        decision, note = extract_decision(record, envelope)
        lines.append("- %s: %s" % (tag, note))

        # (d) DSSE structure
        s_ok, s_msg = check_dsse_structure(envelope)
        ok = ok and s_ok
        lines.append("    dsse:   %s %s" % ("PASS" if s_ok else "FAIL", s_msg))
        if not s_ok:
            invalid_decision = True
            # Raw-byte diagnostics cannot erase the envelope failure.
            h_ok, h_msg = check_content_hash(record, envelope)
            lines.append("    hash:   %s %s" % ("PASS" if h_ok else "FAIL", h_msg))
            lines.append("    checks: SKIP malformed envelope interpretation; failure retained")
            continue

        # (e) in-toto Statement ITE-6 validation (in-toto payloads only)
        t_ok, t_msg = check_intoto_statement(envelope)
        ok = ok and t_ok
        if not t_ok:
            invalid_decision = True
        lines.append("    intoto: %s %s" % ("PASS" if t_ok else "FAIL", t_msg))

        # (f) cryptographic signature verification (SKIP without --verify-key)
        g_ok, g_msg = check_signatures(envelope, public_key_pem)
        ok = ok and g_ok is not False
        g_status = "SKIP" if g_ok is None else ("PASS" if g_ok else "FAIL")
        lines.append("    sig:    %s %s" % (g_status, g_msg))

        # (b) content hash
        h_ok, h_msg = check_content_hash(record, envelope)
        ok = ok and h_ok
        lines.append("    hash:   %s %s" % ("PASS" if h_ok else "FAIL", h_msg))

        # Clear wrapper claims must be bound to the exact sealed payload.
        b_ok, b_msg = check_clear_claim_binding(record, envelope, schema)
        ok = ok and b_ok
        lines.append("    bind:   %s %s" % ("PASS" if b_ok else "FAIL", b_msg))

        # (a) schema (inference receipts only)
        if is_inference_receipt(decision):
            errs = validate(decision, schema)
            v_ok = not errs
            ok = ok and v_ok
            if v_ok:
                lines.append("    schema: PASS validates governed-receipt.schema.json")
            else:
                lines.append("    schema: FAIL")
                for e in errs:
                    lines.append("            - %s" % e)
            if v_ok:
                decisions.append(decision)
            else:
                invalid_decision = True
        else:
            if envelope is None:
                ok = False
                invalid_decision = True
                lines.append("    schema: FAIL unsupported record has no "
                             "inference decision or DSSE envelope")
            else:
                lines.append("    schema: SKIP non-inference receipt "
                             "(envelope + hash checks only)")

    # (c) chain across inference receipts
    if invalid_decision:
        c_ok, c_msgs = False, ["malformed receipt prevents complete chain verification"]
    else:
        c_ok, c_msgs = check_chain(decisions)
    ok = ok and c_ok
    for m in c_msgs:
        lines.append("- chain: %s %s" % ("PASS" if c_ok else "FAIL", m))
    return ok, lines


def verify_file(path, schema, public_key_pem=None):
    try:
        records = load_records(path)
    except (OSError, strict_json.MalformedJSON) as exc:
        return False, ["- records: FAIL input unreadable or malformed (%s)" % type(exc).__name__]
    return verify_records(records, schema, public_key_pem)


def load_schema(path):
    schema = strict_json.parse_json_document(_read_json_text(path))
    if not isinstance(schema, dict):
        raise strict_json.MalformedJSON("schema must be a JSON object")
    return schema


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Offline verifier for SZL Governed Agent Change Management Receipts.")
    parser.add_argument("receipts", nargs="+", help="receipt JSON / NDJSON file(s)")
    parser.add_argument("--schema", default=DEFAULT_SCHEMA,
                        help="path to governed-receipt.schema.json")
    parser.add_argument(
        "--verify-key",
        default=None,
        metavar="PEM",
        help=(
            "path to a PEM ECDSA P-256 public key; when given, every record "
            "must have a signed envelope and all signatures must verify. Without it, "
            "signature verification is reported as SKIP, never as a pass."
        ),
    )
    args = parser.parse_args(argv)

    try:
        schema = load_schema(args.schema)
    except (OSError, strict_json.MalformedJSON) as exc:
        print("FAIL schema unreadable or malformed (%s)" % type(exc).__name__)
        print("OVERALL: FAIL")
        return 1
    public_key_pem = None
    if args.verify_key:
        try:
            with open(args.verify_key, "rb") as fh:
                public_key_pem = fh.read()
        except OSError as exc:
            print("ERROR: cannot read --verify-key %s: %s" % (args.verify_key, exc))
            return 1
    all_ok = True
    success = (
        "PASS (integrity-only; signatures not authenticated)"
        if public_key_pem is None
        else "PASS (signatures verified with supplied key; trust/authorization not assessed)"
    )
    for path in args.receipts:
        print("=== %s ===" % path)
        try:
            file_ok, lines = verify_file(path, schema, public_key_pem)
        except Exception as exc:  # noqa: BLE001
            print("  FAIL could not process file: %s" % exc)
            all_ok = False
            continue
        for line in lines:
            print("  " + line)
        print("  RESULT: %s" % (success if file_ok else "FAIL"))
        all_ok = all_ok and file_ok

    print()
    print("OVERALL: %s" % (success if all_ok else "FAIL"))
    return 0 if all_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
