# SPDX-License-Identifier: Apache-2.0
"""Bounded reproducibility bundles.

Raw input bytes, the parsed summary, the normalization policy, the code
revision, the environment, the parameters and the output digest are stored
as separate fields. Values are not rescaled and blank cells are not written
as zero.
"""

from __future__ import annotations

import hashlib
import json
import math
import platform
import subprocess
from pathlib import Path

from science_evidence.attempts import AttemptBudget
from science_evidence.contract import (
    FORMAT,
    MAX_BYTES,
    MAX_COLUMNS,
    MAX_FIELD,
    MAX_ROWS,
    NORMALIZATION,
    SCHEMA,
    TOKEN,
    EvidenceStop,
    bounded_limit,
)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical(value: object) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False) + "\n"
    ).encode("utf-8")


def code_revision() -> str:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=Path(__file__).resolve().parents[1],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return "UNAVAILABLE"
    if result.returncode != 0:
        return "UNAVAILABLE"
    revision = result.stdout.strip()
    if len(revision) != 40 or any(ch not in "0123456789abcdef" for ch in revision):
        return "UNAVAILABLE"
    return revision


def count_matrix(raw: bytes, request: dict) -> dict:
    """Count columns and features. This loop does not call reference.summarize."""

    if request.get("format") != FORMAT or request.get("delimiter", "\t") != "\t":
        raise EvidenceStop("UNSUPPORTED_FORMAT", "unsupported table format")
    if request.get("normalization", "none") != "none":
        raise EvidenceStop("UNSUPPORTED_FORMAT", "this bundle does not normalize")
    if not str(request.get("accession") or "").strip():
        raise EvidenceStop("MISSING_METADATA", "accession is required")
    rights = request.get("rights")
    if not isinstance(rights, dict) or rights.get("status") != "reviewed":
        raise EvidenceStop("RIGHTS_UNREVIEWED", "source rights have not been reviewed")
    if not isinstance(rights.get("redistribution"), str) or not rights.get("basis"):
        raise EvidenceStop("MISSING_METADATA", "rights basis and redistribution statement are required")
    if len(raw) > bounded_limit(request, "max_bytes", MAX_BYTES):
        raise EvidenceStop("SIZE_LIMIT", "input exceeds the byte budget")
    if raw.startswith(b"\xef\xbb\xbf") or b"\x00" in raw:
        raise EvidenceStop("RECORD_FRAMING", "unexpected record framing")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise EvidenceStop("RECORD_FRAMING", "input is not utf-8") from exc
    rows = text.splitlines()
    if not rows:
        raise EvidenceStop("EMPTY_INPUT", "input has no rows")
    cells = rows[0].split("\t")
    if not cells:
        raise EvidenceStop("INCOMPATIBLE_SHAPE", "cell header")
    if len(cells) > bounded_limit(request, "max_columns", MAX_COLUMNS):
        raise EvidenceStop("SIZE_LIMIT", "column budget exceeded")
    if any(not cell or len(cell) > MAX_FIELD for cell in cells) or len(set(cells)) != len(cells):
        raise EvidenceStop("DUPLICATE_IDENTIFIER" if len(set(cells)) != len(cells) else "INCOMPATIBLE_SHAPE", "cell header")
    if len(rows) - 1 > bounded_limit(request, "max_rows", MAX_ROWS):
        raise EvidenceStop("SIZE_LIMIT", "row budget exceeded")
    prefix = str(request.get("ercc_prefix", "ERCC-"))
    endogenous = [0] * len(cells)
    spikes = [0] * len(cells)
    seen: set[str] = set()
    spike_rows = non_integer = positive = 0
    for row in rows[1:]:
        if row == "":
            raise EvidenceStop("RECORD_FRAMING", "blank row")
        fields = row.split("\t")
        if len(fields) != len(cells) + 1:
            raise EvidenceStop("INCOMPATIBLE_SHAPE", "row width does not match the header")
        feature = fields[0]
        if not feature or len(feature) > MAX_FIELD:
            raise EvidenceStop("RECORD_FRAMING", "feature identifier")
        if feature in seen:
            raise EvidenceStop("DUPLICATE_IDENTIFIER", feature)
        seen.add(feature)
        spike = feature.startswith(prefix)
        spike_rows += int(spike)
        bucket = spikes if spike else endogenous
        for index, token in enumerate(fields[1:]):
            if token == "" or token.strip() != token or token.strip() == "":
                raise EvidenceStop("MISSING_MEASUREMENT", "blank measurement is not zero")
            lowered = token.lower()
            if lowered in {"nan", "inf", "+inf", "-inf", "infinity", "-infinity"}:
                raise EvidenceStop("NONFINITE_NUMBER", token)
            if token[0] == "-":
                raise EvidenceStop("NEGATIVE_VALUE", token)
            if TOKEN.fullmatch(token) is None:
                raise EvidenceStop("MALFORMED_NUMBER", token)
            value = float(token)
            if not math.isfinite(value):
                raise EvidenceStop("NONFINITE_NUMBER", token)
            if not value.is_integer():
                non_integer += 1
            if value > 0:
                positive += 1
                bucket[index] += 1
    if not seen:
        raise EvidenceStop("EMPTY_INPUT", "matrix has no feature rows")
    return {
        "cell_columns": len(cells),
        "cell_identifiers": cells,
        "feature_rows": len(seen),
        "endogenous_feature_rows": len(seen) - spike_rows,
        "ercc_feature_rows": spike_rows,
        "non_integer_entries": non_integer,
        "positive_entries": positive,
        "missing_measurements": 0,
        "per_column_endogenous_positive": endogenous,
        "per_column_ercc_positive": spikes,
        "normalization_policy": "none",
    }


def build_bundle(raw: bytes, request: dict, budget: AttemptBudget | None = None) -> dict:
    budget = budget or AttemptBudget(2)
    counts = {"pass": 0, "fail": 0, "skip": 0, "not_run": 4}
    raw_digest = sha256(raw) if isinstance(raw, (bytes, bytearray)) else None
    base = {
        "schema": SCHEMA,
        "status": "NOT_RUN",
        "reason": None,
        "detail": "",
        "signed": False,
        "governed_receipt": "NOT_ISSUED",
        "biological_claim_validated": False,
        "clinical_use": False,
        "raw_input_sha256": raw_digest,
        "raw_input_bytes": len(raw) if isinstance(raw, (bytes, bytearray)) else None,
        "parsed_summary": None,
        "normalization_policy": NORMALIZATION,
        "code_revision": code_revision(),
        "environment": {"python": platform.python_version(), "platform": platform.platform()},
        "parameters": {
            "format": None if not isinstance(request, dict) else request.get("format"),
            "accession": None if not isinstance(request, dict) else request.get("accession"),
            "ercc_prefix": None if not isinstance(request, dict) else request.get("ercc_prefix", "ERCC-"),
            "positive_threshold": 0,
            "normalization": "none",
        },
        "output_sha256": None,
        "counts": counts,
        "attempt": {"reserved": budget.reserved, "limit": budget.limit, "terminal": budget.terminal},
    }
    if not isinstance(raw, (bytes, bytearray)):
        counts["fail"] += 1
        counts["not_run"] -= 1
        base["status"] = "FAIL"
        base["reason"] = "RECORD_FRAMING"
        budget.fail("RECORD_FRAMING")
        base["attempt"]["terminal"] = budget.terminal
        return base
    try:
        budget.reserve()
        first = count_matrix(bytes(raw), request)
        second = count_matrix(bytes(raw), request)
        if canonical(first) != canonical(second):
            raise EvidenceStop("CHANGED_OUTPUT", "repeat summary differed")
    except EvidenceStop as exc:
        counts["fail"] += 1
        counts["not_run"] = 0
        base["status"] = "FAIL"
        base["reason"] = exc.reason
        base["detail"] = exc.detail
        budget.fail(exc.reason)
        base["attempt"] = {"reserved": budget.reserved, "limit": budget.limit, "terminal": budget.terminal}
        return base
    body = canonical(first)
    counts["pass"] = 8
    counts["not_run"] = 0
    budget.complete()
    base.update({
        "status": "PASS",
        "parsed_summary": first,
        "output_sha256": sha256(body),
        "counts": counts,
        "checks": [
            "rights_reviewed",
            "format_supported",
            "byte_budget",
            "utf8_framing",
            "header_shape",
            "finite_nonnegative_values",
            "missing_measurements_rejected",
            "repeat_summary_identical",
        ],
        "attempt": {"reserved": budget.reserved, "limit": budget.limit, "terminal": budget.terminal},
    })
    return base


def compare_source(bundle: dict, raw: bytes) -> dict:
    observed = sha256(raw)
    if bundle.get("raw_input_sha256") != observed:
        return {"status": "FAIL", "reason": "CHANGED_SOURCE", "observed_sha256": observed}
    return {"status": "PASS", "reason": None, "observed_sha256": observed}


def compare_output(bundle: dict, summary: dict) -> dict:
    observed = sha256(canonical(summary))
    if bundle.get("output_sha256") != observed:
        return {"status": "FAIL", "reason": "CHANGED_OUTPUT", "observed_sha256": observed}
    return {"status": "PASS", "reason": None, "observed_sha256": observed}
