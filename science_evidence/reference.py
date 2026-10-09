# SPDX-License-Identifier: Apache-2.0
"""Independent record and feature counter.

The counting loop in this module is separate from science_evidence.bundle.
Both follow contract.TOKEN and the same stop reasons. Tests compare them
to hand-counted fixtures.
"""

from __future__ import annotations

import math

from science_evidence.contract import (
    FORMAT,
    MAX_BYTES,
    MAX_COLUMNS,
    MAX_FIELD,
    MAX_ROWS,
    TOKEN,
    EvidenceStop,
    bounded_limit,
)


def summarize(raw: bytes, request: dict) -> dict:
    _require_request(request)
    if len(raw) > bounded_limit(request, "max_bytes", MAX_BYTES):
        raise EvidenceStop("SIZE_LIMIT", "input exceeds the byte budget")
    if raw.startswith(b"\xef\xbb\xbf"):
        raise EvidenceStop("RECORD_FRAMING", "byte order mark is not part of the table")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise EvidenceStop("RECORD_FRAMING", "input is not utf-8") from exc
    if "\x00" in text:
        raise EvidenceStop("RECORD_FRAMING", "input contains a NUL")
    lines = text.splitlines()
    if not lines:
        raise EvidenceStop("EMPTY_INPUT", "input has no rows")
    delimiter = "\t"
    header = lines[0].split(delimiter)
    if not header or any(not cell or len(cell) > MAX_FIELD for cell in header):
        raise EvidenceStop("INCOMPATIBLE_SHAPE", "cell header is empty or too wide")
    if len(header) > bounded_limit(request, "max_columns", MAX_COLUMNS):
        raise EvidenceStop("SIZE_LIMIT", "column budget exceeded")
    if len(set(header)) != len(header):
        raise EvidenceStop("DUPLICATE_IDENTIFIER", "duplicate cell identifier")
    if len(lines) - 1 > bounded_limit(request, "max_rows", MAX_ROWS):
        raise EvidenceStop("SIZE_LIMIT", "row budget exceeded")
    endogenous = [0] * len(header)
    spikes = [0] * len(header)
    seen: set[str] = set()
    spike_rows = non_integer = positive = 0
    prefix = str(request.get("ercc_prefix", "ERCC-"))
    for line in lines[1:]:
        if line == "":
            raise EvidenceStop("RECORD_FRAMING", "blank row")
        fields = line.split(delimiter)
        if len(fields) != len(header) + 1:
            raise EvidenceStop("INCOMPATIBLE_SHAPE", "row width does not match the header")
        feature = fields[0]
        if not feature or len(feature) > MAX_FIELD:
            raise EvidenceStop("RECORD_FRAMING", "feature identifier is empty or too long")
        if feature in seen:
            raise EvidenceStop("DUPLICATE_IDENTIFIER", "duplicate feature identifier")
        seen.add(feature)
        is_spike = feature.startswith(prefix)
        spike_rows += int(is_spike)
        target = spikes if is_spike else endogenous
        for index, token in enumerate(fields[1:]):
            if token == "" or token.strip() == "" or token.strip() != token:
                raise EvidenceStop("MISSING_MEASUREMENT", "blank measurement is not zero")
            if token.lower() in {"nan", "inf", "+inf", "-inf", "infinity", "-infinity"}:
                raise EvidenceStop("NONFINITE_NUMBER", token)
            if token.startswith("-"):
                raise EvidenceStop("NEGATIVE_VALUE", token)
            if TOKEN.fullmatch(token) is None:
                raise EvidenceStop("MALFORMED_NUMBER", token)
            value = float(token)
            if not math.isfinite(value):
                raise EvidenceStop("NONFINITE_NUMBER", token)
            non_integer += int(not value.is_integer())
            if value > 0:
                positive += 1
                target[index] += 1
    if not seen:
        raise EvidenceStop("EMPTY_INPUT", "matrix has no feature rows")
    return {
        "cell_columns": len(header),
        "cell_identifiers": header,
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


def _require_request(request: dict) -> None:
    if not isinstance(request, dict):
        raise EvidenceStop("MISSING_METADATA", "request must be an object")
    if request.get("format") != FORMAT:
        raise EvidenceStop("UNSUPPORTED_FORMAT", "only feature_by_cell_tsv is supported")
    if request.get("delimiter", "\t") != "\t":
        raise EvidenceStop("UNSUPPORTED_FORMAT", "only tab delimiters are supported")
    if not str(request.get("accession") or "").strip():
        raise EvidenceStop("MISSING_METADATA", "accession is required")
    rights = request.get("rights")
    if not isinstance(rights, dict) or rights.get("status") != "reviewed":
        raise EvidenceStop("RIGHTS_UNREVIEWED", "source rights have not been reviewed")
    if not isinstance(rights.get("redistribution"), str) or not rights.get("basis"):
        raise EvidenceStop("MISSING_METADATA", "rights basis and redistribution statement are required")
    if request.get("normalization", "none") != "none":
        raise EvidenceStop("UNSUPPORTED_FORMAT", "normalization is not applied")
