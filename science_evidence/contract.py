# SPDX-License-Identifier: Apache-2.0
"""Shared limits for the science evidence workbench.

A passing bundle is a descriptive integrity record. It does not establish
biological correctness, differential expression, normalization validity,
donor identity, adequate power, or clinical suitability.
"""

from __future__ import annotations

import re


SCHEMA = "szl-science-evidence-bundle/v1"
FORMAT = "feature_by_cell_tsv"
NORMALIZATION = "none; missing measurements are rejected and are not stored as zero"
TOKEN = re.compile(r"(?:0|[1-9][0-9]*)(?:\.[0-9]+)?\Z")
TIME = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")

MAX_BYTES = 256_000
MAX_ROWS = 500
MAX_COLUMNS = 64
MAX_FIELD = 128

REASON_CODES = frozenset({
    "MALFORMED_NUMBER",
    "NONFINITE_NUMBER",
    "NEGATIVE_VALUE",
    "DUPLICATE_IDENTIFIER",
    "MISSING_MEASUREMENT",
    "INCOMPATIBLE_SHAPE",
    "MISSING_METADATA",
    "RECORD_FRAMING",
    "SIZE_LIMIT",
    "UNSUPPORTED_FORMAT",
    "EMPTY_INPUT",
    "CHANGED_SOURCE",
    "CHANGED_OUTPUT",
    "INCOMPLETE_EXECUTION",
    "RIGHTS_UNREVIEWED",
    "ATTEMPTS_EXHAUSTED",
    "CANCELLED",
})


class EvidenceStop(Exception):
    """The workbench stopped before producing a usable result."""

    def __init__(self, reason: str, detail: str = "") -> None:
        if reason not in REASON_CODES:
            raise ValueError(f"unknown reason {reason}")
        self.reason = reason
        self.detail = detail
        super().__init__(detail or reason)


def bounded_limit(request: dict, key: str, hard: int) -> int:
    """Return a positive limit that cannot rise above the package cap."""

    raw = request.get(key, hard)
    if isinstance(raw, bool) or not isinstance(raw, int):
        raise EvidenceStop("MISSING_METADATA", f"{key} must be a positive integer")
    if raw < 1 or raw > hard:
        raise EvidenceStop("SIZE_LIMIT", f"{key} is outside 1..{hard}")
    return raw
