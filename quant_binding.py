# SPDX-License-Identifier: Apache-2.0
"""Refuse a quantized-artifact claim that does not carry its bindings.

The check is structural. It does not download weights, rehash bytes, or
decide that a named quantizer produced an artifact.
"""

from __future__ import annotations

import re

_SHA256_HEX = re.compile(r"^[0-9a-f]{64}\Z")
_UNRESOLVED = frozenset({"UNKNOWN", "NOT_CLAIMED", "UNAVAILABLE", "TBD", "NONE"})
_REQUIRED = (
    "artifact_sha256",
    "source_weights_sha256",
    "quantizer_name",
    "quantizer_version",
    "eval_sha256",
)


def check_quantized_artifact_binding(decision):
    """Return (ok, message) for an optional quantized-artifact claim.

    No claim is not a qualification. A claim that is present must name the
    artifact digest, the source-weight digest, a real quantizer name and
    version, and the fixed eval digest. ``bytes_rehashed: true`` is refused
    because this verifier never rehashes the weight bytes.
    """
    if not isinstance(decision, dict) or "quantized_artifact" not in decision:
        return True, "no quantized artifact claim (n/a); absence is not a qualification"
    claim = decision["quantized_artifact"]
    if not isinstance(claim, dict):
        return False, "quantized artifact claim must be an object"
    if claim.get("bytes_rehashed") is True:
        return False, "quantized artifact bytes were not rehashed by this verifier"
    missing = [name for name in _REQUIRED if name not in claim]
    if missing:
        return False, "quantized artifact claim missing %s" % ", ".join(missing)
    for name in ("artifact_sha256", "source_weights_sha256", "eval_sha256"):
        value = claim[name]
        if not isinstance(value, str) or _SHA256_HEX.fullmatch(value) is None:
            return False, "quantized artifact %s must be 64 lowercase hex" % name
    for name in ("quantizer_name", "quantizer_version"):
        value = claim[name]
        if not isinstance(value, str) or not value.strip():
            return False, "quantized artifact %s must be a non-empty string" % name
        if value.strip().upper() in _UNRESOLVED:
            return False, "quantized artifact %s is an unresolved label" % name
    return True, "quantized artifact fields present; this verifier did not rehash the bytes"
