"""Self-consistency of conformance/canonicalization-v1.json (offline, stdlib).

Checks every recorded sha256 against its bytes, reproduces both legacy profiles
with the stdlib json parameters they are defined by, and, when the optional
reference implementations are installed, checks the rfc8785 rows too.
"""
import hashlib
import json
import math
from pathlib import Path

import pytest

DOC = json.loads((Path(__file__).resolve().parents[1] / "conformance" /
                  "canonicalization-v1.json").read_text("utf-8"))
LEGACY = {"szl.canon/v1": True, "szl.lambda/v1": False}  # profile -> ensure_ascii


def _decode(x):
    if isinstance(x, dict):
        if set(x) == {"$float"}:
            return float(x["$float"])
        return {k: _decode(v) for k, v in x.items()}
    if isinstance(x, list):
        return [_decode(v) for v in x]
    return x


def _has_nonfinite(v):
    if isinstance(v, float):
        return not math.isfinite(v)
    if isinstance(v, dict):
        return any(_has_nonfinite(w) for w in v.values())
    if isinstance(v, list):
        return any(_has_nonfinite(w) for w in v)
    return False


def test_schema_and_ids():
    assert DOC["schema"] == "szl.canonicalization.vectors/v1"
    assert DOC["profiles"] == ["szl.canon/v1", "szl.lambda/v1", "rfc8785"]
    ids = [c["id"] for c in DOC["cases"]]
    assert len(ids) == len(set(ids))


@pytest.mark.parametrize("case", DOC["cases"], ids=lambda c: c["id"])
def test_digests_match_bytes(case):
    for exp in case["expected"].values():
        if not exp.get("reject"):
            assert hashlib.sha256(exp["utf8"].encode("utf-8")).hexdigest() == exp["sha256"]


@pytest.mark.parametrize("case", DOC["cases"], ids=lambda c: c["id"])
@pytest.mark.parametrize("profile", sorted(LEGACY))
def test_legacy_profiles_reproduce_with_stdlib(case, profile):
    value = _decode(case["input"])
    exp = case["expected"][profile]
    if exp.get("reject"):
        assert _has_nonfinite(value)
        with pytest.raises(ValueError):
            json.dumps(value, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=LEGACY[profile], allow_nan=False)
        return
    got = json.dumps(value, sort_keys=True, separators=(",", ":"),
                     ensure_ascii=LEGACY[profile], allow_nan=False)
    assert got == exp["utf8"]


@pytest.mark.parametrize("case", DOC["cases"], ids=lambda c: c["id"])
def test_rfc8785_rows_against_reference(case):
    rfc8785 = pytest.importorskip("rfc8785")
    value = _decode(case["input"])
    exp = case["expected"]["rfc8785"]
    try:
        ref = rfc8785.dumps(value)
    except Exception:
        assert exp.get("reject") or "rfc8785" in case.get("implementations_may_reject", [])
        return
    assert not exp.get("reject")
    assert ref.decode("utf-8") == exp["utf8"]
