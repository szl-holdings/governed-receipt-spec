#!/usr/bin/env python3
"""A quantized-artifact claim must carry its bindings or fail closed.

The published SZL-Khipu-1.5B-GGUF record has file digests and no quantizer
version. A claim built from that record must fail. These tests do not
download or rehash the weight bytes.
"""

import base64
import hashlib
import json
import os
import sys
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

import verify  # noqa: E402

SCHEMA = verify.load_schema(os.path.join(REPO_ROOT, "schema", "governed-receipt.schema.json"))

# Provider LFS metadata and the publication eval digest, read 2026-11-04.
# Not an independent byte rehash.
KHIPU_Q4_SHA256 = "13c1a1993063e1dff92f7413ccf48eaca6d48efc8801ae9af35961ae3396623a"
KHIPU_F16_SHA256 = "2348ee342efe639e100f3fb31a3dc11b8c12d8c43ecfe45e18041b9f94c71a12"
KHIPU_EVAL_SHA256 = "9a88c74863099c752bfcd20e7d602ca14c161cc8d68eb78d052af686aebb600e"


def _envelope(claim):
    decision = {
        "action": "inference",
        "ns": "szl-forge",
        "seq": 0,
        "prev": "0" * 64,
        "digest": "ab" * 32,
        "payload_digest": "cd" * 32,
        "ts": "2026-11-04T18:13:34Z",
        "decision": "abstain",
    }
    if claim is not None:
        decision["quantized_artifact"] = claim
    body = json.dumps(decision, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return {
        "payloadType": "application/vnd.szl.khipu+json",
        "payload": base64.b64encode(body).decode("ascii"),
        "payloadSha256": hashlib.sha256(body).hexdigest(),
        "signatures": [],
        "signed": False,
    }


def _complete_claim():
    return {
        "artifact_sha256": "11" * 32,
        "source_weights_sha256": "22" * 32,
        "quantizer_name": "fixture-quantizer",
        "quantizer_version": "0.test",
        "eval_sha256": "33" * 32,
        "bytes_rehashed": False,
    }


class QuantizedArtifactBinding(unittest.TestCase):
    def test_absence_is_not_a_qualification_and_still_passes(self):
        ok, lines = verify.verify_records([_envelope(None)], SCHEMA)
        self.assertTrue(ok, "\n".join(lines))
        self.assertTrue(any("absence is not a qualification" in line for line in lines), "\n".join(lines))

    def test_complete_fixture_claim_passes_without_rehashing(self):
        ok, lines = verify.verify_records([_envelope(_complete_claim())], SCHEMA)
        self.assertTrue(ok, "\n".join(lines))
        self.assertTrue(any("did not rehash the bytes" in line for line in lines), "\n".join(lines))

    def test_khipu_publication_gap_fails(self):
        claim = {
            "artifact_sha256": KHIPU_Q4_SHA256,
            "source_weights_sha256": KHIPU_F16_SHA256,
            "eval_sha256": KHIPU_EVAL_SHA256,
        }
        ok, lines = verify.verify_records([_envelope(claim)], SCHEMA)
        self.assertFalse(ok, "\n".join(lines))
        self.assertTrue(any("quantizer_name" in line and "missing" in line for line in lines), "\n".join(lines))

    def test_unresolved_quantizer_version_fails(self):
        claim = _complete_claim()
        claim["quantizer_version"] = "UNKNOWN"
        ok, lines = verify.verify_records([_envelope(claim)], SCHEMA)
        self.assertFalse(ok, "\n".join(lines))
        self.assertTrue(any("unresolved label" in line for line in lines), "\n".join(lines))

    def test_bytes_rehashed_true_fails(self):
        claim = _complete_claim()
        claim["bytes_rehashed"] = True
        ok, lines = verify.verify_records([_envelope(claim)], SCHEMA)
        self.assertFalse(ok, "\n".join(lines))
        self.assertTrue(any("not rehashed" in line for line in lines), "\n".join(lines))

    def test_short_digest_fails(self):
        claim = _complete_claim()
        claim["eval_sha256"] = "abcd"
        ok, lines = verify.verify_records([_envelope(claim)], SCHEMA)
        self.assertFalse(ok, "\n".join(lines))
        self.assertTrue(any("eval_sha256" in line for line in lines), "\n".join(lines))


if __name__ == "__main__":
    unittest.main()
