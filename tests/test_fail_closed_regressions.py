#!/usr/bin/env python3
"""Fail-closed regressions for verify.py (stdlib unittest; no-key mode).

Each case was accepted (ok=True) before this change:
  * a chain fragment that does not start at genesis (seq 0),
  * an unsigned envelope with no content-hash field (nothing was checked, yet PASS),
  * a hex field with a trailing newline satisfying a ``^...$`` pattern.
Controls keep the published examples passing, including the signed
integrity-only daily-activity receipt.
"""

import contextlib
import io
import json
import os
import sys
import tempfile
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

import verify  # noqa: E402

SCHEMA = verify.load_schema(os.path.join(REPO_ROOT, "schema", "governed-receipt.schema.json"))
CHAIN = os.path.join(REPO_ROOT, "examples", "a11oy-khipu-chain.json")
DAILY = os.path.join(REPO_ROOT, "examples", "daily-activity-receipt.json")


def _chain():
    with open(CHAIN, "r", encoding="utf-8") as fh:
        return json.load(fh)


class GenesisRequired(unittest.TestCase):
    def test_full_chain_still_passes(self):
        ok, lines = verify.verify_records(_chain(), SCHEMA)
        self.assertTrue(ok, "\n".join(lines))
        self.assertFalse(any("FRAGMENT" in ln for ln in lines))

    def test_fragment_without_genesis_fails_by_default(self):
        ok, lines = verify.verify_records(_chain()[2:], SCHEMA)
        self.assertFalse(ok, "\n".join(lines))
        self.assertTrue(any("does not start at genesis" in ln for ln in lines), "\n".join(lines))

    def test_fragment_is_reported_as_fragment_when_explicitly_allowed(self):
        ok, lines = verify.verify_records(_chain()[2:], SCHEMA, allow_partial=True)
        self.assertTrue(ok, "\n".join(lines))
        self.assertTrue(any("FRAGMENT starting at seq 2" in ln for ln in lines), "\n".join(lines))

    def test_cli_requires_flag_for_fragment(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "fragment.json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(_chain()[2:], fh)
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(1, verify.main([path]))
                self.assertEqual(0, verify.main([path, "--allow-partial"]))


class NothingCheckedIsNotAPass(unittest.TestCase):
    def test_unsigned_unhashed_envelope_fails(self):
        envelope = {"payloadType": "application/octet-stream", "payload": "", "signatures": []}
        ok, lines = verify.verify_records([envelope], SCHEMA)
        self.assertFalse(ok, "\n".join(lines))
        self.assertTrue(any("nothing binds the payload" in ln for ln in lines), "\n".join(lines))

    def test_signed_integrity_only_example_still_passes(self):
        ok, lines = verify.verify_file(DAILY, SCHEMA)
        self.assertTrue(ok, "\n".join(lines))


class PatternEndAnchor(unittest.TestCase):
    HEX = {"type": "string", "pattern": "^[0-9a-f]{64}$"}

    def test_trailing_newline_is_refused(self):
        self.assertTrue(verify.validate("a" * 64 + "\n", self.HEX))

    def test_exact_value_is_accepted(self):
        self.assertFalse(verify.validate("a" * 64, self.HEX))

    def test_escaped_dollar_is_literal(self):
        self.assertFalse(verify.validate("x$", {"type": "string", "pattern": r"^x\$"}))


if __name__ == "__main__":
    unittest.main()
