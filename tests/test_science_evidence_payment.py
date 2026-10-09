# SPDX-License-Identifier: Apache-2.0
"""Inert payment-context fixtures. No live Cloudflare charge is attempted."""

from __future__ import annotations

import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from science_evidence.payment import (
    JWKS_URL,
    public_jwk,
    response_headers,
    sign_fixture,
    validate_payment_context,
)


AUDIENCE = "https://example.test/science-report"
NOW = 1_770_000_100


def claims(**overrides):
    value = {"iat": NOW - 10, "nbf": NOW - 10, "exp": NOW + 60, "aud": AUDIENCE, "scheme": "exact", "amount": "25000"}
    value.update(overrides)
    return value


class PaymentTests(unittest.TestCase):
    def setUp(self) -> None:
        self.private = Ed25519PrivateKey.generate()
        self.keys = [public_jwk(self.private.public_key())]

    def token(self, **overrides) -> str:
        return sign_fixture(self.private, claims(**overrides))

    def test_pinned_jwks_and_absent_header_are_unpaid(self) -> None:
        self.assertEqual(JWKS_URL, "https://payments.cloudflare.com/certs")
        decision = validate_payment_context(None, audience=AUDIENCE, keys=self.keys, now=NOW)
        self.assertFalse(decision["authorized"])
        self.assertEqual(decision["reason"], "ABSENT")
        self.assertIsNone(decision["payment_settlement"])
        self.assertFalse(decision["live"])
        self.assertEqual(decision["idempotency"], "UNRESOLVED")

    def test_exact_scheme_does_not_emit_settlement(self) -> None:
        decision = validate_payment_context(self.token(), audience=AUDIENCE, keys=self.keys, now=NOW, actual_amount="1")
        self.assertTrue(decision["authorized"])
        self.assertEqual(decision["scheme"], "exact")
        self.assertIsNone(decision["payment_settlement"])
        self.assertNotIn("PAYMENT-RESPONSE", response_headers(decision))
        self.assertNotIn("PAYMENT-SETTLEMENT", response_headers(decision))

    def test_upto_settles_only_a_successful_in_range_amount(self) -> None:
        token = self.token(scheme="upto", amount="1000")
        ok = validate_payment_context(token, audience=AUDIENCE, keys=self.keys, now=NOW, status_code=200, actual_amount="1000")
        self.assertEqual(ok["payment_settlement"], {"amount": "1000"})
        self.assertEqual(response_headers(ok)["PAYMENT-SETTLEMENT"], '{"amount":"1000"}')
        self.assertNotIn("PAYMENT-RESPONSE", response_headers(ok))
        failed = validate_payment_context(token, audience=AUDIENCE, keys=self.keys, now=NOW, status_code=400, actual_amount="1000")
        self.assertTrue(failed["authorized"])
        self.assertIsNone(failed["payment_settlement"])
        over = validate_payment_context(token, audience=AUDIENCE, keys=self.keys, now=NOW, actual_amount="1001")
        self.assertFalse(over["authorized"])
        self.assertEqual(over["reason"], "ABOVE_AUTHORIZED_MAXIMUM")
        self.assertIsNone(over["payment_settlement"])
        zero = validate_payment_context(token, audience=AUDIENCE, keys=self.keys, now=NOW, actual_amount="0")
        self.assertEqual(zero["payment_settlement"], {"amount": "0"})

    def test_bad_signature_time_audience_and_wallet_header_are_rejected(self) -> None:
        bad = self.token()[:-2] + "aa"
        self.assertFalse(validate_payment_context(bad, audience=AUDIENCE, keys=self.keys, now=NOW)["authorized"])
        expired = validate_payment_context(self.token(exp=NOW - 1), audience=AUDIENCE, keys=self.keys, now=NOW)
        self.assertEqual(expired["reason"], "TIME_WINDOW")
        early = validate_payment_context(self.token(nbf=NOW + 5), audience=AUDIENCE, keys=self.keys, now=NOW)
        self.assertEqual(early["reason"], "TIME_WINDOW")
        wrong = validate_payment_context(self.token(), audience="https://example.test/other", keys=self.keys, now=NOW)
        self.assertEqual(wrong["reason"], "AUDIENCE")
        none_alg = "eyJhbGciOiJub25lIn0.eyJhdWQiOiJ4In0.e30"
        self.assertEqual(validate_payment_context(none_alg, audience=AUDIENCE, keys=self.keys, now=NOW)["reason"], "ALGORITHM")
        wallet = validate_payment_context("0xabc", audience=AUDIENCE, keys=self.keys, now=NOW)
        self.assertFalse(wallet["authorized"])
        self.assertFalse(wallet["origin_creates_payment_response"])
        self.assertNotIn("PAYMENT-RESPONSE", response_headers(wallet))


if __name__ == "__main__":
    unittest.main()
