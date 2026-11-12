# SPDX-License-Identifier: Apache-2.0
"""Inert payment-context fixtures. No live Cloudflare charge is attempted."""

from __future__ import annotations

import hashlib
import json
import unittest
import warnings
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from science_evidence.payment import (
    CANONICAL_VALIDATOR,
    DEFAULT_LEEWAY_SECONDS,
    JWKS_URL,
    MAX_LEEWAY_SECONDS,
    PaymentRejected,
    public_jwk,
    response_headers,
    sign_fixture,
    validate_payment_context as _validate_payment_context,
)


AUDIENCE = "https://example.test/science-report"
NOW = 1_770_000_100
PRICE = "25000"
VECTORS = Path(__file__).resolve().parent / "fixtures" / "x402-payment-context.v1.json"
# Copied byte for byte from szl-holdings/szl-trust tests/vectors/x402-payment-context.v1.json
# (generated there by tools/x402_payment_context_vectors.py). Re-copy, and update this pin,
# whenever the canonical vectors change.
VECTORS_SHA256 = "0285e9bf9aed7776823005880d3b77fb8846dac368911dce3d781eb46b167556"


def validate_payment_context(*args, **kwargs):
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        return _validate_payment_context(*args, **kwargs)


def claims(**overrides):
    value = {"iat": NOW - 10, "nbf": NOW - 10, "exp": NOW + 60, "aud": AUDIENCE, "scheme": "exact", "amount": PRICE}
    value.update(overrides)
    return value


class PaymentTests(unittest.TestCase):
    def setUp(self) -> None:
        self.private = Ed25519PrivateKey.generate()
        self.keys = [public_jwk(self.private.public_key())]

    def token(self, **overrides) -> str:
        return sign_fixture(self.private, claims(**overrides))

    def check(self, token, **overrides) -> dict:
        options = {"audience": AUDIENCE, "keys": self.keys, "now": NOW, "scheme": "exact", "expected_amount": PRICE}
        options.update(overrides)
        return validate_payment_context(token, **options)

    def test_pinned_jwks_and_absent_header_are_unpaid(self) -> None:
        self.assertEqual(JWKS_URL, "https://payments.cloudflare.com/certs")
        decision = self.check(None)
        self.assertFalse(decision["authorized"])
        self.assertEqual(decision["reason"], "ABSENT")
        self.assertIsNone(decision["payment_settlement"])
        self.assertFalse(decision["live"])
        self.assertEqual(decision["idempotency"], "UNRESOLVED")
        self.assertEqual(decision["replay_protection"], "NOT_IMPLEMENTED")

    def test_exact_scheme_does_not_emit_settlement(self) -> None:
        decision = self.check(self.token(), actual_amount="1")
        self.assertTrue(decision["authorized"])
        self.assertEqual(decision["scheme"], "exact")
        self.assertIsNone(decision["payment_settlement"])
        self.assertNotIn("PAYMENT-RESPONSE", response_headers(decision))
        self.assertNotIn("PAYMENT-SETTLEMENT", response_headers(decision))

    def test_upto_settles_only_a_successful_in_range_amount(self) -> None:
        token = self.token(scheme="upto", amount="1000")
        upto = {"scheme": "upto", "expected_amount": "1000"}
        ok = self.check(token, status_code=200, actual_amount="1000", **upto)
        self.assertEqual(ok["payment_settlement"], {"amount": "1000"})
        self.assertEqual(response_headers(ok)["PAYMENT-SETTLEMENT"], '{"amount":"1000"}')
        self.assertNotIn("PAYMENT-RESPONSE", response_headers(ok))
        failed = self.check(token, status_code=400, actual_amount="1000", **upto)
        self.assertTrue(failed["authorized"])
        self.assertIsNone(failed["payment_settlement"])
        over = self.check(token, actual_amount="1001", **upto)
        self.assertFalse(over["authorized"])
        self.assertEqual(over["reason"], "ABOVE_AUTHORIZED_MAXIMUM")
        self.assertIsNone(over["payment_settlement"])
        zero = self.check(token, actual_amount="0", **upto)
        self.assertEqual(zero["payment_settlement"], {"amount": "0"})

    def test_bad_signature_time_audience_and_wallet_header_are_rejected(self) -> None:
        bad = self.token()[:-2] + "aa"
        self.assertFalse(self.check(bad)["authorized"])
        expired = self.check(self.token(exp=NOW - DEFAULT_LEEWAY_SECONDS))
        self.assertEqual(expired["reason"], "TIME_WINDOW")
        early = self.check(self.token(nbf=NOW + DEFAULT_LEEWAY_SECONDS + 1))
        self.assertEqual(early["reason"], "TIME_WINDOW")
        wrong = self.check(self.token(), audience="https://example.test/other")
        self.assertEqual(wrong["reason"], "AUDIENCE")
        none_alg = "eyJhbGciOiJub25lIn0.eyJhdWQiOiJ4In0.e30"
        self.assertEqual(self.check(none_alg)["reason"], "ALGORITHM")
        wallet = self.check("0xabc")
        self.assertFalse(wallet["authorized"])
        self.assertFalse(wallet["origin_creates_payment_response"])
        self.assertNotIn("PAYMENT-RESPONSE", response_headers(wallet))

    def test_expected_scheme_and_amount_are_required(self) -> None:
        with self.assertRaises(TypeError):
            validate_payment_context(self.token(), audience=AUDIENCE, keys=self.keys, now=NOW)
        with self.assertRaises(TypeError):
            validate_payment_context(self.token(), audience=AUDIENCE, keys=self.keys, now=NOW, scheme="exact")
        for bad in (None, True, "25000.0", "025000", 999, 100_000_001):
            with self.assertRaises(PaymentRejected) as raised:
                self.check(self.token(), expected_amount=bad)
            self.assertEqual(raised.exception.reason, "EXPECTED_AMOUNT")
        with self.assertRaises(PaymentRejected) as raised:
            self.check(self.token(), scheme="fixed")
        self.assertEqual(raised.exception.reason, "SCHEME_CONFIG")

    def test_context_signed_under_a_cheaper_rule_is_rejected(self) -> None:
        for amount in ("1000", "10000", "24999", "25001", "100000"):
            decision = self.check(self.token(amount=amount))
            self.assertFalse(decision["authorized"], amount)
            self.assertEqual(decision["reason"], "AMOUNT_MISMATCH")
        confused = self.check(self.token(scheme="upto", amount="1000"))
        self.assertEqual(confused["reason"], "SCHEME")
        over = self.check(self.token(scheme="upto", amount="25001"), scheme="upto", actual_amount="0")
        self.assertEqual(over["reason"], "ABOVE_CONFIGURED_MAXIMUM")
        under = self.check(self.token(scheme="upto", amount="20000"), scheme="upto", actual_amount="20000")
        self.assertEqual((under["authorized"], under["authorized_amount"]), (True, "20000"))

    def test_leeway_is_five_seconds_and_bounded(self) -> None:
        self.assertEqual((DEFAULT_LEEWAY_SECONDS, MAX_LEEWAY_SECONDS), (5, 30))
        self.assertTrue(self.check(self.token(iat=NOW + 4))["authorized"])
        self.assertEqual(self.check(self.token(iat=NOW + 6))["reason"], "TIME_WINDOW")
        self.assertTrue(self.check(self.token(nbf=NOW + 4))["authorized"])
        self.assertEqual(self.check(self.token(nbf=NOW + 6))["reason"], "TIME_WINDOW")
        self.assertTrue(self.check(self.token(exp=NOW - 4))["authorized"])
        self.assertEqual(self.check(self.token(iat=NOW + 4), leeway=0)["reason"], "TIME_WINDOW")
        for leeway in (31, -1, True, 5.0):
            with self.assertRaises(PaymentRejected) as raised:
                self.check(self.token(), leeway=leeway)
            self.assertEqual(raised.exception.reason, "LEEWAY")

    def test_token_supplied_key_material_is_rejected(self) -> None:
        import base64
        for name, value in (("jku", "https://attacker.invalid/keys"), ("x5c", []), ("crit", ["exp"])):
            header = {"alg": "EdDSA", "typ": "JWT", "kid": "fixture", name: value}
            encoded = [base64.urlsafe_b64encode(json.dumps(part, separators=(",", ":")).encode()).rstrip(b"=").decode()
                       for part in (header, claims())]
            signing_input = ".".join(encoded)
            signature = base64.urlsafe_b64encode(self.private.sign(signing_input.encode())).rstrip(b"=").decode()
            decision = self.check(f"{signing_input}.{signature}")
            self.assertEqual(decision["reason"], "HEADER" if name == "crit" else "KEY_HEADER")

    def test_deprecated_in_favour_of_the_canonical_validator(self) -> None:
        with self.assertWarns(DeprecationWarning) as caught:
            decision = _validate_payment_context(self.token(), audience=AUDIENCE, keys=self.keys, now=NOW,
                                                 scheme="exact", expected_amount=PRICE)
        self.assertIn("szl-trust", str(caught.warning))
        self.assertTrue(decision["deprecated"])
        self.assertEqual(decision["canonical_validator"], CANONICAL_VALIDATOR)
        self.assertEqual(decision["production_status"], "LOCAL_TEST_ONLY")


# Canonical reason codes (szl-trust) and the codes this deprecated module reports.
REASONS = {
    "ABSENT": "ABSENT", "MALFORMED_TOKEN": "MALFORMED", "WRONG_ALGORITHM": "ALGORITHM",
    "TOKEN_SUPPLIED_KEY_MATERIAL": "KEY_HEADER", "UNSUPPORTED_HEADER": "HEADER", "UNKNOWN_KEY": "KEY",
    "BAD_SIGNATURE": "SIGNATURE", "TIME_CLAIMS_INVALID": "TIME_WINDOW", "EXPIRED": "TIME_WINDOW",
    "NOT_YET_VALID": "TIME_WINDOW", "WRONG_AUDIENCE": "AUDIENCE", "WRONG_SCHEME": "SCHEME",
    "MALFORMED_AMOUNT": "AMOUNT", "AMOUNT_OUT_OF_BOUNDS": "AMOUNT", "AMOUNT_MISMATCH": "AMOUNT_MISMATCH",
    "AMOUNT_ABOVE_MAXIMUM": "ABOVE_CONFIGURED_MAXIMUM",
}
CONFIG_REASONS = {
    "UNKNOWN_SCHEME": "SCHEME_CONFIG", "BAD_LEEWAY": "LEEWAY", "BAD_AUDIENCE": "AUDIENCE_CONFIG",
    "BAD_EXPECTED_AMOUNT": "EXPECTED_AMOUNT", "BAD_NOW": "TIME_WINDOW",
}


class CanonicalVectorAgreementTests(unittest.TestCase):
    """The deprecated module decides every shared vector as the canonical validators do."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.raw = VECTORS.read_bytes()
        cls.document = json.loads(cls.raw)

    def test_fixture_is_the_pinned_copy(self) -> None:
        self.assertEqual(hashlib.sha256(self.raw).hexdigest(), VECTORS_SHA256)
        self.assertEqual(self.document["schema"], "szl.x402-payment-context-vectors.v1")
        self.assertEqual(self.document["contract"]["default_leeway_seconds"], DEFAULT_LEEWAY_SECONDS)
        self.assertEqual(self.document["contract"]["max_leeway_seconds"], MAX_LEEWAY_SECONDS)

    def test_every_vector_agrees(self) -> None:
        checked = 0
        for vector in self.document["vectors"]:
            if "request_url" in vector:
                continue  # this deprecated API has no request-URL binding
            checked += 1
            with self.subTest(vector=vector["name"]):
                expected = vector["result"]
                try:
                    decision = validate_payment_context(
                        vector["token"], audience=vector["expected_audience"],
                        keys=self.document["jwks"][vector["jwks"]]["keys"], scheme=vector["scheme"],
                        expected_amount=vector["expected_amount"], now=vector["now"], leeway=vector["leeway"],
                        actual_amount="0" if vector["scheme"] == "upto" else None)
                except PaymentRejected as exc:
                    self.assertFalse(expected["valid"])
                    self.assertEqual(exc.reason, CONFIG_REASONS[expected["reason"]])
                    continue
                self.assertEqual(decision["authorized"], expected["valid"])
                if expected["valid"]:
                    self.assertEqual(decision["authorized_amount"], str(expected["amount"]))
                else:
                    self.assertEqual(decision["reason"], REASONS[expected["reason"]])
        self.assertGreaterEqual(checked, 80)


if __name__ == "__main__":
    unittest.main()
