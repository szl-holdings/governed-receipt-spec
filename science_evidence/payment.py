# SPDX-License-Identifier: Apache-2.0
"""Local PAYMENT-CONTEXT checks. Deprecated; local tests only.

Deprecated in favour of the estate's canonical validators in
szl-holdings/szl-trust: ``scripts/x402_payment_context.py`` (Python) and
``ops/evidence-snapshot-worker/src/payment-context.mjs`` (Workers). New code
must use those. This module stays for its existing local tests, applies the
same contract, and agrees with them on every shared vector in
``tests/fixtures/x402-payment-context.v1.json`` (copied from szl-trust).

The caller states the route's scheme and price. An ``exact`` context must sign
exactly ``expected_amount``; an ``upto`` maximum must not exceed it. A context
signed under a cheaper rule, or under the other scheme, is rejected. Clock
leeway defaults to 5 seconds and is bounded to 0..30 seconds.

The live Cloudflare JWKS is https://payments.cloudflare.com/certs. Tests inject
inert keys and never call that endpoint; this module never fetches keys. It
does not create PAYMENT-RESPONSE and does not emit PAYMENT-SETTLEMENT for fixed
exact prices. Cloudflare's documented claims define no ``jti`` or nonce;
replay protection is not implemented here, and production idempotency and live
settlement remain unresolved.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
import time
import warnings

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


JWKS_URL = "https://payments.cloudflare.com/certs"
CANONICAL_VALIDATOR = "szl-holdings/szl-trust:scripts/x402_payment_context.py"
SCHEMES = frozenset({"exact", "upto"})
MIN_ATOMIC = 1_000
MAX_ATOMIC = 100_000_000
DEFAULT_LEEWAY_SECONDS = 5
MAX_LEEWAY_SECONDS = 30
MAX_TOKEN_LENGTH = 8_192
MAX_SAFE_INTEGER = 2**53 - 1
FORBIDDEN_HEADER_PARAMS = frozenset({"jku", "jwk", "x5u", "x5c"})
UNSUPPORTED_HEADER_PARAMS = frozenset({"crit", "b64"})
ATOMIC = re.compile(r"0|[1-9][0-9]*")
_SEGMENT = re.compile(r"[A-Za-z0-9_-]+")
_AUDIENCE = re.compile(
    r"https://[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?(?::[0-9]{1,5})?/[A-Za-z0-9._~!$&'()*+,;=:@%/-]*")


class PaymentRejected(Exception):
    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(segment: str) -> bytes:
    if not isinstance(segment, str) or not segment or _SEGMENT.fullmatch(segment) is None or len(segment) % 4 == 1:
        raise PaymentRejected("MALFORMED")
    try:
        decoded = base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))
    except (ValueError, binascii.Error) as exc:
        raise PaymentRejected("MALFORMED") from exc
    if _b64url(decoded) != segment:
        raise PaymentRejected("MALFORMED")
    return decoded


def _reject_constant(name: str) -> None:
    raise ValueError(f"non-standard JSON constant {name}")


def _strict_json(data: bytes) -> object:
    return json.loads(data.decode("utf-8"), parse_constant=_reject_constant,
                      parse_int=lambda text: int(text) if len(text) <= 17 else float(text))


def sign_fixture(private_key, claims: dict, *, kid: str = "fixture") -> str:
    """Sign an inert test token. Not a Cloudflare payment."""

    header = {"alg": "EdDSA", "typ": "JWT", "kid": kid}
    signing_input = f"{_b64url(json.dumps(header, separators=(',', ':')).encode())}.{_b64url(json.dumps(claims, separators=(',', ':')).encode())}"
    signature = private_key.sign(signing_input.encode("ascii"))
    return f"{signing_input}.{_b64url(signature)}"


def public_jwk(public_key: Ed25519PublicKey, *, kid: str = "fixture") -> dict:
    raw = public_key.public_bytes_raw()
    return {"kty": "OKP", "crv": "Ed25519", "alg": "EdDSA", "kid": kid, "x": _b64url(raw)}


def _select_key(keys: list[dict], kid: str | None) -> Ed25519PublicKey:
    matches = []
    for key in keys:
        if key.get("kty") != "OKP" or key.get("crv") != "Ed25519":
            continue
        if kid is not None and key.get("kid") != kid:
            continue
        if kid is None and len(keys) != 1:
            continue
        raw = _b64url_decode(key.get("x", ""))
        if len(raw) != 32:
            raise PaymentRejected("KEY")
        matches.append(Ed25519PublicKey.from_public_bytes(raw))
    if len(matches) != 1:
        raise PaymentRejected("KEY")
    return matches[0]


def _atomic(value: object) -> int:
    if not isinstance(value, str) or ATOMIC.fullmatch(value) is None:
        raise PaymentRejected("AMOUNT")
    if len(value) > len(str(MAX_ATOMIC)):
        return MAX_ATOMIC + 1
    return int(value)


def _numeric_date(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if abs(value) <= MAX_SAFE_INTEGER else None
    if isinstance(value, float) and value.is_integer() and abs(value) <= MAX_SAFE_INTEGER:
        return int(value)
    return None


def _expected_atomic(expected_amount: object) -> int:
    if isinstance(expected_amount, int) and not isinstance(expected_amount, bool):
        expected = expected_amount
    elif isinstance(expected_amount, str) and ATOMIC.fullmatch(expected_amount):
        expected = _atomic(expected_amount)
    else:
        raise PaymentRejected("EXPECTED_AMOUNT")
    if not MIN_ATOMIC <= expected <= MAX_ATOMIC:
        raise PaymentRejected("EXPECTED_AMOUNT")
    return expected


def validate_payment_context(
    header: str | None,
    *,
    audience: str,
    keys: list[dict],
    scheme: str,
    expected_amount: int | str,
    now: int | None = None,
    leeway: int = DEFAULT_LEEWAY_SECONDS,
    status_code: int = 200,
    actual_amount: str | None = None,
) -> dict:
    """Deprecated: use the canonical validator in szl-trust (see CANONICAL_VALIDATOR).

    Raises ``PaymentRejected`` for a caller error (scheme, expected amount,
    leeway, audience or ``now``); returns an unauthorized decision for a bad or
    absent token.
    """
    warnings.warn(
        f"science_evidence.payment is deprecated; use {CANONICAL_VALIDATOR}",
        DeprecationWarning,
        stacklevel=2,
    )
    if not isinstance(scheme, str) or scheme not in SCHEMES:
        raise PaymentRejected("SCHEME_CONFIG")
    if type(leeway) is not int or not 0 <= leeway <= MAX_LEEWAY_SECONDS:
        raise PaymentRejected("LEEWAY")
    if not isinstance(audience, str) or _AUDIENCE.fullmatch(audience) is None:
        raise PaymentRejected("AUDIENCE_CONFIG")
    expected = _expected_atomic(expected_amount)
    now = int(time.time()) if now is None else now
    if type(now) is not int:
        raise PaymentRejected("TIME_WINDOW")
    decision = {
        "authorized": False,
        "reason": "ABSENT",
        "scheme": None,
        "audience": audience,
        "expected_scheme": scheme,
        "expected_amount": str(expected),
        "authorized_amount": None,
        "payment_settlement": None,
        "origin_creates_payment_response": False,
        "production_status": "LOCAL_TEST_ONLY",
        "deprecated": True,
        "canonical_validator": CANONICAL_VALIDATOR,
        "idempotency": "UNRESOLVED",
        "replay_protection": "NOT_IMPLEMENTED",
        "live": False,
        "jwks_url": JWKS_URL,
    }
    if header is None or header == "":
        return decision
    try:
        if not isinstance(header, str) or len(header) > MAX_TOKEN_LENGTH:
            raise PaymentRejected("MALFORMED")
        parts = header.split(".")
        if len(parts) != 3:
            raise PaymentRejected("MALFORMED")
        header_bytes, payload_bytes, signature = (_b64url_decode(part) for part in parts)
        header_obj = _strict_json(header_bytes)
        if not isinstance(header_obj, dict):
            raise PaymentRejected("MALFORMED")
        if header_obj.get("alg") != "EdDSA":
            raise PaymentRejected("ALGORITHM")
        if FORBIDDEN_HEADER_PARAMS.intersection(header_obj):
            raise PaymentRejected("KEY_HEADER")
        if UNSUPPORTED_HEADER_PARAMS.intersection(header_obj):
            raise PaymentRejected("HEADER")
        kid = header_obj.get("kid")
        if "kid" in header_obj and (not isinstance(kid, str) or not kid):
            raise PaymentRejected("MALFORMED")
        key = _select_key(keys, kid)
        key.verify(signature, f"{parts[0]}.{parts[1]}".encode("ascii"))
        claims = _strict_json(payload_bytes)
        if not isinstance(claims, dict):
            raise PaymentRejected("MALFORMED")
        iat, nbf, exp = (_numeric_date(claims.get(name)) for name in ("iat", "nbf", "exp"))
        if iat is None or nbf is None or exp is None or iat > exp or nbf > exp:
            raise PaymentRejected("TIME_WINDOW")
        if exp <= now - leeway or nbf > now + leeway or iat > now + leeway:
            raise PaymentRejected("TIME_WINDOW")
        if not isinstance(claims.get("aud"), str) or claims["aud"] != audience:
            raise PaymentRejected("AUDIENCE")
        if claims.get("scheme") != scheme:
            raise PaymentRejected("SCHEME")
        amount = _atomic(claims.get("amount"))
        if not MIN_ATOMIC <= amount <= MAX_ATOMIC:
            raise PaymentRejected("AMOUNT")
        if scheme == "exact" and amount != expected:
            raise PaymentRejected("AMOUNT_MISMATCH")
        if scheme == "upto" and amount > expected:
            raise PaymentRejected("ABOVE_CONFIGURED_MAXIMUM")
        settlement = None
        if scheme == "upto" and 200 <= status_code < 400:
            if actual_amount is None:
                raise PaymentRejected("AMOUNT")
            actual = _atomic(actual_amount)
            if actual > amount:
                raise PaymentRejected("ABOVE_AUTHORIZED_MAXIMUM")
            settlement = {"amount": str(actual)}
        decision.update({
            "authorized": True,
            "reason": None,
            "scheme": scheme,
            "authorized_amount": str(amount),
            "payment_settlement": settlement,
        })
        return decision
    except PaymentRejected as exc:
        decision["reason"] = exc.reason
        decision["payment_settlement"] = None
        return decision
    except InvalidSignature:
        decision["reason"] = "SIGNATURE"
        decision["payment_settlement"] = None
        return decision
    except (json.JSONDecodeError, UnicodeError, ValueError, RecursionError):
        decision["reason"] = "MALFORMED"
        decision["payment_settlement"] = None
        return decision


def response_headers(decision: dict) -> dict[str, str]:
    headers: dict[str, str] = {}
    settlement = decision.get("payment_settlement")
    if settlement is not None:
        headers["PAYMENT-SETTLEMENT"] = json.dumps(settlement, separators=(",", ":"))
    return headers
