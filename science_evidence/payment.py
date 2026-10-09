# SPDX-License-Identifier: Apache-2.0
"""Local PAYMENT-CONTEXT checks.

The live Cloudflare JWKS is https://payments.cloudflare.com/certs. Tests
inject inert keys and never call that endpoint. This module does not create
PAYMENT-RESPONSE and does not emit PAYMENT-SETTLEMENT for fixed exact prices.
Production idempotency, replay and live settlement remain unresolved.
"""

from __future__ import annotations

import base64
import json
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


JWKS_URL = "https://payments.cloudflare.com/certs"
ATOMIC = __import__("re").compile(r"(?:0|[1-9][0-9]*)\Z")


class PaymentRejected(Exception):
    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(segment: str) -> bytes:
    if not isinstance(segment, str) or not segment:
        raise PaymentRejected("MALFORMED")
    pad = "=" * ((4 - len(segment) % 4) % 4)
    try:
        return base64.urlsafe_b64decode(segment + pad)
    except (ValueError, base64.binascii.Error) as exc:
        raise PaymentRejected("MALFORMED") from exc


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
    return int(value)


def validate_payment_context(
    header: str | None,
    *,
    audience: str,
    keys: list[dict],
    now: int | None = None,
    status_code: int = 200,
    actual_amount: str | None = None,
) -> dict:
    decision = {
        "authorized": False,
        "reason": "ABSENT",
        "scheme": None,
        "audience": audience,
        "authorized_amount": None,
        "payment_settlement": None,
        "origin_creates_payment_response": False,
        "production_status": "LOCAL_TEST_ONLY",
        "idempotency": "UNRESOLVED",
        "replay_protection": "NOT_IMPLEMENTED",
        "live": False,
        "jwks_url": JWKS_URL,
    }
    if header is None or header == "":
        return decision
    now = int(time.time()) if now is None else now
    if type(now) is not int:
        raise PaymentRejected("TIME_WINDOW")
    try:
        parts = header.split(".")
        if len(parts) != 3:
            raise PaymentRejected("MALFORMED")
        header_obj = json.loads(_b64url_decode(parts[0]))
        if header_obj.get("alg") != "EdDSA":
            raise PaymentRejected("ALGORITHM")
        key = _select_key(keys, header_obj.get("kid"))
        key.verify(_b64url_decode(parts[2]), f"{parts[0]}.{parts[1]}".encode("ascii"))
        claims = json.loads(_b64url_decode(parts[1]))
        for name in ("iat", "nbf", "exp"):
            if type(claims.get(name)) is not int:
                raise PaymentRejected("TIME_WINDOW")
        if claims["nbf"] > now or now >= claims["exp"] or claims["iat"] > now or claims["iat"] > claims["exp"]:
            raise PaymentRejected("TIME_WINDOW")
        if claims.get("aud") != audience or not isinstance(audience, str):
            raise PaymentRejected("AUDIENCE")
        if claims.get("scheme") not in {"exact", "upto"}:
            raise PaymentRejected("SCHEME")
        amount = _atomic(claims.get("amount"))
        settlement = None
        if claims["scheme"] == "upto" and 200 <= status_code < 400:
            if actual_amount is None:
                raise PaymentRejected("AMOUNT")
            actual = _atomic(actual_amount)
            if actual > amount:
                raise PaymentRejected("ABOVE_AUTHORIZED_MAXIMUM")
            settlement = {"amount": str(actual)}
        decision.update({
            "authorized": True,
            "reason": None,
            "scheme": claims["scheme"],
            "authorized_amount": str(amount),
            "payment_settlement": settlement,
        })
        return decision
    except PaymentRejected as exc:
        decision["reason"] = exc.reason
        decision["payment_settlement"] = None
        return decision
    except (InvalidSignature, json.JSONDecodeError, UnicodeError, ValueError):
        decision["reason"] = "SIGNATURE" if header.count(".") == 2 else "MALFORMED"
        decision["payment_settlement"] = None
        return decision


def response_headers(decision: dict) -> dict[str, str]:
    headers: dict[str, str] = {}
    settlement = decision.get("payment_settlement")
    if settlement is not None:
        headers["PAYMENT-SETTLEMENT"] = json.dumps(settlement, separators=(",", ":"))
    return headers
