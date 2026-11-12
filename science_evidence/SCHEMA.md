# Science evidence schemas

These records are descriptive. A pass does not establish biological correctness,
differential expression, normalization validity, statistical power, causal
evidence, donor identity, or clinical suitability. Receipts from this package
are unsigned and are not governed-receipt issuances.

## Bundle `szl-science-evidence-bundle/v1`

Separate fields, not one blended blob:

- `raw_input_sha256` and `raw_input_bytes`: exact submitted bytes
- `parsed_summary`: counts after the declared parse
- `normalization_policy`: always none; blank measurements are rejected
- `code_revision`: git HEAD, or `UNAVAILABLE`
- `environment`: Python and platform
- `parameters`: format, accession, ERCC prefix, threshold
- `output_sha256`: canonical parsed summary
- `counts`: `pass`, `fail`, `skip`, `not_run`
- `signed`: false
- `attempt`: reserved count, limit, and absorbing terminal

Supported format: `feature_by_cell_tsv`, tab-delimited, UTF-8, no byte-order mark.
Tokens are nonnegative decimals. `ERCC-` rows are counted apart from other features.
Default budgets: 256000 bytes, 500 feature rows, 64 cell columns.
A request may lower a budget. It cannot raise one, and a boolean is not a number.

`GSE85241` is a retained external example of this shape (17005498 bytes,
SHA-256 `2f253ffb1f6d54f6bb259e862195f5c20ea3f13e00471b9864ff92773658f513`).
It is above this package's byte budget, is not redistributed here, and is not
re-executed by this package. No second public accession has been format-checked
under the budget.

## Watch item

Required: stable `item_id`, customer or reviewer `question`, `source_id`,
`revision`, evidence `category`, `blocker`, `unblock_condition`, `assumptions`,
`external_checks`, `rate_policy`, `reviewer`, `rights`, `next_permitted_check`.

Categories: `ACCESS_LIMITED`, `COVERAGE_MISSING`, `POWER_INADEQUATE`,
`INSTRUMENT_UNAVAILABLE`, `METADATA_INSUFFICIENT`, `RELEASE_UNCHANGED`,
`CHANGE_REQUIRES_REVIEW`.

`scientific_validity` stays `NOT_ESTABLISHED`. The software rejects a decision
named `SCIENTIFICALLY_VALID`. A changed release is recorded as `observed_release`
and does not replace the pinned `revision` or clear `REVIEW_REQUIRED`.
Unavailable sources set `evidence_against_hypothesis`
false. Failed, interrupted, and inaccessible checks do not advance
`last_successfully_checked`. History is append-only. Customer items stay out of
`public_projection` unless `publication_approved` is set.

## Model register

Classifications are `QUALIFIED_WITHIN_SCOPE`, `RESEARCH_ONLY`, `BLOCKED`, or
`UNKNOWN`. The inspected study5 adapter is `BLOCKED`. Nothing in the register
is enabled for production or paid inference.

## Evidence chain `szl-science-evidence-chain/v1`

Slots stay separate: `source`, `tests`, `publication`, `runtime`, `integrity`,
and `authority`. A missing slot is `MISSING`. A digest, when present, is the
full lowercase SHA-256. `observation_time` and `ui_refresh_time` are different
fields. `stale` is `UNKNOWN` until the caller sets it.

Recovery kinds are `MODELED_REPLAY`, `POSTURE_CORRECTION`, and
`INDEPENDENTLY_VERIFIED`. A modeled replay and a posture correction do not
repair infrastructure. A complete verified record can show before-state,
detector, approval, action, after-state, source identity, and readback.
`infrastructure_repaired` stays false and `repair_conclusion` stays
`NOT_CONCLUDED`.

## Payment context (deprecated)

`science_evidence/payment.py` is deprecated in favour of the canonical
validators in szl-holdings/szl-trust: `scripts/x402_payment_context.py`
(Python) and `ops/evidence-snapshot-worker/src/payment-context.mjs` (Workers).
It stays for local tests and emits a `DeprecationWarning` on every call. It
decides the shared vectors in `tests/fixtures/x402-payment-context.v1.json`, a
pinned copy of szl-trust's `tests/vectors/x402-payment-context.v1.json`, the
same way the canonical validators do. The request-URL vectors are skipped
because this API has no request-URL binding.

Local tests validate Ed25519 `PAYMENT-CONTEXT` tokens against injected keys.
The caller must pass the route's `scheme` and `expected_amount`. An `exact`
context must sign exactly that amount and an `upto` maximum must not exceed
it, so a context signed under a cheaper rule is rejected (`AMOUNT_MISMATCH`,
`ABOVE_CONFIGURED_MAXIMUM`, or `SCHEME` for the other scheme). `nbf`, `exp`
and a future `iat` get a 5-second leeway by default and at most 30 seconds.
Token-supplied key material (`jku`, `jwk`, `x5u`, `x5c`) and `crit` or `b64`
headers are rejected.

`exact` responses do not set `PAYMENT-SETTLEMENT`. `upto` may set that header
only for a successful status and an atomic amount within the authorized maximum.
Origin code does not create `PAYMENT-RESPONSE`.

Cloudflare's documented claims (`iat`, `nbf`, `exp`, `aud`, `scheme`, `amount`)
define no `jti` or nonce. Replay protection is not implemented here, and
idempotency is unresolved. Live use is not authorized: the Cloudflare account
was approved for the Monetization Gateway closed beta on 2026-11-02 (szl-trust
activation record), but no science-evidence route, price or audience has been
approved, and this module is not wired to any origin.
