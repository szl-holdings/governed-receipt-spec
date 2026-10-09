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

## Payment context

Local tests validate Ed25519 `PAYMENT-CONTEXT` tokens against injected keys.
`exact` responses do not set `PAYMENT-SETTLEMENT`. `upto` may set that header
only for a successful status and an atomic amount within the authorized maximum.
Origin code does not create `PAYMENT-RESPONSE`. Live use is not authorized:
account monetization was observed as `pending`, idempotency is unresolved, and
no wallet, price, or audience has been approved.
