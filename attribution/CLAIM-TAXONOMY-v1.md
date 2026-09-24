# Attribution Claim Taxonomy v1

**Part of governed-receipt-spec.** For any AI-assisted change, the receipt or
commit message records three separable identity facts — never blurred:

| Claim | Marker | Meaning |
|---|---|---|
| `implementation_authorship` | `authored-by-agent: <name>` | which agent/account produced the bytes |
| `automated_review_event` | `reviewed-by-automation: <tool> (scope: <head, date, verdict>)` | which automated review ran and on what |
| `merge_authority` | `merged-by: <protection-rules or human-id>` | which authority admitted the change to main |

## The laundering rule

A recorded negative evidence event — "usage limit, not approval",
"quota-blocked", "no independent approval" — may never be upgraded into an
approval claim. The validator returns:

- `MEASURED` — all three markers present, or negative evidence honestly recorded
- `INCOMPLETE` — some facts present, others missing
- `UNSAFE` — a non-approval record contradicted by an approval claim
- `BLOCKED` — nothing claimable present

## Validator

`attribution.py` is importable: `assess(commit_message) -> dict`. Stdlib only;
deterministic; every verdict carries a `claim_digest`.

Scope honesty: this module asserts provenance only. It does not certify that
the change is correct, reviewed well, or secure. Doctrine v11. Apache-2.0.
