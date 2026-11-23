# Model-receipts provenance-chain schema extension (proposed)

**Status: PROPOSED DRAFT (PROPOSE_ONLY; authorizes nothing until owner/council ratification).**

Landed as an additive DRAFT document under the W26L landing-triage blocker queue conversion (row G3, landing_priority 12).

## Provenance and landing truth
- Queue record: mesh/2026-11-23/w26l-landing-triage/w26l-blocker-queue.json
- Draft source (PROPOSE_ONLY): mesh/2026-11-23/w26i-g-series-drafts/w26i-g-series-drafts.json
- Blocker clearance: SIGNATURE_MINT cleared 2026-11-23: owner signature mint landed (W26C LEG A complete + W28X corrected-head verified commits; key id 1356467, fp SHA256:/w0Rx9...; going-forward SSH signing live on the owner device)
- Fresh Kimi GO at landing: nonce W26M-G3-145148 (receipt published in wave-logs mesh/2026-11-23/w26m-queue-conversion/)
- Landed 2026-11-23T14:51:50Z. Landed by delegated estate automation under the owner standing green-light directive; NOT independent human review.
- Target adjudication: target listed as model-receipts provenance-chain; landed in governed-receipt-spec (the open format repo for governed AI inference receipts), disclosed adjudication; sibling homes possible (szl-receipt, szl-warehouse matrix class) and owner may redirect.

## Source citation
W26I G3 draft; szl-model-inference-lab serves Khipu-1.5B GGUF with unsigned execution provenance, honestly disclosed

## Proposed change
provenance-chain fields, signature stays null until mint, unsigned displays fail-closed

## Proposed schema extension (additive)
- extend model-receipts with provenance-chain fields:
  - model_sha256
  - quant_format
  - runtime_version
  - input_canary_digest
  - evidence_links
- signature semantics: drafted 2026-11-22 when the owner signature mint was pending; the mint landed 2026-11-23 (W26C LEG A) so going-forward executions may carry real signatures
- unsigned status displays FAIL CLOSED on any receipt lacking a signature
- no signature is claimed, simulated, or fabricated

## Finding
- szl-model-inference-lab serves Khipu-1.5B GGUF with unsigned execution provenance, honestly disclosed (W26I G3)

## Acceptance gate
no signature is claimed or simulated; unsigned receipts display fail-closed

## Rollback
doc removal only

## Baseline
governed-receipt-spec baseline unchanged; this proposal does not modify it.
