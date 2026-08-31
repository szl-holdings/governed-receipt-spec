# ITE-9 Predicate Proposal: `GovernedAction/v1`

**Status:** DRAFT — prepared for submission to in-toto/attestation per the
ITE-9 vetting process. Not yet submitted. This document must not be cited
as "accepted" or "under review" until the upstream PR link exists.

- **Predicate type URI:** `https://szl.dev/GovernedAction/v1`
- **Envelope:** in-toto Statement (ITE-6), `payloadType: application/vnd.in-toto+json`
- **Reference validator:** `governed_action.py` (stdlib-only, offline) and
  `verify.py` (DSSE/ECDSA layer) in this repository
- **Adversarial coverage:** `tests/adversarial/` (23 tests, all required to
  pass for any claim about this predicate to be made)

## 1. Use case

AI agents now take consequential actions: deploying patches, modifying
production configuration, sending external communications. The supply-chain
predicates record how an artifact was **built**. Guardrails frameworks
record what a model **said**. Neither records what a governed runtime
**decided to let an agent do** — the pre-execution policy evaluation, the
identified natural person who verified it, the side-effect classification,
and the evidence obligations that remain outstanding.

`GovernedAction/v1` is that record: one governed action, one receipt,
hash-chained to its neighbors, offline-verifiable after the vendor, the
outage, and the auditor.

## 2. Why existing predicates do not cover it

| Predicate | Records | Gap for runtime governance |
|---|---|---|
| Link | Build step materials/products | No authority evaluation, no principal identity class, no evidence obligations |
| SLSA Provenance | Build provenance | Post-hoc by definition; a governed action is gated *before* execution (`evaluated_before_execution: const true`) |
| Runtime Trace (ITE-6 ecosystem) | Execution observation | Observation is not authorization; no `REQUIRE_HUMAN_APPROVAL` semantics |

## 3. Fail-closed semantics (the actual contribution)

1. **Missing evidence ⇒ INCOMPLETE, never PASS.** `completeness` is derived
   from obligation state; asserting COMPLETE with unsatisfied obligations
   is a hard FAIL.
2. **Human-principal binding.** `principal.is_service_account` is
   `const: false` in the human-verification profile, and
   `auth_method: api_key` is rejected as a service-account spoof — the
   schema-level encoding of EU AI Act Art. 12(3)(d)-style requirements.
3. **Anti-backdating.** PASS requires `ntp_synced: true` and an RFC 3161
   timestamp token; a future timestamp relative to verification is FAIL.
4. **Redaction accountability.** Redacted receipts must carry salted-hash
   commitments so an auditor can detect deletion of exculpatory evidence.
5. **Four side-effect classes, never collapsed:**
   `READ_ONLY / REVERSIBLE / IRREVERSIBLE / EXTERNALLY_VISIBLE`. The latter
   two require recorded human approval when the outcome is ALLOW.

## 4. Bindings

A protobuf definition for Go/Python/Java binding generation accompanies the
upstream PR. The reference Python validator in this repo is deliberately
stdlib-only so a verifier can run in an air-gapped audit environment with
zero supply-chain exposure beyond CPython itself.

## 5. Adoption ask

We ask maintainers to review the fail-closed semantics, not the SZL
deployment. The predicate is useful only if runtimes we do not control can
emit it. One external organization emitting one conformant receipt from the
spec alone — with no help beyond documentation — is our acceptance test for
calling this a standard.
