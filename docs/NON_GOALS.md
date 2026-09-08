# Non-Goals — What SZL Holdings Receipts Do Not Prove

A signed receipt is easy to over-read. This document states, in one place,
exactly what a `szl-receipt` / `governed-receipt-spec` record does NOT
establish, so that no downstream reader — internal or external — mistakes
tamper-evidence for correctness, completeness, or independence. This section
adopts the disclosure discipline of IETF draft-chueayen-attestation-receipts
(Section 1.3) and the Sello paper (arXiv:2606.04193, Section 6), applied to
this specification's own threat model.

## Non-goals

1. **Correctness.** A receipt proves that a specific input, model version,
   and parameter set produced a specific output at a specific time. It does
   not prove the output was accurate, safe, clinically valid, legally
   compliant, or fit for any downstream purpose. Correctness requires
   independent domain review; a receipt is evidence for that review, not a
   substitute for it.

2. **Completeness.** A receipt records what its schema captures. It does
   not prove that no relevant step, tool call, or human intervention
   occurred outside the recorded fields. Absence of a field in the receipt
   is not evidence of absence in reality — it may simply be unrecorded.

3. **Independence from self-attestation.** Current `szl-receipt` records
   are signed by the runtime that performed the action, not by a receiving
   third party. This is the same trust boundary as draft-chueayen's
   issuer-signed model, and it is weaker than a receiver-signed or
   witness-cosigned design (cf. Sello, arXiv:2606.04193, which has the
   *called service* sign rather than the caller). A compromised or
   dishonest runtime can, in principle, sign a false receipt. Tamper
   evidence protects against *post-hoc* alteration of an existing receipt;
   it does not protect against a receipt that was false at the moment of
   signing.

4. **Novelty or uniqueness of method (Λ).** Any claim referencing the Λ
   aggregator's uniqueness is CONJECTURE, not a proven theorem, per existing
   doctrine labeling. This document does not upgrade that status.

5. **Legal or regulatory sufficiency.** Alignment language referencing the
   EU AI Act Article 12 or NIST AI RMF describes a design intent, not a
   certification, attestation of conformity, or legal opinion. No receipt
   format alone satisfies a regulatory requirement without the surrounding
   institutional controls a regulator would separately evaluate.

6. **Suppression or selective disclosure resistance.** A receipt chain
   proves that recorded events were not altered after signing. It does not
   prove that no unfavorable event was simply never submitted for a
   receipt in the first place. Detecting *missing* receipts requires an
   external retrieval/audit guarantee, which is a separate, unsolved
   problem shared with every design in this space (cf. Sello §6,
   "Completeness and Retrieval").

## What a receipt does establish

- The exact model/version, input hash, parameters, and output hash bound
  together at a specific time.
- That the bound record has not been altered since signing (within the
  chain's hash-linkage).
- A machine-checkable, offline-verifiable link between a claim and the
  process that produced it — sufficient for a human reviewer to *begin*
  scrutiny, not to end it.
