<!-- PROPOSE-ONLY / DO-NOT-MERGE. Study document only. No code, config, or workflow change is proposed by this file. -->
# LEADERS-STUDY -- governed-receipt-spec (tranche 6, 2026-11-24)

> **PROPOSE-ONLY / DO-NOT-MERGE.** This is a per-repo-domain public-surface study card drafted from the round-2 leader pack.
> Nothing here is approved for implementation. Merge requires a separate governing review plus a fresh owner GO naming repo, PR, and pin.
> Authors: ouroboros CTO lane (Vibe dc rail), owner act-as-me, Kimi-governed per-lap.

## 0. Scope gate

Study-only. This PR adds exactly one documentation file (this file). It contains no code, no CI change, no dependency change, and no claim upgrade. All absorb candidates below are UNAPPROVED until a governing lap says otherwise.

## 1. Current state (measured evidence, 2026-11-24 qualification)

- Repo: szl-holdings/governed-receipt-spec, main tip at qualification 96655517184b280e28bbfbd2f3b9a908ed9173e7, 136 files, zero open PRs at scan time.
- README positioning: an open format for the governance decision receipt a governed AI runtime emits, plus an offline verifier built on pinned, maintained crypto libraries. Demo a11oy.net; verify-in-60s via clone + pip install -e . + pytest -q. Apache-2.0.
- Pinned dependencies per v11 doctrine 7.1: in-toto-attestation 0.9.3 and cryptography 50.0.1 (README, measured).
- docs/ holds CANONICALIZATION, LANDSCAPE, NON_GOALS (measured file-list), i.e. the repo already studies its own terrain honestly.
- Honest trust-tier table in README places the receipt tier explicitly below zkML proof tier and TEE hardware tier. A receipt is NOT a zero-knowledge proof.

## 2. Field leaders (public-surface study, round-2 leader pack)

| # | Leader | Public source | Leads at |
|---|---|---|---|
| L1 | IETF RATS Attested Inference Receipt (AIR), COSE/CWT profiles, drafts -00 to -02 | datatracker.ietf.org/doc/html/draft-tsyrulnikov-rats-attested-inference-receipt | IETF-tracked attested-inference receipt envelope with COSE/CWT binding |
| L2 | IETF Enforcement Attestation Receipts for AI Inference Decisions (draft-02) | ietf.org archive id draft-chueayen-attestation-receipts-02.html | Enforcement decisions expressed as signed receipts |
| L3 | in-toto Attestation / DSSE ecosystem | in-toto.io, DSSE spec, Sigstore adoption | Multi-project adoption of a stable signed-envelope standard; our verifier already pins in-toto-attestation |
| L4 | Raucle Provenance Receipt v1 | cloud.raucle.com/spec/provenance/v1/ | Product-spec provenance receipt surface. **UNVERIFIED** (behind a product page; depth not independently checked) -- watch only |

## 3. Honest gaps (this repo vs the leaders)

- Gap A: no IETF-tracked profile alignment. The spec is estate-shaped; leaders L1/L2 are standards-tracked drafts with named authors and revision history.
- Gap B: no published negative-conformance vector suite (mutated-receipt classes that MUST fail) versus L1's conformance-oriented draft culture.
- Gap C: adoption surface is estate-only; L3's leader posture is multi-adopter tooling, not a single-estate format.
- Honest non-gap: the deny-first verifier and the below-zkML trust-tier table are already more honest than most public receipt surfaces.

## 4. Absorb candidates A1-A4 (ALL UNAPPROVED)

- A1: Align the receipt envelope to an AIR-shaped COSE/CWT profile WITHOUT weakening the deny-first verifier. Applicability test: every field maps one-to-one and every unmapped field fails closed.
- A2: Add negative conformance vectors per defect class (echoes the Aqta round-1 moat). Applicability test: verifier rejects every mutated receipt class; suite runs offline in CI.
- A3: Publish a third-party conformance/adopters doc modeled on L3's multi-project posture. Applicability test: an outside party can verify a receipt with one command and two pinned deps (already true) and cite the spec externally.
- A4: Cite draft-chueayen-attestation-receipts in capability-ledger alignment docs (converged design: kill-switch-as-signed-entry). Applicability test: citation only, verifier semantics unchanged.

## 5. Open questions A5-A6 (governing gates)

- A5 (Kimi lap): does AIR-profile alignment risk breaking the estate-side receipt contract compatibility (existing chains/verifiers)? Fail-closed answer required before any A1 work.
- A6 (owner/Kimi): versioning story for citing IETF drafts that churn (-00 to -02 already). Does the estate freeze draft revisions in docs the way it pins library versions?

## 6. Non-goals

No implementation in this PR. No zkML or TEE claims. No new dependency. No merge without governing review + fresh owner GO naming repo, PR number, and tip pin.

## 7. Markers and receipts

LEADERS_STUDY_TRANCH6_CARD_1_OF_6 | PROPOSE_ONLY_DNM | qualification tip 96655517 | erf scan C:/SZL/edge-debug/sp9_census.txt | qualification receipt ft_h4_t6qual.json (2026-11-24T13:46:23Z) | leader pack round2-leader-pack.md (Kimi-assigned public-surface lane).
