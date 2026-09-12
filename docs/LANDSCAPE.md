# Receipt-Format Landscape — Honest Positioning

Comparison drafted from primary sources: Sello (arXiv:2606.04193), IETF
draft-chueayen-attestation-receipts, and public references to Attested
Intelligence's USPTO filing 19/433,835. This document exists so that SZL
Holdings' positioning claims stay grounded in what those designs actually
do, not in what would be convenient for them to do.

## Summary table

| Property | Sello (academic, receiver-signed) | draft-chueayen (IETF, issuer-signed) | Attested Intelligence (patented) | SZL `szl-receipt` (current) |
|---|---|---|---|---|
| Who signs the record | The **receiving service**, structurally independent of the calling agent | The **issuer** — same party whose decision is being recorded | Proprietary, patent-protected architecture | The runtime performing the action (self-attested) |
| Confidentiality of contents | HPKE-encrypted to a designated owner | Not specified | Not publicly disclosed | Not currently encrypted |
| Tamper evidence | Witness-cosigned Merkle transparency log | Signature only, no log commitment specified | Not publicly disclosed | Local hash-chain (Merkle-style), no external witness |
| Explicit non-goals stated | Yes — dedicated section on suppression, collusion, retrieval | Yes — explicit "not established by this format alone" box | Unknown | Yes — see `docs/NON_GOALS.md` |
| Legal/IP status | Open academic proposal | Open IETF draft | Patented (filed) | Open-source, Apache-2.0 |
| Maturity | Research prototype | Draft-stage IETF submission | Commercial/patented | Working implementation, pre-standardization |

## Where SZL is genuinely ahead

- **Shipping, not drafting.** Unlike Sello and draft-chueayen, `szl-receipt`
  and `governed-receipt-spec` are live, working code with an offline
  verifier today, not a paper proposal or an IETF draft awaiting adoption.
- **Formal-methods backing.** The Lean 4 formalization of the underlying
  decision kernel has no analogue in any of the three comparison designs —
  none of them ground their receipt semantics in a machine-checked proof
  system.
- **Open licensing.** Apache-2.0, versus a patented commercial design
  (Attested Intelligence) and two proposals with no committed license path
  yet.

## Where SZL is behind, stated plainly

- **Signing party.** Sello's central contribution — receiver-side signing —
  is the single most important design choice in this landscape, because it
  removes the self-attestation weakness. `szl-receipt` shares this weakness
  with draft-chueayen, not with Sello. See `hatun-mcp`
  `docs/COSIGNING_PROPOSAL.md` for the scoped remediation plan.
- **Witnessing / transparency log.** Sello's Merkle-witnessed log gives a
  tamper-evidence guarantee that survives even a compromised signer after
  the fact. SZL's local hash-chain does not yet have an external witness.
- **Confidentiality.** Sello's HPKE encryption-to-owner has no counterpart
  in the current SZL design; receipts are not currently encrypted at rest
  or in transit beyond signature integrity.

## Where SZL is not competing at all

- Attested Intelligence's patent scope is unknown publicly beyond the
  filing number; no comparison of mechanism is possible without the full
  patent text, and no claim of similarity or difference should be made
  until it is reviewed directly.

## Maintenance rule

This table must be re-verified against primary sources whenever any of the
four designs ships a material change. Positioning claims that drift from
the primary sources are doctrine violations, not marketing latitude.
