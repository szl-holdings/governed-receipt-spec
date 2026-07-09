# governed-receipt-spec

**An open format for the *governance decision receipt* an AI runtime emits — plus a dependency-free offline verifier.**

Built and maintained by [SZL Holdings](https://a-11-oy.com). Apache-2.0.

A **governed inference receipt** is the small, replayable, hash-chained record that a governed AI runtime produces for one governed action (e.g. an inference): what it decided, the Λ governance-floor status, whether energy was actually measured, and a signed envelope that lets anyone re-check it offline.

This repo publishes that receipt as a documented, adoptable format so an outside party can verify SZL receipts (and model their own) **with one command and zero dependencies.**

---

## Where this sits — an honest trust tier

There is no single "trustworthy AI" primitive; there is a spectrum with real cost/guarantee trade-offs:

| Tier | Example tech | What it proves | Cost |
| --- | --- | --- | --- |
| **Proof tier** | zkML (e.g. `zkonduit/ezkl`) | Zero-knowledge proof that an output came from a specific model on a specific input | Very high (proof-gen, GPU-hours) |
| **Hardware tier** | TEE / confidential inference | Attested execution inside a trusted enclave | Medium–high; hardware-bound |
| **Receipt tier — *this repo*** | signed, hash-chained decision receipts | An honest, replayable audit record of *what the governed runtime decided* | Low; deployable today |

**A receipt is explicitly NOT a zero-knowledge proof and NOT a proof of computation.** It does not prove the model ran correctly or that an output is "true". It is a signed, tamper-evident record of a governance *decision* and its bound content hashes. That honesty is the point.

**The gap this fills:** the supply-chain world has standardised provenance (`sigstore/model-transparency`, SLSA, in-toto) and the guardrails world ships decision *models*, but there is no clean open standard for a **runtime governance decision receipt**. This is that format.

---

## What's in a receipt

The schema (`schema/governed-receipt.schema.json`, JSON Schema draft 2020-12) is grounded in the **real receipts** SZL already publishes — see [`examples/`](examples/). Core fields:

- **`decision`** — the verdict (`allow` / `deny` / `block` / `review` / `abstain`). `deny`/`block` express the deny-by-default *honest-blocked* posture ([`szl-blocked`](https://github.com/szl-holdings)).
- **`lambda`** *(optional)* — the Λ governance-floor status. SZL keeps the honest label **"Λ = Conjecture 1 — never green"**: the unconditional Λ-uniqueness conjecture is machine-checked *open* (see [`lutar-lean`](https://github.com/szl-holdings) / `szl-lambda-gate`), so a receipt must never report Λ as "proven".
- **`energy`** — `{ joules, label }`. **Joules are never fabricated:** with no live meter, `joules` is `null` and `label` is `UNAVAILABLE`, with an honest reason in `evidence`.
- **`ts`** — emission time (Unix seconds float, as in real receipts, or ISO-8601).
- **`payload_digest`** — SHA-256 of the underlying governed payload (the content itself is intentionally not embedded).
- **`prev` / `digest` / `seq`** — the hash chain. Each receipt's `prev` equals the previous receipt's `digest`; genesis uses 64 zeros at `seq` 0.
- **DSSE envelope** *(optional)* — `dsse` / `envelope`: a signed [DSSE](https://github.com/secure-systems-lab/dsse) envelope binding the payload via the DSSE PAE, with SZL honesty extensions (`_pae_sha256`, `honesty`, `verify_key_url`).
- **`otel`** *(optional)* — an OpenTelemetry span link (see `vsp-otel`).

Fields not present in today's real receipts (e.g. an inline numeric Λ score, `otel`) are defined as **optional** spec extensions — the schema reflects reality and never invents data.

---

## Verify in one command

Dependency-free — Python 3 standard library only, no network:

```bash
python verify.py examples/a11oy-khipu-chain.json
```

The verifier, for each receipt:

1. **validates** the decoded decision object against `schema/governed-receipt.schema.json`;
2. **recomputes the content hash** and checks it — `sha256(DSSE PAE) == _pae_sha256` for signed khipu/lake receipts, or `sha256(payload) == payloadSha256` for readiness receipts (this matches SZL's own documented `how_to_verify`);
3. **checks the prev-hash chain** across a receipt list (`prev == previous.digest`, contiguous `seq`, genesis is 64 zeros); and
4. **structurally checks the DSSE envelope**.

It prints a clear `PASS` / `FAIL` per receipt with reasons, and exits non-zero on any failure.

> Honesty note: the verifier does **not** re-derive the runtime's internal `digest` serialization (that is internal to the emitting runtime). It verifies the relations an outside party can independently reproduce — the DSSE PAE content hash, the payload-bytes hash, and the `prev ↔ digest` chain. Full signature verification of the DSSE `ECDSA-P256` signature is done upstream with `cosign verify-blob --key cosign.pub`; the public key is linked from each receipt's `verify_key_url`.

---

## Examples (real data)

Every file in [`examples/`](examples/) is drawn factually from public SZL datasets — nothing is fabricated:

| File | Source dataset | Shows |
| --- | --- | --- |
| `a11oy-khipu-chain.json` | `SZLHOLDINGS/a11oy-verifiable-corpus` (`receipts/`) | a 5-receipt signed hash chain (`seq` 0→4) |
| `lake-inference-receipt.json` | `SZLHOLDINGS/a11oy-verifiable-corpus` (`lake/`) | `decision` + measured-or-null `energy` in the clear |
| `readiness-audit-receipt.json` | `SZLHOLDINGS/readiness-runs` | unsigned envelope with `payloadSha256` |
| `daily-activity-receipt.json` | `SZLHOLDINGS/szl-evidence` | HMAC-stub daily activity receipt |

---

## Tests

```bash
python -m unittest discover -s tests -v
```

Valid examples must pass; tampered fixtures ([`tests/fixtures/`](tests/fixtures)) must fail — a flipped payload byte breaks the content hash, and a rewritten `prev` breaks the chain.

---

## The estate

- Live console: **[a-11-oy.com](https://a-11-oy.com)** · a11oy console `szlholdings-a11oy.hf.space`
- Hugging Face org: **[SZLHOLDINGS](https://huggingface.co/SZLHOLDINGS)** — receipt datasets (`a11oy-verifiable-corpus`, `readiness-runs`, `szl-evidence`) and the **Governed Kernels** collection (`szl-lambda-gate`, `szl-blocked`, `governed-inference-meter`, …).
- GitHub org: **[szl-holdings](https://github.com/szl-holdings)**

## License

Apache-2.0 — see [`LICENSE`](LICENSE).
