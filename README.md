# governed-receipt-spec
<!-- szl:header v1 -->
<!-- badges: add this repo's CI / release / status badges here -->
[![org: szl-holdings](https://img.shields.io/badge/org-szl--holdings-black)](https://github.com/szl-holdings)
[![doctrine](https://img.shields.io/badge/doctrine-control%20before%20action%20%C2%B7%20evidence%20after-blue)](https://a-11-oy.com)

**Control before action. Evidence after.**

Part of the [szl-holdings](https://github.com/szl-holdings) estate ·
Product: [a-11-oy.com](https://a-11-oy.com) ·
Proof: [a11oy.net](https://a11oy.net)
<!-- /szl:header -->

**An open format for the *governance decision receipt* an AI runtime emits — plus an offline verifier built on pinned, maintained crypto libraries (no hand-rolled DSSE/ECDSA).**

Built and maintained by [SZL Holdings](https://a-11-oy.com). Apache-2.0.

A **governed inference receipt** is the small, replayable, hash-chained record that a governed AI runtime produces for one governed action (e.g. an inference): what it decided, the Λ governance-floor status, whether energy was actually measured, and a signed envelope that lets anyone re-check it offline.

This repo publishes that receipt as a documented, adoptable format so an outside party can verify SZL receipts (and model their own) **with one command and two pinned dependencies** ([`in-toto-attestation` 0.9.3](https://pypi.org/project/in-toto-attestation/) and [`cryptography` 50.0.1](https://pypi.org/project/cryptography/), per the v11 doctrine §7.1).

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

Offline (no network). Two pinned maintained dependencies — no hand-rolled crypto:

```bash
pip install -r requirements.txt
python verify.py examples/a11oy-khipu-chain.json
```

The verifier, for each receipt:

1. **validates** the decoded decision object against `schema/governed-receipt.schema.json`;
2. **recomputes the content hash** and checks it — `sha256(DSSE PAE) == _pae_sha256` for signed khipu/lake receipts, or `sha256(payload) == payloadSha256` for readiness receipts (this matches SZL's own documented `how_to_verify`);
3. **checks the prev-hash chain** across a receipt list (`prev == previous.digest`, contiguous `seq`, genesis is 64 zeros);
4. **structurally checks the DSSE envelope**;
5. **validates in-toto Statement payloads** through the pinned `in-toto-attestation` 0.9.3 bindings (ITE-6 minimums); and
6. with `--verify-key cosign.pub`, **cryptographically verifies every envelope signature** — ECDSA P-256 SHA-256 over the DSSE PAE of the *decoded* payload bytes, via `cryptography` 50.0.1:

```bash
python verify.py --verify-key tests/fixtures/cosign.pub examples/a11oy-khipu-chain.json
```

Without `--verify-key` the signature check is reported as `SKIP` — never as a pass. It prints a clear `PASS` / `FAIL` per receipt with reasons, and exits non-zero on any failure.

> Honesty note: the verifier does **not** re-derive the runtime's internal `digest` serialization (that is internal to the emitting runtime). It verifies the relations an outside party can independently reproduce — the DSSE PAE content hash, the payload-bytes hash, the `prev ↔ digest` chain, and (with a public key) the envelope signature. The same signatures also verify upstream with `cosign verify-blob --key cosign.pub`; the public key is linked from each receipt's `verify_key_url` and vendored for offline use at `tests/fixtures/cosign.pub`.

**Prefer to click?** Paste any receipt into the live verifier Space — **[`SZLHOLDINGS/governed-receipt-verifier`](https://huggingface.co/spaces/SZLHOLDINGS/governed-receipt-verifier)** — which runs this exact `verify.py` in your browser (via Pyodide, no upload). Or run against the benchmark corpus **[`SZLHOLDINGS/governed-receipts-bench`](https://huggingface.co/datasets/SZLHOLDINGS/governed-receipts-bench)** — real receipts (must PASS) plus labeled tampers (must FAIL).

---

## Examples (real data)

Every file in [`examples/`](examples/) is drawn factually from public SZL datasets — nothing is fabricated:

| File | Source dataset | Shows |
| --- | --- | --- |
| `a11oy-khipu-chain.json` | `SZLHOLDINGS/a11oy-verifiable-corpus` (`receipts/`) | a 5-receipt signed hash chain (`seq` 0→4) |
| `lake-inference-receipt.json` | `SZLHOLDINGS/a11oy-verifiable-corpus` (`lake/`) | Legacy negative example: `decision` + `energy` exist only in the clear wrapper and therefore verify as `UNBOUND` / FAIL |
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

- **Live verifier Space:** **[`SZLHOLDINGS/governed-receipt-verifier`](https://huggingface.co/spaces/SZLHOLDINGS/governed-receipt-verifier)** — paste a receipt, verify it in your browser (runs this `verify.py` via Pyodide).
- **Benchmark corpus:** **[`SZLHOLDINGS/governed-receipts-bench`](https://huggingface.co/datasets/SZLHOLDINGS/governed-receipts-bench)** — real receipts (PASS) + labeled tampers (FAIL) for conformance testing.
- Live console: **[a-11-oy.com](https://a-11-oy.com)** · a11oy console `szlholdings-a11oy.hf.space`
- Hugging Face org: **[SZLHOLDINGS](https://huggingface.co/SZLHOLDINGS)** — receipt datasets (`a11oy-verifiable-corpus`, `readiness-runs`, `szl-evidence`) and the **Governed Kernels** collection (`szl-lambda-gate`, `szl-blocked`, `governed-inference-meter`, …).
- GitHub org: **[szl-holdings](https://github.com/szl-holdings)**

## License

Apache-2.0 — see [`LICENSE`](LICENSE).
