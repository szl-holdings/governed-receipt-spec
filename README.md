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

Without `--verify-key` the signature check is reported as `SKIP`, including unsigned
receipts. Successful file and overall results say `PASS (integrity-only; signatures
not authenticated)`: only the applicable structure, content-hash, binding, schema
and chain checks passed. The Python `check_signatures` API returns `None` for SKIP,
`True` for verified signatures, and `False` for failure.

With `--verify-key`, every record must contain a signed envelope with at least one
signature, and every signature must verify against the supplied key. Missing or
empty signatures fail, including in mixed signed/unsigned files. A successful
result means signatures verified with that key; signer trust and authorization
are not assessed. Any failed check produces a non-zero exit status.

> Honesty note: the verifier does **not** re-derive the runtime's internal `digest` serialization (that is internal to the emitting runtime). It verifies the relations an outside party can independently reproduce — the DSSE PAE content hash, the payload-bytes hash, the `prev ↔ digest` chain, and (with a public key) the envelope signature. The same signatures also verify upstream with `cosign verify-blob --key cosign.pub`; the public key is linked from each receipt's `verify_key_url` and vendored for offline use at `tests/fixtures/cosign.pub`.

**Browser consumer status:** the former `SZLHOLDINGS/governed-receipt-verifier` standalone Space was retired and its files preserved in the [Command Centre archive](https://huggingface.co/spaces/betterwithage/szl-command-centre/tree/2b951ce7e1ed5c5f78e97fae8c087bd49c16d625/archive/governed-receipt-verifier), as recorded by the [immutable consolidation receipt](https://huggingface.co/spaces/betterwithage/szl-command-centre/blob/2b951ce7e1ed5c5f78e97fae8c087bd49c16d625/HF_SPACE_CONSOLIDATION_FINAL_RECEIPT.json). The archived browser entrypoint loads a separate `verify.js`; it does not run this `verify.py` or `governed_action.py`. Archive availability is not a deployed-source binding, consumer-conformance result, or functional receipt-verification witness. Use the offline commands above for this repository's verifier.

The stdlib-only [`governed_action.py`](governed_action.py) separately validates the proposed [GovernedAction predicate profile](docs/ITE-9-governed-action-predicate-proposal.md). Its `PASS` establishes structural/profile conformance, not signature authenticity, token authorization, artifact-byte correspondence, or deployment readiness. No automatic integration of that validator into the archived browser consumer or the product websites is claimed.

For portable **synthetic GovernedAction/v1** malformed-input tests, run `python scripts/replay_governed_conformance.py`. The [raw-JSON corpus and adapter-result contract](conformance/README.md) use a fixed clock, explicit validator mode, typed parse/validation outcomes and exact byte/hash bindings. The offline comparator rejects partial or ambiguous adapter reports; comparison alone does not prove an adapter executed or a consumer deployed the validator. This is separate from the real receipt/chain benchmark below.

For replayable conformance testing, use **[`SZLHOLDINGS/governed-receipts-bench`](https://huggingface.co/datasets/SZLHOLDINGS/governed-receipts-bench)** — real receipts (must PASS) plus labeled negatives (must FAIL), each with a declared expected outcome for a pinned verifier revision. `python scripts/replay_bench.py --revision <dataset-commit>` replays it, and the `bench-replay` workflow does so on every push and PR.

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

The policy-gate regression tests also require Bash and ripgrep (`rg`) on PATH.

```bash
python -m unittest discover -s tests -v
```

Valid examples must pass; tampered fixtures ([`tests/fixtures/`](tests/fixtures)) must fail — a flipped payload byte breaks the content hash, and a rewritten `prev` breaks the chain.

Replay the benchmark corpus against this `verify.py` (standard library plus `requirements.txt`; fetches the dataset at an immutable commit over HTTPS, or use `--bench-dir` for a local copy):

```bash
python scripts/replay_bench.py --revision <governed-receipts-bench commit sha>
```

It exits non-zero if any fixture's outcome differs from `bench.jsonl`. CI pins the dataset commit in [`.github/workflows/bench-replay.yml`](.github/workflows/bench-replay.yml); a verifier change that alters an outcome needs a new bench revision and a bumped pin.

---

## The estate

- **Archived browser prototype:** [preserved governed-receipt-verifier files](https://huggingface.co/spaces/betterwithage/szl-command-centre/tree/2b951ce7e1ed5c5f78e97fae8c087bd49c16d625/archive/governed-receipt-verifier) — separate JavaScript consumer, not a live standalone Space or verified deployment of this repository's Python validators.
- **Benchmark corpus:** **[`SZLHOLDINGS/governed-receipts-bench`](https://huggingface.co/datasets/SZLHOLDINGS/governed-receipts-bench)** — real receipts (PASS) + labeled negatives (FAIL) for conformance testing, replayed in CI.
- Live console: **[a-11-oy.com](https://a-11-oy.com)** · a11oy console `szlholdings-a11oy.hf.space`
- Hugging Face org: **[SZLHOLDINGS](https://huggingface.co/SZLHOLDINGS)** — receipt datasets (`a11oy-verifiable-corpus`, `readiness-runs`, `szl-evidence`) and the **Governed Kernels** collection (`szl-lambda-gate`, `szl-blocked`, `governed-inference-meter`, …).
- GitHub org: **[szl-holdings](https://github.com/szl-holdings)**

## License

Apache-2.0 — see [`LICENSE`](LICENSE).
