# Portable GovernedAction/v1 vectors

`governed-action-v1.json` is a versioned **synthetic structural/profile** corpus,
not a record of real governed actions or a deployment receipt. It is separate
from `article12.yaml` (a logging profile) and the existing receipt-chain benchmark
for `verify.py`. It preserves current validator semantics; it does not tighten
the predicate schema, change the benchmark pin, or implement cryptography.

Run the reference replay, offline and without third-party dependencies:

```sh
python scripts/replay_governed_conformance.py
```

The 42 cases include conformant predicates/statements, `INCOMPLETE` evidence,
malformed obligations and scalar `artifact_digests`, false completeness claims,
wrong scalar types, subject digests, clock boundaries, redaction, duplicate keys
in both orders (including escaped-name aliases), nonfinite/overflow numbers,
invalid Unicode and malformed JSON. The verification clock is fixed at
`2026-09-19T00:00:00Z`; replay does not depend on today's date.

Each case has a unique `id`, explicit `mode` (`predicate` or `statement`), raw
`input_json` string, and `expected` outcome:

```json
{"stage": "parse", "state": "FAIL"}
```

`stage=parse` means strict parsing rejected the input **before validation** and
requires `state=FAIL`. `stage=validate` means parsing succeeded and the selected
validator returned `PASS`, `INCOMPLETE`, or `FAIL`. A later validation failure
cannot satisfy a parser-rejection expectation. An unexpected validator exception
produces `stage=exception` in the reference report and makes the suite fail, as
does an unexpected parser exception; it
must never count as a successful negative test. Exception messages and receipt
payloads are not reflected into that report.

To test a separate implementation, run it against every raw input using the
corpus clock and explicit mode, then write **measured** results as:

```text
{
  "format": "GovernedActionAdapterResults/v1",
  "corpus_sha256": "<SHA-256 of the exact corpus file bytes>",
  "results": [
    {
      "id": "<case id>",
      "mode": "<case mode>",
      "input_sha256": "<SHA-256 of the case input_json UTF-8 bytes>",
      "stage": "<parse or validate>",
      "state": "<PASS, INCOMPLETE, or FAIL>"
    }
  ]
}
```

The placeholders above are not a valid report. Do not copy expected outcomes
into a report and call them measured. Compare a report without executing any
adapter code or using the network:

```sh
python scripts/replay_governed_conformance.py --adapter-results adapter-results.json
```

The comparator requires exact corpus byte identity and one result per case,
bound to its explicit mode and raw-input hash. It rejects duplicate, omitted,
unknown or extra cases/fields, invalid types, ambiguous/nonstandard JSON, wrong
hashes/modes and unsupported outcomes. Result order may differ. Corpus and
adapter files are bounded by the reference parser's limits (4 MiB, bounded work
and nesting); the corpus admits 1–500 unique cases. No clock/profile override
is accepted: these are bound by the exact corpus bytes and version.

The JSON report includes the corpus digest, fixed clock, current reference
`governed_action.py` byte digest, per-case outcomes and mismatches. That source
digest identifies bytes read by the reporter, not a signed implementation
identity or evidence that an external adapter executed them. Comparing an
adapter report is only comparing **reported assertions**. A forged matching
report will compare successfully; executed-adapter/source/artifact binding must
be established separately by the consumer's witnessed run and release evidence.

Exit codes: `0` = all declared vector outcomes match; `1` = one or more outcome
mismatches (including validator crashes); `2` = unreadable/invalid corpus or
adapter contract. Contract failures emit typed `INVALID_CONFORMANCE_CONTRACT`,
never a receipt `PASS`. All replay and admission regressions run in the existing
Python test gates; no CI gate is removed, skipped or relaxed.

## Limits

`PASS` is structural/profile conformance **on these vectors only**. It is not
action authorization (a structurally valid `DENY` action can pass), signature
authenticity, RFC 3161 verification, real artifact correspondence, proof of
computation, legal compliance, complete hostile-input coverage, runtime
readiness or deployment. Token presence and clock claims remain assertions.
Python-only hostile objects, aliases and cycles are covered separately by the
Python unit tests; they cannot be represented in this raw-JSON corpus.

The corpus does not integrate or publish this validator into Hugging Face,
`a-11-oy.com`, `a11oy.net`, or the retired browser prototype. No consumer parity
or deployment claim is made until a bound, witnessed consumer run exists.
