#!/usr/bin/env python3
"""Offline raw-JSON GovernedAction profile replay, not runtime/authenticity proof."""

import argparse
from datetime import datetime
import hashlib
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import governed_action as governed  # noqa: E402

CORPUS_FORMAT = "GovernedActionConformance/v1"
RESULT_FORMAT = "GovernedActionAdapterResults/v1"
DEFAULT_CORPUS = ROOT / "conformance/governed-action-v1.json"
LIMIT = governed.MAX_JSON_TEXT_BYTES
ID = re.compile(r"[a-z0-9][a-z0-9-]{0,127}")
HASH = re.compile(r"[0-9a-f]{64}")
CLOCK = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")


class ContractError(ValueError):
    """Invalid conformance metadata, not a receipt verification verdict."""


def fields(obj, names):
    if type(obj) is not dict or set(obj) != set(names):
        raise ContractError("object fields invalid")


def parse_contract(raw):
    if type(raw) is not bytes or len(raw) > LIMIT:
        raise ContractError("contract bytes invalid")
    try:
        return governed.parse_json_document(raw.decode("utf-8"))
    except (UnicodeError, governed.MalformedJSON):
        raise ContractError("contract JSON invalid") from None


def outcome(row):
    if type(row["stage"]) is not str or row["stage"] not in ("parse", "validate"):
        raise ContractError("outcome stage invalid")
    if type(row["state"]) is not str or row["state"] not in ("PASS", "INCOMPLETE", "FAIL"):
        raise ContractError("outcome state invalid")
    if row["stage"] == "parse" and row["state"] != "FAIL":
        raise ContractError("parser rejection cannot pass")


def load_corpus(raw):
    corpus = parse_contract(raw)
    fields(corpus, ("format", "synthetic", "verification_time", "cases"))
    if corpus["format"] != CORPUS_FORMAT or corpus["synthetic"] is not True:
        raise ContractError("unsupported corpus profile")
    clock = corpus["verification_time"]
    if type(clock) is not str or not CLOCK.fullmatch(clock):
        raise ContractError("fixed UTC clock required")
    try:
        datetime.fromisoformat(clock.replace("Z", "+00:00"))
    except ValueError:
        raise ContractError("invalid calendar clock") from None
    cases = corpus["cases"]
    if type(cases) is not list or not 1 <= len(cases) <= 500:
        raise ContractError("non-empty bounded case list required")
    seen = set()
    for case in cases:
        fields(case, ("id", "mode", "input_json", "expected"))
        name = case["id"]
        if type(name) is not str or not ID.fullmatch(name) or name in seen:
            raise ContractError("case identity invalid")
        seen.add(name)
        if type(case["mode"]) is not str or case["mode"] not in ("predicate", "statement"):
            raise ContractError("explicit validator mode required")
        if type(case["input_json"]) is not str:
            raise ContractError("raw input text required")
        fields(case["expected"], ("stage", "state"))
        outcome(case["expected"])
    return corpus


def identity(case):
    return {"id": case["id"], "mode": case["mode"],
            "input_sha256": hashlib.sha256(case["input_json"].encode("utf-8")).hexdigest()}


def reference_results(corpus):
    now = datetime.fromisoformat(corpus["verification_time"].replace("Z", "+00:00"))
    results = []
    for case in corpus["cases"]:
        row = identity(case)
        try:
            document = governed.parse_json_document(case["input_json"])
        except governed.MalformedJSON:
            row.update(stage="parse", state="FAIL")
        except Exception:
            # Internal parser faults are not successful malformed-input tests.
            row.update(stage="exception", state="FAIL")
        else:
            validator = governed.validate_statement if case["mode"] == "statement" else governed.validate_predicate
            try:
                verdict = validator(document, now=now)
                if type(verdict) is not governed.Verdict or verdict.state not in ("PASS", "INCOMPLETE", "FAIL"):
                    raise ContractError("invalid reference verdict")
                row.update(stage="validate", state=verdict.state)
            except Exception:
                # A crashing validator must not satisfy an expected receipt FAIL.
                # Never render the exception message or the untrusted payload.
                row.update(stage="exception", state="FAIL")
        results.append(row)
    return results


def adapter_results(raw, corpus, digest):
    document = parse_contract(raw)
    fields(document, ("format", "corpus_sha256", "results"))
    if document["format"] != RESULT_FORMAT or document["corpus_sha256"] != digest:
        raise ContractError("adapter corpus binding invalid")
    results = document["results"]
    if type(results) is not list or len(results) != len(corpus["cases"]):
        raise ContractError("adapter result coverage invalid")
    cases = {case["id"]: case for case in corpus["cases"]}
    by_id = {}
    for row in results:
        fields(row, ("id", "mode", "input_sha256", "stage", "state"))
        name = row["id"]
        if type(name) is not str or name not in cases or name in by_id:
            raise ContractError("adapter result identity invalid")
        if type(row["input_sha256"]) is not str or not HASH.fullmatch(row["input_sha256"]):
            raise ContractError("adapter raw-input binding invalid")
        if {key: row[key] for key in ("id", "mode", "input_sha256")} != identity(cases[name]):
            raise ContractError("adapter case binding invalid")
        outcome(row)
        by_id[name] = row
    return [by_id[case["id"]] for case in corpus["cases"]]


def evaluate(raw, reported=None):
    corpus = load_corpus(raw)
    digest = hashlib.sha256(raw).hexdigest()
    results = reference_results(corpus) if reported is None else adapter_results(reported, corpus, digest)
    mismatches = []
    for case, actual in zip(corpus["cases"], results):
        observed = {key: actual[key] for key in ("stage", "state")}
        if observed != case["expected"]:
            mismatches.append({"id": case["id"], "expected": case["expected"], "actual": observed})
    return {
        "format": "GovernedActionConformanceReport/v1",
        "state": "FAIL" if mismatches else "PASS",
        "mode": "reference-replay" if reported is None else "compare-reported-adapter-results",
        "corpus_sha256": digest, "verification_time": corpus["verification_time"],
        "reference_source_sha256": hashlib.sha256((ROOT / "governed_action.py").read_bytes()).hexdigest(),
        "results": results, "mismatches": mismatches,
        "boundary": "Synthetic structural/profile vectors only; reported adapter results are assertions. "
                    "No signature, token, artifact authenticity, executed-adapter, deployment or runtime proof.",
    }


def read_bounded(path):
    with path.open("rb") as stream:
        raw = stream.read(LIMIT + 1)
    if len(raw) > LIMIT:
        raise ContractError("file byte limit exceeded")
    return raw


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, default=DEFAULT_CORPUS)
    parser.add_argument("--adapter-results", type=Path, help="compare data only; never executes an adapter")
    args = parser.parse_args()
    try:
        raw = read_bounded(args.corpus)
        reported = read_bounded(args.adapter_results) if args.adapter_results is not None else None
        report = evaluate(raw, reported)
    except (OSError, ContractError):
        print(json.dumps({"state": "FAIL", "error": "INVALID_CONFORMANCE_CONTRACT"}))
        return 2
    print(json.dumps(report, sort_keys=True, indent=2, ensure_ascii=True))
    return 0 if report["state"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
