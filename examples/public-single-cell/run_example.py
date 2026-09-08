#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Reproducible GEO file-summary example. No biological inference or new scoring method.

The existing repository verifier checks the unsigned receipt. This adapter adds
checks of the actual input/output files; a digest is not a trusted signature.
Run from the repository root with its pinned requirements installed.
"""
from __future__ import annotations

import argparse
import base64
import copy
import csv
import gzip
import hashlib
import importlib.util
import json
import math
import platform
import re
import statistics
import sys
import urllib.request
from importlib.metadata import version
from pathlib import Path
from typing import Any, Iterable

ROOT = Path(__file__).resolve().parents[2]
URL = "https://ftp.ncbi.nlm.nih.gov/geo/series/GSE85nnn/GSE85241/suppl/GSE85241_cellsystems_dataset_4donors_updated.csv.gz"
INPUT_SHA256 = "2f253ffb1f6d54f6bb259e862195f5c20ea3f13e00471b9864ff92773658f513"
INPUT_BYTES = 17005498
VERIFIER_BLOB = "84cd6b67a6a9052dc6ec6a334c810b6b4752bc8f"
PTYPE = "application/vnd.in-toto+json"
PREDICATE = "https://github.com/szl-holdings/governed-receipt-spec/examples/public-single-cell/v1"
MAX_EXPANDED = 512 * 1024 * 1024
PARAMETERS = {
    "operation": "per-column positive-feature counts, grouped by source donor label",
    "positive_threshold": 0,
    "exclude_from_endogenous_counts": "feature identifiers starting with ERCC-",
    "cell_filter": "none; all submitted columns retained",
    "normalization": "none; submitted processed values used without rounding",
    "gene_signature_scoring": False,
    "differential_expression": False,
    "statistical_hypothesis_tests": False,
    "clinical_or_causal_validation": False,
}


class ExampleError(ValueError):
    """A required input, calculation or recorded hash did not agree."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ExampleError(message)


def canonical(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=False, allow_nan=False) + "\n").encode("utf-8")


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def file_sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_verifier():
    path = ROOT / "verify.py"
    data = path.read_bytes()
    blob = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
    require(blob == VERIFIER_BLOB, "review the changed verifier before changing its pin")
    spec = importlib.util.spec_from_file_location("public_example_existing_verifier", path)
    require(spec is not None and spec.loader is not None, "verifier import unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def download(path: Path) -> None:
    # One fixed public scientific file. No secrets, auth, mirrors or arbitrary URLs.
    request = urllib.request.Request(URL, headers={"User-Agent": "SZL-Public-Single-Cell-Example/1"})
    with urllib.request.urlopen(request, timeout=60) as response:
        require(response.url == URL, "unexpected download redirect")
        with path.open("xb") as stream:
            size = 0
            while chunk := response.read(1024 * 1024):
                size += len(chunk)
                require(size <= INPUT_BYTES, "input exceeds reviewed size")
                stream.write(chunk)
    check_input(path)


def check_input(path: Path) -> None:
    require(path.stat().st_size == INPUT_BYTES, "input byte count mismatch")
    require(file_sha(path) == INPUT_SHA256, "input SHA-256 mismatch")


def bounded_lines(stream) -> Iterable[str]:
    size = 0
    while line := stream.readline(512 * 1024 + 1):
        require(len(line) <= 512 * 1024, "input line budget exceeded")
        size += len(line)
        require(size <= MAX_EXPANDED, "expanded file budget exceeded")
        yield line


def summarize_rows(rows: Iterable[list[str]]) -> dict[str, Any]:
    rows = iter(rows)
    cells = next(rows, [])
    require(0 < len(cells) <= 10000 and len(set(cells)) == len(cells), "invalid cell header")
    labels = []
    for cell in cells:
        match = re.fullmatch(r"(D[0-9]+)-[1-9][0-9]*_[1-9][0-9]*", cell)
        require(match is not None, "unrecognized source donor/plate label")
        labels.append(match.group(1))
    endogenous = [0] * len(cells)
    spikes = [0] * len(cells)
    seen: set[str] = set()
    spike_rows = non_integer = positive_entries = 0
    for row in rows:
        require(len(row) == len(cells) + 1, "matrix row width mismatch")
        feature = row[0]
        require(bool(feature) and feature not in seen, "empty or duplicate feature identifier")
        seen.add(feature)
        require(len(seen) <= 100000, "feature budget exceeded")
        is_spike = feature.startswith("ERCC-")
        spike_rows += int(is_spike)
        target = spikes if is_spike else endogenous
        for index, token in enumerate(row[1:]):
            value = float(token)
            require(math.isfinite(value) and value >= 0, "nonfinite or negative expression value")
            non_integer += int(not value.is_integer())
            if value > 0:
                positive_entries += 1
                target[index] += 1
    require(bool(seen), "empty expression matrix")
    groups = []
    for donor in sorted(set(labels)):
        indices = [i for i, label in enumerate(labels) if label == donor]
        values = [endogenous[i] for i in indices]
        groups.append({"source_donor_label": donor, "cell_columns": len(indices),
                       "endogenous_detected_features_min": min(values),
                       "endogenous_detected_features_median": statistics.median(values),
                       "endogenous_detected_features_max": max(values),
                       "columns_without_positive_endogenous_features": sum(x == 0 for x in values)})
    return {"schema": "public-single-cell-file-summary/v1", "accession": "GSE85241",
            "input_sha256": INPUT_SHA256, "cell_columns": len(cells),
            "feature_rows": len(seen), "endogenous_feature_rows": len(seen) - spike_rows,
            "ercc_feature_rows": spike_rows, "non_integer_entries": non_integer,
            "positive_entries": positive_entries, "source_donor_label_count": len(groups),
            "groups": groups, "parameters": PARAMETERS,
            "interpretation": "Descriptive file summary only; source donor labels are not independently authenticated donor identities."}


def summarize(path: Path) -> dict[str, Any]:
    check_input(path)
    with gzip.open(path, "rt", encoding="utf-8", newline="") as stream:
        return summarize_rows(csv.reader(bounded_lines(stream), delimiter="\t"))


def envelope_for(statement: dict[str, Any], verifier) -> dict[str, Any]:
    body = canonical(statement)
    return {"payloadType": PTYPE, "payload": base64.b64encode(body).decode("ascii"),
            "signatures": [], "signed": False,
            "_pae_sha256": sha(verifier.dsse_pae(PTYPE, body))}


def make_receipt(summary_bytes: bytes, verifier) -> dict[str, Any]:
    statement = {"_type": "https://in-toto.io/Statement/v1",
                 "subject": [{"name": "summary.json", "digest": {"sha256": sha(summary_bytes)}}],
                 "predicateType": PREDICATE,
                 "predicate": {"input": {"url": URL, "sha256": INPUT_SHA256, "bytes": INPUT_BYTES},
                               "parameters": PARAMETERS,
                               "analysis_sha256": file_sha(Path(__file__)),
                               "verifier_git_blob": VERIFIER_BLOB,
                               "claim": "Recorded file integrity and deterministic summary only; not biological validity or trusted authorship."}}
    return envelope_for(statement, verifier)


def verify_bundle(data: Path, summary: Path, receipt: dict[str, Any], verifier) -> list[str]:
    check_input(data)
    require(receipt.get("payloadType") == PTYPE and receipt.get("signed") is False
            and receipt.get("signatures") == [] and isinstance(receipt.get("_pae_sha256"), str),
            "expected an explicitly unsigned, hashed example receipt")
    schema = verifier.load_schema(str(ROOT / "schema/governed-receipt.schema.json"))
    ok, lines = verifier.verify_records([receipt], schema)
    require(ok, "existing receipt verifier rejected the receipt: " + " | ".join(lines))
    statement = json.loads(base64.b64decode(receipt["payload"], validate=True))
    require(statement.get("_type") == "https://in-toto.io/Statement/v1" and
            statement.get("predicateType") == PREDICATE, "unexpected statement type")
    require(statement.get("subject") == [{"name": "summary.json", "digest": {"sha256": file_sha(summary)}}],
            "output file does not match receipt subject")
    predicate = statement.get("predicate", {})
    require(predicate.get("input") == {"url": URL, "sha256": INPUT_SHA256, "bytes": INPUT_BYTES},
            "input metadata does not match reviewed source")
    require(predicate.get("parameters") == PARAMETERS, "analysis parameters changed")
    require(predicate.get("verifier_git_blob") == VERIFIER_BLOB and
            predicate.get("analysis_sha256") == file_sha(Path(__file__)), "source identity mismatch")
    return lines


def run(output: Path, input_path: Path | None = None) -> dict[str, Any]:
    require(not output.exists(), "choose a new output directory; existing evidence is never overwritten")
    output.mkdir(parents=True)
    verifier = load_verifier()
    data = input_path or output / "source.tsv.gz"
    if input_path is None:
        download(data)
    first, second = canonical(summarize(data)), canonical(summarize(data))
    require(first == second, "repeat calculation produced different summary bytes")
    summary_path = output / "summary.json"
    summary_path.write_bytes(first)
    receipt = make_receipt(first, verifier)
    (output / "receipt.json").write_bytes(canonical(receipt))
    lines = verify_bundle(data, summary_path, receipt, verifier)

    # Keep the recorded receipt fixed while deliberately changing its subject or payload.
    bad_receipt = copy.deepcopy(receipt)
    changed = json.loads(base64.b64decode(bad_receipt["payload"]))
    changed["predicate"]["parameters"]["differential_expression"] = True
    bad_receipt["payload"] = base64.b64encode(canonical(changed)).decode()
    try:
        verify_bundle(data, summary_path, bad_receipt, verifier)
    except ExampleError:
        receipt_rejected = True
    else:
        receipt_rejected = False
    bad_summary = json.loads(first)
    bad_summary["cell_columns"] += 1
    summary_path.write_bytes(canonical(bad_summary))
    try:
        verify_bundle(data, summary_path, receipt, verifier)
    except ExampleError:
        output_rejected = True
    else:
        output_rejected = False
    finally:
        summary_path.write_bytes(first)
    require(receipt_rejected and output_rejected, "negative control unexpectedly accepted")
    verify_bundle(data, summary_path, receipt, verifier)
    report = {"schema": "public-single-cell-verification/v1", "status": "PASS",
              "scope": "file integrity and repeatability, not biological validation",
              "input_sha256": file_sha(data), "summary_sha256": sha(first),
              "receipt_sha256": file_sha(output / "receipt.json"),
              "analysis_sha256": file_sha(Path(__file__)), "verifier_git_blob": VERIFIER_BLOB,
              "checks": {"intact_bundle": True, "repeat_summary_byte_identical": True,
                         "changed_receipt_payload_rejected": receipt_rejected,
                         "changed_output_file_rejected": output_rejected},
              "signature_verified": False, "trusted_authorship_verified": False,
              "scoring_methods_benchmarked": [], "biological_claim_validated": False,
              "python": platform.python_version(),
              "packages": {name: version(name) for name in ("cryptography", "in-toto-attestation")},
              "existing_verifier_report": lines}
    (output / "verification.json").write_bytes(canonical(report))
    (output / "environment.txt").write_text(sys.version + "\n" + platform.platform() + "\n", encoding="utf-8")
    print(json.dumps({"summary": json.loads(first), "verification": report}, indent=2))
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--input", type=Path, help="already downloaded, exact pinned GEO gzip file")
    args = parser.parse_args()
    try:
        run(args.output, args.input)
    except (OSError, ValueError) as exc:
        print(json.dumps({"status": "FAIL", "error": str(exc)}), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
