"""Offline current-source qualification; never a rerun of the historical data analysis."""

import argparse
from datetime import datetime, timezone
import hashlib
from importlib.metadata import version
import json
from pathlib import Path
import platform
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import verify  # noqa: E402

HISTORICAL = "examples/public-single-cell/observed-run.json"
CHAIN = "examples/a11oy-khipu-chain.json"
PUBLIC_KEY = "tests/fixtures/cosign.pub"
SOURCES = (
    "verify.py", "governed_action.py", "schema/governed-receipt.schema.json",
    "scripts/qualify_current_verifier.py", HISTORICAL, CHAIN, PUBLIC_KEY,
    "examples/public-single-cell/run_example.py",
    "examples/public-single-cell/reproduction-profile.json",
    "tests/fixtures/tampered-payload.json", "tests/fixtures/broken-chain.json",
    "examples/lake-inference-receipt.json",
)


def qualify():
    schema = verify.load_schema(verify.DEFAULT_SCHEMA)
    key = (ROOT / PUBLIC_KEY).read_bytes()
    historical = json.loads((ROOT / HISTORICAL).read_text(encoding="utf-8"))["receipt"]
    cases = (
        ("historical-receipt-current-integrity", [historical], None, True, ["SKIP"]),
        ("historical-unsigned-rejected-with-key", [historical], key, False, ["FAIL"]),
        ("public-chain-integrity", verify.load_records(ROOT / CHAIN), None, True, ["SKIP"] * 5),
        ("public-chain-signatures", verify.load_records(ROOT / CHAIN), key, True, ["PASS"] * 5),
        ("tampered-payload", verify.load_records(ROOT / "tests/fixtures/tampered-payload.json"), None, False, None),
        ("broken-chain", verify.load_records(ROOT / "tests/fixtures/broken-chain.json"), None, False, None),
        ("unbound-legacy-claims", verify.load_records(ROOT / "examples/lake-inference-receipt.json"), None, False, None),
    )
    results = []
    for name, records, public_key, expected, expected_signatures in cases:
        ok, lines = verify.verify_records(records, schema, public_key)
        signatures = [line.split()[1] for line in lines if line.strip().startswith("sig:")]
        if ok is not expected or (expected_signatures is not None and signatures != expected_signatures):
            raise ValueError("current verifier qualification mismatch: " + name)
        results.append({"id": name, "verifier_ok": ok,
                        "mode": "supplied-public-key" if public_key is not None else "integrity-only",
                        "signature_states": signatures, "report": lines})
    return {
        "schema": "current-verifier-qualification/v1",
        "scope": "current verifier on retained public fixtures; no data-analysis rerun or signer-trust claim",
        "source_sha256": {path: hashlib.sha256((ROOT / path).read_bytes()).hexdigest() for path in SOURCES},
        "results": results,
    }


def check_retained(retained, current):
    for field in ("schema", "scope", "source_sha256", "results"):
        # JSON comparison preserves booleans rather than equating True with 1.
        if json.dumps(retained.get(field), sort_keys=True) != json.dumps(current[field], sort_keys=True):
            raise ValueError("retained qualification does not match current " + field)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    destination = parser.add_mutually_exclusive_group()
    destination.add_argument("--output", type=Path)
    destination.add_argument("--check", type=Path)
    args = parser.parse_args(argv)
    result = qualify()
    if args.check:
        check_retained(json.loads(args.check.read_text(encoding="utf-8")), result)
    result["execution"] = {
        "observed_at_utc": datetime.now(timezone.utc).isoformat(),
        "command": ["python", "scripts/qualify_current_verifier.py"] +
                   (["--output", args.output.as_posix()] if args.output else
                    ["--check", args.check.as_posix()] if args.check else []),
        "python": platform.python_version(), "platform": platform.system(),
        "packages": {name: version(name) for name in ("cryptography", "in-toto-attestation", "protobuf")},
        "historical_data_analysis_rerun": "NOT_RUN",
        "private_key_generation": "NOT_RUN",
    }
    text = json.dumps(result, indent=2) + "\n"
    if args.output:
        with args.output.open("x", encoding="utf-8", newline="\n") as output:
            output.write(text)
    print(text, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
