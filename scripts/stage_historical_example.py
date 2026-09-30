"""Stage immutable historical payload code beside the current reproduction tooling.

This copies Git objects; it neither executes the historical verifier nor claims
that its old PASS labels describe current-verifier conformance.
"""

import argparse
import ast
import hashlib
import json
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = "examples/public-single-cell/"
PAYLOAD = ("verify.py", "schema/governed-receipt.schema.json", EXAMPLE + "run_example.py")
TOOLING = tuple(EXAMPLE + name for name in (
    "Dockerfile", "check_reproduction.py", "reproduction-profile.json",
    "requirements-linux-cp312.lock", "observed-run.json",
))


def git_blob(data):
    return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()


def stage(destination, root=ROOT):
    destination = Path(destination)
    if destination.exists() or destination.is_symlink():
        raise ValueError("choose a new staging directory; existing evidence is never overwritten")
    profile = json.loads((root / (EXAMPLE + "reproduction-profile.json")).read_text())
    revision = profile["historical_reproduction_commit"]
    if re.fullmatch(r"[0-9a-f]{40}", revision) is None:
        raise ValueError("historical source requires an immutable commit")
    files = {
        path: subprocess.check_output(
            ["git", "-C", str(root), "show", revision + ":" + path], timeout=15,
        ) for path in PAYLOAD
    }
    analysis = files[EXAMPLE + "run_example.py"]
    pins = [ast.literal_eval(node.value) for node in ast.parse(analysis).body
            if isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Name) and target.id == "VERIFIER_BLOB"
                    for target in node.targets)]
    if pins != [git_blob(files["verify.py"])]:
        raise ValueError("historical verifier does not match the unchanged analysis pin")
    if git_blob(analysis) != profile["historical_analysis_git_blob"]:
        raise ValueError("historical analysis does not match its reproduction profile")
    if (root / (EXAMPLE + "run_example.py")).read_bytes() != analysis:
        raise ValueError("current historical analysis differs from the pinned source")
    files.update({path: (root / path).read_bytes() for path in TOOLING})
    manifest = {
        "scope": "historical reproduction only; not current-verifier qualification",
        "historical_commit": revision,
        "files": {path: {"sha256": hashlib.sha256(data).hexdigest(),
                         "git_blob": git_blob(data),
                         "source": "historical commit" if path in PAYLOAD else "current tooling"}
                  for path, data in files.items()},
    }
    destination.mkdir(parents=True)
    for path, data in files.items():
        target = destination / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    (destination / "historical-source.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8",
    )
    return manifest


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    print(json.dumps(stage(parser.parse_args().output), indent=2))
