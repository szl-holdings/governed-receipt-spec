#!/usr/bin/env python3
"""Replay the governed-receipts-bench conformance corpus against verify.py.

Every row of the bench manifest (``bench.jsonl``) names one fixture file and
the outcome the verifier must produce for it:

* ``expected_result`` -- ``PASS`` or ``FAIL`` for the default invocation
  ``python verify.py <fixture>`` (no ``--verify-key``);
* ``expected_reason`` -- optional, FAIL rows only: a token (e.g. ``UNBOUND``)
  that must appear on a FAIL line of the verifier output, so a fixture that
  fails for a different reason is still reported as a mismatch.

The script runs the verifier CLI once per fixture, exactly as a user would,
and exits non-zero on any mismatch or on a malformed manifest (a path outside
``valid/``/``invalid/``, a ``valid/`` row not expecting PASS, an
``invalid/`` row not expecting FAIL, a fixture file the manifest does not
list, ...).

Fixtures come from one of:

* ``--revision SHA`` -- the public Hugging Face dataset at an immutable commit,
  fetched over plain HTTPS (standard library only). Each downloaded file is
  checked against the object id the Hub tree API reports for that commit.
* ``--bench-dir DIR`` -- a local directory with the same layout.

Standard library only; the verifier itself needs ``requirements.txt``.
"""

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import urllib.parse
import urllib.request

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_REPO = "SZLHOLDINGS/governed-receipts-bench"
DEFAULT_VERIFIER = os.path.join(REPO_ROOT, "verify.py")
HUB = "https://huggingface.co"
MANIFEST = "bench.jsonl"

COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
REPO_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*/[A-Za-z0-9][A-Za-z0-9._-]*$")
FIXTURE_RE = re.compile(r"^(valid|invalid)/[A-Za-z0-9][A-Za-z0-9._-]*\.json$")
CATEGORY_RESULT = {"valid": "PASS", "invalid": "FAIL"}


class BenchError(Exception):
    """The bench could not be fetched or its manifest is malformed."""


# --------------------------------------------------------------------------- #
# Fetching a pinned Hub revision                                              #
# --------------------------------------------------------------------------- #
def _http_get(url, timeout=60):
    request = urllib.request.Request(
        url, headers={"User-Agent": "governed-receipt-spec-bench-replay"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read(), response.headers


def _next_link(headers):
    for part in (headers.get("Link") or "").split(","):
        match = re.match(r'\s*<([^>]+)>\s*;\s*rel="next"', part)
        if match:
            return match.group(1)
    return None


def _hub_tree(repo, revision):
    url = "%s/api/datasets/%s/tree/%s?recursive=true" % (HUB, repo, revision)
    entries = []
    while url:
        body, headers = _http_get(url)
        entries.extend(json.loads(body.decode("utf-8")))
        url = _next_link(headers)
    return {e["path"]: e for e in entries if e.get("type") == "file"}


def _matches_hub_oid(data, entry):
    lfs = entry.get("lfs")
    if isinstance(lfs, dict) and lfs.get("oid"):
        return hashlib.sha256(data).hexdigest() == lfs["oid"]
    git_blob = hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()
    return git_blob == entry.get("oid")


def fetch_revision(repo, revision, dest):
    """Download the manifest and every fixture of ``repo`` at ``revision``."""
    if not REPO_RE.match(repo):
        raise BenchError("invalid dataset repo id: %r" % repo)
    if not COMMIT_RE.match(revision):
        raise BenchError(
            "--revision must be a full 40-hex dataset commit sha (branches and "
            "tags move); got %r" % revision)
    tree = _hub_tree(repo, revision)
    wanted = [MANIFEST] + sorted(p for p in tree if FIXTURE_RE.match(p))
    if MANIFEST not in tree:
        raise BenchError("%s not found in %s@%s" % (MANIFEST, repo, revision))
    for path in wanted:
        url = "%s/datasets/%s/resolve/%s/%s" % (
            HUB, repo, revision, urllib.parse.quote(path))
        data, _ = _http_get(url)
        if not _matches_hub_oid(data, tree[path]):
            raise BenchError("downloaded bytes of %s do not match the Hub "
                             "object id at %s" % (path, revision))
        target = os.path.join(dest, *path.split("/"))
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with open(target, "wb") as fh:
            fh.write(data)
    # Directory entries outside valid/ and invalid/ are not fixtures; any
    # other *.json there would make the manifest/coverage check below fail.
    stray = sorted(p for p in tree
                   if p.endswith(".json") and p.split("/")[0] in CATEGORY_RESULT
                   and not FIXTURE_RE.match(p))
    if stray:
        raise BenchError("fixture paths with unsupported names: %s"
                         % ", ".join(stray))


# --------------------------------------------------------------------------- #
# Manifest                                                                    #
# --------------------------------------------------------------------------- #
def list_fixture_files(bench_dir):
    found = []
    for category in sorted(CATEGORY_RESULT):
        root = os.path.join(bench_dir, category)
        if not os.path.isdir(root):
            continue
        for dirpath, _, filenames in os.walk(root):
            for name in filenames:
                if name.endswith(".json"):
                    rel = os.path.relpath(os.path.join(dirpath, name), bench_dir)
                    found.append(rel.replace(os.sep, "/"))
    return sorted(found)


def load_manifest(bench_dir):
    """Return validated manifest rows; raise BenchError listing every problem."""
    path = os.path.join(bench_dir, MANIFEST)
    try:
        with open(path, "r", encoding="utf-8") as fh:
            raw_lines = fh.read().splitlines()
    except OSError as exc:
        raise BenchError("cannot read %s: %s" % (MANIFEST, exc))

    rows, problems, seen = [], [], set()
    for number, line in enumerate(raw_lines, 1):
        if not line.strip():
            continue
        where = "%s line %d" % (MANIFEST, number)
        try:
            row = json.loads(line)
        except ValueError as exc:
            problems.append("%s: not JSON (%s)" % (where, exc))
            continue
        if not isinstance(row, dict):
            problems.append("%s: not a JSON object" % where)
            continue
        fixture = row.get("file")
        expected = row.get("expected_result")
        reason = row.get("expected_reason")
        if not isinstance(fixture, str) or not FIXTURE_RE.match(fixture):
            problems.append("%s: file %r is not valid/<name>.json or "
                            "invalid/<name>.json" % (where, fixture))
            continue
        category = fixture.split("/", 1)[0]
        if fixture in seen:
            problems.append("%s: duplicate row for %s" % (where, fixture))
        seen.add(fixture)
        if row.get("category") != category:
            problems.append("%s: category %r does not match directory %r"
                            % (where, row.get("category"), category))
        if expected not in ("PASS", "FAIL"):
            problems.append("%s: expected_result %r is not PASS/FAIL"
                            % (where, expected))
        elif expected != CATEGORY_RESULT[category]:
            problems.append("%s: %s/ fixture %s declares %s; %s/ fixtures "
                            "must expect %s" % (where, category, fixture,
                                                expected, category,
                                                CATEGORY_RESULT[category]))
        if reason is not None and (
                not isinstance(reason, str) or not reason.strip()
                or expected != "FAIL"):
            problems.append("%s: expected_reason must be a non-empty string "
                            "and only accompany expected_result FAIL" % where)
        if not os.path.isfile(os.path.join(bench_dir, *fixture.split("/"))):
            problems.append("%s: fixture %s is missing" % (where, fixture))
        rows.append(row)

    unlisted = sorted(set(list_fixture_files(bench_dir)) - seen)
    for fixture in unlisted:
        problems.append("fixture %s is not listed in %s" % (fixture, MANIFEST))
    if not rows and not problems:
        problems.append("%s has no rows" % MANIFEST)
    if problems:
        raise BenchError("\n".join(problems))
    return rows


# --------------------------------------------------------------------------- #
# Replay                                                                      #
# --------------------------------------------------------------------------- #
def run_verifier(verifier, fixture_path, timeout=120):
    """Run ``python verify.py <fixture>``; return (outcome, output_lines)."""
    env = dict(os.environ, PYTHONIOENCODING="utf-8")
    try:
        proc = subprocess.run(
            [sys.executable, verifier, fixture_path],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            timeout=timeout, env=env, check=False)
    except subprocess.TimeoutExpired:
        return "ERROR", ["verifier timed out after %ss" % timeout]
    lines = proc.stdout.decode("utf-8", errors="replace").splitlines()
    overall = [ln.strip() for ln in lines if ln.strip().startswith("OVERALL:")]
    if proc.returncode == 0 and overall == ["OVERALL: PASS"]:
        return "PASS", lines
    if proc.returncode == 1 and overall == ["OVERALL: FAIL"]:
        return "FAIL", lines
    return "ERROR", lines + ["(exit code %d)" % proc.returncode]


def _fail_lines(lines):
    return [ln.strip() for ln in lines
            if "FAIL" in ln and not ln.strip().startswith(("RESULT:", "OVERALL:"))]


def replay(bench_dir, verifier, out=sys.stdout):
    """Replay every manifest row; return the number of mismatching rows."""
    rows = load_manifest(bench_dir)
    mismatches = 0
    for row in rows:
        fixture = row["file"]
        expected = row["expected_result"]
        reason = row.get("expected_reason")
        observed, lines = run_verifier(
            verifier, os.path.join(bench_dir, *fixture.split("/")))
        fails = _fail_lines(lines)
        ok = observed == expected
        if ok and reason is not None:
            ok = any(reason in ln for ln in fails)
        want = expected + (" (%s)" % reason if reason else "")
        out.write("%-8s %-40s expected %-16s observed %s\n" % (
            "MATCH" if ok else "MISMATCH", fixture, want, observed))
        if not ok:
            mismatches += 1
            for ln in (fails if observed == "FAIL" else lines)[:12]:
                out.write("         | %s\n" % ln)
    out.write("bench replay: %d/%d fixtures match\n"
              % (len(rows) - mismatches, len(rows)))
    return mismatches


def file_sha256(path):
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def main(argv=None, out=sys.stdout):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--revision", metavar="SHA",
                        help="dataset commit sha to fetch from the Hub")
    source.add_argument("--bench-dir", metavar="DIR",
                        help="local bench directory (bench.jsonl, valid/, invalid/)")
    parser.add_argument("--repo", default=DEFAULT_REPO,
                        help="Hub dataset id (default: %(default)s)")
    parser.add_argument("--verifier", default=DEFAULT_VERIFIER,
                        help="verify.py to replay (default: this repo's)")
    args = parser.parse_args(argv)

    verifier = os.path.abspath(args.verifier)
    if not os.path.isfile(verifier):
        out.write("ERROR: verifier not found: %s\n" % verifier)
        return 2
    out.write("verifier: %s (sha256 %s)\n" % (verifier, file_sha256(verifier)))
    try:
        if args.bench_dir:
            out.write("bench:    %s\n" % os.path.abspath(args.bench_dir))
            mismatches = replay(args.bench_dir, verifier, out)
        else:
            out.write("bench:    %s/datasets/%s @ %s\n"
                      % (HUB, args.repo, args.revision))
            with tempfile.TemporaryDirectory() as tmp:
                fetch_revision(args.repo, args.revision, tmp)
                mismatches = replay(tmp, verifier, out)
    except (BenchError, OSError, ValueError) as exc:
        out.write("ERROR: %s\n" % exc)
        return 2
    return 1 if mismatches else 0


if __name__ == "__main__":
    raise SystemExit(main())
