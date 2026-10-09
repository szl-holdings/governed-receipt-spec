# SPDX-License-Identifier: Apache-2.0
"""Fresh-process entry: print the semantic matrix summary."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from science_evidence.bundle import canonical, count_matrix


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) != 2:
        print(json.dumps({"status": "FAIL", "reason": "MISSING_METADATA"}), file=sys.stderr)
        return 2
    raw = Path(args[0]).read_bytes()
    request = json.loads(Path(args[1]).read_text(encoding="utf-8"))
    try:
        summary = count_matrix(raw, request)
    except Exception as exc:
        reason = getattr(exc, "reason", "INCOMPLETE_EXECUTION")
        print(json.dumps({"status": "FAIL", "reason": reason}), file=sys.stderr)
        return 1
    sys.stdout.buffer.write(canonical(summary))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
