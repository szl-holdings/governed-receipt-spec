# SPDX-License-Identifier: Apache-2.0
"""Finite attempt reservation. Terminal outcomes absorb further reserves."""

from __future__ import annotations

from science_evidence.contract import EvidenceStop


class AttemptBudget:
    def __init__(self, limit: int) -> None:
        if type(limit) is not int or limit < 0:
            raise ValueError("attempt limit must be a nonnegative integer")
        self.limit = limit
        self.reserved = 0
        self.terminal: str | None = None
        self.reason: str | None = None

    def reserve(self) -> int:
        if self.terminal is not None:
            raise EvidenceStop(
                "CANCELLED" if self.terminal == "CANCELLED" else "ATTEMPTS_EXHAUSTED",
                self.terminal,
            )
        if self.reserved >= self.limit:
            self.terminal = "EXHAUSTED"
            self.reason = "ATTEMPTS_EXHAUSTED"
            raise EvidenceStop("ATTEMPTS_EXHAUSTED", f"limit {self.limit}")
        self.reserved += 1
        return self.reserved

    def complete(self) -> None:
        self._absorb("COMPLETED")

    def fail(self, reason: str) -> None:
        self.reason = reason
        self._absorb("FAILED")

    def cancel(self) -> None:
        self.reason = "CANCELLED"
        self._absorb("CANCELLED")

    def _absorb(self, name: str) -> None:
        if self.terminal is None:
            self.terminal = name
