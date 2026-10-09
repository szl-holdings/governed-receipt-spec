# SPDX-License-Identifier: Apache-2.0
"""Evidence-gap watch items.

A source change requests human review. It does not mark a hypothesis valid.
An inaccessible source is UNAVAILABLE, not evidence against the hypothesis.
No scheduler is started by this module.
"""

from __future__ import annotations

from science_evidence.contract import TIME, EvidenceStop


CATEGORIES = frozenset({
    "ACCESS_LIMITED",
    "COVERAGE_MISSING",
    "POWER_INADEQUATE",
    "INSTRUMENT_UNAVAILABLE",
    "METADATA_INSUFFICIENT",
    "RELEASE_UNCHANGED",
    "CHANGE_REQUIRES_REVIEW",
})
REQUIRED = (
    "item_id",
    "question",
    "source_id",
    "revision",
    "category",
    "blocker",
    "unblock_condition",
    "assumptions",
    "external_checks",
    "rate_policy",
    "reviewer",
    "rights",
    "next_permitted_check",
)


class WatchList:
    def __init__(self) -> None:
        self.items: dict[str, dict] = {}

    def add(self, spec: dict) -> dict:
        missing = [key for key in REQUIRED if key not in spec or spec[key] in ("", None, [])]
        if missing:
            raise EvidenceStop("MISSING_METADATA", ",".join(missing))
        if spec["category"] not in CATEGORIES:
            raise EvidenceStop("MISSING_METADATA", "unknown evidence category")
        if not TIME.fullmatch(spec["next_permitted_check"]):
            raise EvidenceStop("RECORD_FRAMING", "next_permitted_check")
        if spec["item_id"] in self.items:
            raise EvidenceStop("DUPLICATE_IDENTIFIER", spec["item_id"])
        if not isinstance(spec["external_checks"], list) or not spec["assumptions"]:
            raise EvidenceStop("MISSING_METADATA", "assumptions and external checks are required")
        item = {
            "item_id": spec["item_id"],
            "question": spec["question"],
            "source_id": spec["source_id"],
            "revision": spec["revision"],
            "observed_release": None,
            "category": spec["category"],
            "blocker": spec["blocker"],
            "unblock_condition": spec["unblock_condition"],
            "assumptions": list(spec["assumptions"]),
            "external_checks": list(spec["external_checks"]),
            "rate_policy": spec["rate_policy"],
            "reviewer": spec["reviewer"],
            "rights": dict(spec["rights"]) if isinstance(spec["rights"], dict) else spec["rights"],
            "next_permitted_check": spec["next_permitted_check"],
            "prior_observation": spec.get("prior_observation"),
            "publication_approved": False,
            "machine_state": "OPEN",
            "review_state": "UNREVIEWED",
            "scientific_validity": "NOT_ESTABLISHED",
            "evidence_against_hypothesis": False,
            "condition_met": False,
            "last_observation": None,
            "last_successfully_checked": None,
            "freshness": "UNOBSERVED",
            "checkpoint": None,
            "checkpoint_covers_all_observations": False,
            "citations": [],
            "independent_corroboration": False,
            "history": [],
            "seen_event_ids": [],
        }
        self._event(item, spec.get("event_id", f"{spec['item_id']}-created"), "CREATED", spec["next_permitted_check"], {})
        self.items[item["item_id"]] = item
        return item

    def observe(self, item_id: str, observation: dict) -> dict:
        item = self._item(item_id)
        event_id = str(observation.get("event_id") or "")
        observed_at = str(observation.get("observed_at") or "")
        if not event_id or not TIME.fullmatch(observed_at):
            raise EvidenceStop("RECORD_FRAMING", "observation id and time")
        if event_id in item["seen_event_ids"]:
            raise EvidenceStop("DUPLICATE_IDENTIFIER", "duplicate event")
        if observed_at < item["next_permitted_check"]:
            raise EvidenceStop("RECORD_FRAMING", "observation is earlier than the permitted check")
        if not observation.get("completed", False):
            self._event(item, event_id, "INTERRUPTED", observed_at, {"reason": "INCOMPLETE_EXECUTION"})
            item["freshness"] = "INCOMPLETE"
            return item
        item["last_observation"] = observed_at
        if not observation.get("accessible", False) or not observation.get("source_present", True):
            item["machine_state"] = "UNAVAILABLE"
            item["category"] = "ACCESS_LIMITED"
            item["evidence_against_hypothesis"] = False
            item["scientific_validity"] = "NOT_ESTABLISHED"
            self._event(item, event_id, "UNAVAILABLE", observed_at, {"evidence_against_hypothesis": False})
            return item
        if not observation.get("metadata_sufficient", False):
            item["category"] = "METADATA_INSUFFICIENT"
            item["machine_state"] = "OBSERVED"
            item["scientific_validity"] = "NOT_ESTABLISHED"
            self._event(item, event_id, "METADATA_INSUFFICIENT", observed_at, {})
            return item
        if observation.get("source_id") != item["source_id"]:
            item["machine_state"] = "REVIEW_REQUIRED"
            item["review_state"] = "REVIEW_REQUIRED"
            item["category"] = "CHANGE_REQUIRES_REVIEW"
            item["scientific_validity"] = "NOT_ESTABLISHED"
            item["last_successfully_checked"] = observed_at
            self._event(item, event_id, "IDENTIFIER_CHANGED", observed_at, {
                "previous_source_id": item["source_id"],
                "observed_source_id": observation.get("source_id"),
            })
            return item
        changed = observation.get("release") != item["revision"]
        if changed:
            item["observed_release"] = observation.get("release")
            item["category"] = "CHANGE_REQUIRES_REVIEW"
            item["machine_state"] = "REVIEW_REQUIRED"
            item["review_state"] = "REVIEW_REQUIRED"
            item["scientific_validity"] = "NOT_ESTABLISHED"
        else:
            item["category"] = "RELEASE_UNCHANGED"
            item["machine_state"] = "OBSERVED"
        item["last_successfully_checked"] = observed_at
        item["freshness"] = "CURRENT"
        if observation.get("condition_met"):
            item["condition_met"] = True
            item["scientific_validity"] = "NOT_ESTABLISHED"
            if not changed:
                item["machine_state"] = "UNBLOCK_PENDING_REVIEW"
                item["review_state"] = "REVIEW_OUTSTANDING"
        self._event(item, event_id, "OBSERVED", observed_at, {
            "release_changed": changed,
            "condition_met": bool(observation.get("condition_met")),
            "scientific_validity": "NOT_ESTABLISHED",
        })
        return item

    def record_review(self, item_id: str, review: dict) -> dict:
        item = self._item(item_id)
        decision = review.get("decision")
        if decision == "SCIENTIFICALLY_VALID":
            raise EvidenceStop("UNSUPPORTED_FORMAT", "software does not mint scientific validity")
        if decision not in {"REVIEW_RECORDED", "UNBLOCK_NOT_GRANTED"}:
            raise EvidenceStop("MISSING_METADATA", "review decision")
        if not review.get("evidence_ref") or not review.get("reviewer"):
            raise EvidenceStop("MISSING_METADATA", "reviewer and evidence reference")
        item["review_state"] = "HUMAN_REVIEW_RECORDED"
        item["scientific_validity"] = "NOT_ESTABLISHED"
        if decision == "REVIEW_RECORDED" and item["condition_met"]:
            item["machine_state"] = "UNBLOCK_RECORDED_BY_REVIEWER"
        self._event(item, review["event_id"], "HUMAN_REVIEW", review["observed_at"], {
            "decision": decision,
            "evidence_ref": review["evidence_ref"],
            "reviewer": review["reviewer"],
            "external_checks_remain": list(item["external_checks"]),
        })
        return item

    def cite(self, item_id: str, source_id: str) -> dict:
        item = self._item(item_id)
        item["citations"].append(source_id)
        distinct = {source for source in item["citations"] if source != item["source_id"]}
        item["independent_corroboration"] = len(distinct) > 0 and len(set(item["citations"])) > 1
        if item["citations"].count(source_id) > 1:
            item["independent_corroboration"] = False
        return item

    def note_stale(self, item_id: str, now: str) -> dict:
        item = self._item(item_id)
        if not TIME.fullmatch(now):
            raise EvidenceStop("RECORD_FRAMING", "stale clock")
        previous = item["last_successfully_checked"]
        if item["last_observation"] is None or now > item["next_permitted_check"]:
            item["freshness"] = "STALE"
        item["last_successfully_checked"] = previous
        return item

    def advance_checkpoint(self, item_id: str, checkpoint: str) -> dict:
        item = self._item(item_id)
        item["checkpoint"] = checkpoint
        item["checkpoint_covers_all_observations"] = False
        return item

    def public_projection(self) -> list[dict]:
        return [
            {"item_id": item["item_id"], "question": item["question"], "machine_state": item["machine_state"]}
            for item in self.items.values()
            if item["publication_approved"] is True
        ]

    def _item(self, item_id: str) -> dict:
        try:
            return self.items[item_id]
        except KeyError as exc:
            raise EvidenceStop("MISSING_METADATA", item_id) from exc

    def _event(self, item: dict, event_id: str, kind: str, at: str, detail: dict) -> None:
        if event_id in item["seen_event_ids"]:
            raise EvidenceStop("DUPLICATE_IDENTIFIER", event_id)
        item["seen_event_ids"].append(event_id)
        item["history"].append({"event_id": event_id, "kind": kind, "at": at, "detail": dict(detail)})
