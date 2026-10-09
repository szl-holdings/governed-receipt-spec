# SPDX-License-Identifier: Apache-2.0
"""Model qualification register.

Records below classify inspected publication metadata. This module does not
download weights, load pickles, trust remote code, or enable paid inference.
"""

from __future__ import annotations


def _record(**fields: object) -> dict:
    base = {
        "weights_bytes_verified": False,
        "remote_code": "DENY",
        "pickle_loader": "DENY",
        "paid_inference": "DISABLED",
        "training": "NOT_AUTHORIZED",
        "clinical_use": "PROHIBITED",
        "safe_loader": "DO_NOT_LOAD",
    }
    base.update(fields)
    return base


REGISTRY = {
    "SZLHOLDINGS/szl-triage-qwen3.5-0.8b-lora-study5": _record(
        classification="BLOCKED",
        artifact="peft-lora",
        task="generic request triage research",
        base_model="unsloth/Qwen3.5-0.8B",
        base_revision="NOT_RECORDED",
        adapter_revision="fba959ea268a316eaac302e1d58e377013172aa8",
        tokenizer="not separately qualified",
        quantization="BF16; GGUF not attested here",
        peft={"rank": 16, "alpha": 16},
        training_rows=515,
        held_rows=113,
        held_template_families=81,
        leakage={"seed_11_contamination": "REFUSED", "maximum_jaccard": 0.8378, "gate": "NOT_PROMOTABLE"},
        legacy_promotable_override="DENIED",
        prohibited_uses=["production scientific claims", "paid inference", "clinical triage"],
        dependencies=["unsloth", "peft", "transformers"],
        resource_cost="not measured by this package",
        abstention="not qualified",
        release_gate="blocked until a new rights-cleared independently labeled evaluation",
        evidence_basis="inspected publication and seed-11 training receipt; weights not reloaded",
    ),
    "SZLHOLDINGS/SZL-Khipu-1.5B": _record(
        classification="BLOCKED",
        artifact="proposal-only language model",
        task="not a qualified science adapter",
        base_revision="not re-verified in this package",
        quantization="GGUF requires a separate exact-byte qualification; not done here",
        leakage="not rechecked",
        abstention="historical 2/6 result is not a current qualification",
        prohibited_uses=["paid scientific claims", "identity with a local alias"],
        release_gate="release-blocked on the inspected evidence",
        evidence_basis="inspected release evidence; weights not reloaded",
    ),
    "SZLHOLDINGS/szl-kernels": _record(
        classification="RESEARCH_ONLY",
        artifact="128-dimensional PPMI/SVD MiniEmbed software representation",
        task="not a transformers model and not a qualified retriever",
        terms=3290,
        in_domain_documents=26,
        nearest_neighbor_check="sanity check only; not downstream retrieval qualification",
        prohibited_uses=["drop-in transformers inference", "paid retrieval claims"],
        safe_loader="not loaded",
        release_gate="embedding adapter stays disabled until it beats exact/BM25 on a frozen evaluation",
        evidence_basis="inspected kernel card; matrix bytes not reloaded",
    ),
    "SZLHOLDINGS/oac-system-health-v1": _record(
        classification="RESEARCH_ONLY",
        artifact="operational-health research adapter",
        task="infrastructure research inside its stated domain",
        prohibited_uses=["clinical", "diagnostic", "triage", "PHI"],
        release_gate="optional infrastructure research only",
        evidence_basis="inspected model card; not a biological predictor",
    ),
    "SZLHOLDINGS/oac-ops-health-v2": _record(
        classification="UNKNOWN",
        artifact="synthetic operational benchmark source was inspected; exact hub runtime was not",
        task="not established",
        prohibited_uses=["patient or laboratory validity", "doctor-facing prediction"],
        release_gate="unpublished origin commit was not independently verified",
        evidence_basis="source review did not establish the public v2 runtime",
    ),
}


def classify(model_id: str) -> dict:
    record = REGISTRY.get(model_id)
    if record is None:
        return _record(classification="UNKNOWN", model_id=model_id, evidence_basis="not in this register")
    return {"model_id": model_id, **record}


def production_enabled(model_id: str) -> bool:
    return False


def legacy_promotable_cannot_override(model_id: str) -> bool:
    record = classify(model_id)
    return record.get("legacy_promotable_override", "DENIED") == "DENIED" or record["classification"] == "BLOCKED"
