# SPDX-License-Identifier: Apache-2.0
"""Human-readable and machine-readable evidence reports."""

from __future__ import annotations

import json

from science_evidence.bundle import canonical


def human_report(bundle: dict) -> str:
    summary = bundle.get("parsed_summary") or {}
    lines = [
        "Science evidence report",
        f"Status: {bundle.get('status')}",
        f"Reason: {bundle.get('reason') or 'none'}",
        f"Accession: {bundle.get('parameters', {}).get('accession')}",
        f"Raw input SHA-256: {bundle.get('raw_input_sha256')}",
        f"Output SHA-256: {bundle.get('output_sha256')}",
        f"Code revision: {bundle.get('code_revision')}",
        f"Normalization: {bundle.get('normalization_policy')}",
        f"Cell columns: {summary.get('cell_columns', 'not run')}",
        f"Feature rows: {summary.get('feature_rows', 'not run')}",
        f"Endogenous features: {summary.get('endogenous_feature_rows', 'not run')}",
        f"ERCC features: {summary.get('ercc_feature_rows', 'not run')}",
        f"Counts pass/fail/skip/not-run: {bundle.get('counts')}",
        "Signed: no",
        "Governed receipt: not issued",
        "This report records a bounded descriptive summary and integrity checks.",
        "It does not establish biological correctness, differential expression,",
        "normalization validity, statistical power, causal evidence, or clinical use.",
        "A payment, when one is later authorized, would buy processing and packaging,",
        "not scientific truth.",
    ]
    return "\n".join(lines) + "\n"


def machine_report(bundle: dict) -> bytes:
    return canonical(bundle)


def public_catalog() -> list[dict]:
    return [
        {
            "project": "science-evidence-workbench",
            "purpose": "Bounded descriptive summaries and integrity reports for small tabular matrices.",
            "intended_users": ["scientists", "developers", "reviewers"],
            "source": "szl-holdings/governed-receipt-spec",
            "example": "examples/science-evidence/synthetic-matrix.tsv",
            "license": "Apache-2.0",
            "publication": "public_synthetic",
            "research_status": "descriptive integrity only",
            "known_blockers": [
                "GSE85241 remains on the existing public-single-cell example and is over this package byte budget",
                "model adapters are disabled",
                "live payment is not enabled",
            ],
            "performance_narrative": "same facts for every audience; no recovery rate or accuracy claim",
        }
    ]


def dumps_catalog() -> str:
    return json.dumps(public_catalog(), indent=2, sort_keys=True) + "\n"
