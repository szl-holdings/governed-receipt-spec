# SPDX-License-Identifier: Apache-2.0
"""Frozen exact-search and BM25 baseline over a synthetic corpus.

This is not a qualification of MiniEmbed or any hub model. Queries and
relevance judgments are fixed in this file.
"""

from __future__ import annotations

import math


DOCUMENTS = {
    "d1": "alpha beta digest",
    "d2": "alpha alpha digest",
    "d3": "gamma organ",
}
JUDGMENTS = {
    "alpha digest": {"d1", "d2"},
    "gamma": {"d3"},
    "omega unknown": set(),
}
K1 = 1.0
B = 0.0


def _tokens(text: str) -> list[str]:
    return [part for part in text.casefold().split() if part]


def exact_hits(query: str) -> list[str]:
    needed = set(_tokens(query))
    if not needed:
        return []
    hits = []
    for doc_id, text in DOCUMENTS.items():
        if needed <= set(_tokens(text)):
            hits.append(doc_id)
    return hits


def bm25(query: str) -> list[tuple[str, float]]:
    """Lucene non-negative IDF. Length normalization is off because B is 0."""

    docs = {doc_id: _tokens(text) for doc_id, text in DOCUMENTS.items()}
    average = sum(len(tokens) for tokens in docs.values()) / len(docs)
    scores = []
    for doc_id, tokens in docs.items():
        score = 0.0
        counts: dict[str, int] = {}
        for token in tokens:
            counts[token] = counts.get(token, 0) + 1
        for term in _tokens(query):
            df = sum(term in set(row) for row in docs.values())
            idf = math.log(1 + (len(docs) - df + 0.5) / (df + 0.5))
            frequency = counts.get(term, 0)
            denom = frequency + K1 * (1 - B + B * len(tokens) / average)
            score += idf * (frequency * (K1 + 1)) / denom if denom else 0.0
        scores.append((doc_id, score))
    scores.sort(key=lambda item: (-item[1], item[0]))
    return scores


def evaluate(query: str, k: int = 2) -> dict:
    if query not in JUDGMENTS:
        return {"status": "ABSTAIN", "reason": "UNJUDGED_QUERY", "recall_at_k": None}
    relevant = JUDGMENTS[query]
    if not relevant:
        hits = exact_hits(query)
        return {
            "status": "ABSTAIN" if not hits else "FAIL",
            "reason": "OUT_OF_DOMAIN" if not hits else "UNEXPECTED_HIT",
            "recall_at_k": None,
            "hits": hits,
        }
    ranked = [doc_id for doc_id, score in bm25(query) if score > 0][:k]
    found = len(set(ranked) & relevant)
    return {
        "status": "SCORED",
        "reason": None,
        "recall_at_k": found / len(relevant),
        "k": k,
        "ranked": ranked,
        "embedding_adapter": "DISABLED",
    }
