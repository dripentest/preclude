"""Score endpoints by remaining (non-precluded) attack surface and rank them.

The point of batch mode: given many endpoints, say *where to test first*. An
endpoint whose juicy classes are all PRECLUDED sinks to the bottom; one with
live, high-value classes rises to the top.
"""

from __future__ import annotations

from .batch import Result
from .checks import OPEN, PRECLUDED, REVIEW, Verdict

# How interesting each class is to actually test, roughly by typical impact/effort.
CLASS_WEIGHT = {
    "xss": 10,
    "cors": 9,
    "csrf": 7,
    "cookie-theft": 6,
    "sensitive-caching": 6,
    "tls-downgrade": 4,
    "clickjacking": 4,
    "mime-sniffing": 4,
    "mixed-content": 3,
    "referrer-leak": 3,
    "xs-leaks": 3,
    "cookie-transport": 3,
    "info-disclosure": 2,
}

STATUS_MULT = {OPEN: 1.0, REVIEW: 0.5, PRECLUDED: 0.0}
EXPLOITABLE_MULT = 1.5  # a probe-confirmed live finding counts more than a plain OPEN


def verdict_score(v: Verdict) -> float:
    base = CLASS_WEIGHT.get(v.cls, 3)
    score = base * STATUS_MULT.get(v.status, 0.0)
    if v.exploitable:
        score = base * EXPLOITABLE_MULT
    return score


def endpoint_score(verdicts: list[Verdict]) -> float:
    return sum(verdict_score(v) for v in verdicts)


def top_leads(verdicts: list[Verdict], n: int = 3) -> list[str]:
    """Highest-scoring non-precluded classes, labelled."""
    live = [v for v in verdicts if v.status != PRECLUDED]
    live.sort(key=verdict_score, reverse=True)
    labels = []
    for v in live[:n]:
        tag = v.cls
        if v.exploitable:
            tag += "(!)"
        elif v.status == OPEN:
            tag += "(open)"
        labels.append(tag)
    return labels


def rank(results: list[Result]) -> list[tuple[Result, float]]:
    scored = [(r, endpoint_score(r.verdicts)) for r in results]
    # Errors to the bottom; otherwise by score desc, then URL for stability.
    scored.sort(key=lambda t: (t[0].error is not None, -t[1], t[0].url))
    return scored
