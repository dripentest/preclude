"""Strict, monochrome text rendering of a probe + its verdicts."""

from __future__ import annotations

import json

from .batch import Result
from .checks import OPEN, PRECLUDED, REVIEW, Verdict
from .probe import Probe
from . import prioritize

_ORDER = [PRECLUDED, REVIEW, OPEN]
_SECTION = {
    PRECLUDED: "PRECLUDED  - ruled out by headers on this endpoint; skip",
    REVIEW: "REVIEW     - control present but partial/weak; verify by hand",
    OPEN: "OPEN       - no relevant control present; test normally",
}


def render(p: Probe, verdicts: list[Verdict]) -> str:
    lines: list[str] = []

    lines.append(f"target   {p.url}")
    methods = p.method
    if p.cors.probed:
        methods += " (+ CORS probe with foreign Origin)"
    lines.append(f"method   {methods}")

    if p.error:
        lines.append(f"error    {p.error}")
        return "\n".join(lines)

    final = f"{p.status}"
    if p.history:
        chain = " -> ".join(str(s) for s, _ in p.history) + f" -> {p.status}"
        final = f"{p.status}  [{chain} to {p.final_url}]"
    elif p.final_url != p.url:
        final += f"  [{p.final_url}]"
    lines.append(f"final    {final}")
    lines.append("")

    width = max((len(v.cls) for v in verdicts), default=0)
    for status in _ORDER:
        group = [v for v in verdicts if v.status == status]
        if not group:
            continue
        lines.append(_SECTION[status])
        for v in group:
            row = f"  {v.cls.ljust(width)}  {v.evidence}"
            lines.append(row)
            if v.note:
                lines.append(f"  {' ' * width}  ^ {v.note}")
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def _truncate(s: str, n: int) -> str:
    return s if len(s) <= n else s[: n - 1] + "…"


def render_priority(results: list[Result]) -> str:
    """Ranked map across many endpoints: where to test first."""
    ranked = prioritize.rank(results)
    ok = [t for t in ranked if t[0].error is None]
    errs = [t for t in ranked if t[0].error is not None]

    urlw = min(max((len(r.url) for r, _ in ranked), default=8), 54)
    lines: list[str] = []
    lines.append(f"PRIORITY MAP  ({len(results)} endpoints, sorted by remaining attack surface)")
    lines.append("")
    header = f"{'score':>5}  {'open':>4}  {'rev':>3}  {'endpoint'.ljust(urlw)}  top leads"
    lines.append(header)
    lines.append("-" * len(header))
    for r, score in ok:
        nopen = sum(1 for v in r.verdicts if v.status == OPEN)
        nrev = sum(1 for v in r.verdicts if v.status == REVIEW)
        leads = ", ".join(prioritize.top_leads(r.verdicts))
        lines.append(f"{score:>5.0f}  {nopen:>4}  {nrev:>3}  {_truncate(r.url, urlw).ljust(urlw)}  {leads}")

    if errs:
        lines.append("")
        lines.append("unreachable:")
        for r, _ in errs:
            lines.append(f"  {_truncate(r.url, urlw).ljust(urlw)}  {r.error}")

    lines.append("")
    lines.append("legend: (!) probe-confirmed live finding   (open) no control present")
    return "\n".join(lines).rstrip() + "\n"


def _verdict_dict(v: Verdict) -> dict:
    return {
        "class": v.cls,
        "status": v.status,
        "evidence": v.evidence,
        "note": v.note,
        "exploitable": v.exploitable,
    }


def render_json(results: list[Result]) -> str:
    out = []
    for r, score in prioritize.rank(results):
        out.append({
            "url": r.url,
            "final_url": r.probe.final_url,
            "status": r.probe.status,
            "error": r.error,
            "score": round(score, 1),
            "verdicts": [_verdict_dict(v) for v in r.verdicts],
        })
    return json.dumps(out, indent=2) + "\n"
