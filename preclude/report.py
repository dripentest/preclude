"""Strict, monochrome text rendering of a probe + its verdicts."""

from __future__ import annotations

from .checks import OPEN, PRECLUDED, REVIEW, Verdict
from .probe import Probe

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
