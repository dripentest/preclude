"""Concurrent scanning of many endpoints."""

from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

from . import checks, probe


@dataclass
class Result:
    url: str
    probe: probe.Probe
    verdicts: list[checks.Verdict] = field(default_factory=list)

    @property
    def error(self) -> str | None:
        return self.probe.error


def scan_one(url: str, **kw) -> Result:
    p = probe.run(url, **kw)
    verdicts = [] if p.error else checks.evaluate(p)
    return Result(url=url, probe=p, verdicts=verdicts)


def scan_many(urls: list[str], concurrency: int = 10, **kw) -> list[Result]:
    """Scan every URL concurrently; results are returned in input order."""
    results: dict[int, Result] = {}
    with ThreadPoolExecutor(max_workers=max(1, concurrency)) as ex:
        futures = {ex.submit(scan_one, url, **kw): i for i, url in enumerate(urls)}
        for fut in futures:
            idx = futures[fut]
            try:
                results[idx] = fut.result()
            except Exception as exc:  # defensive: never let one target kill the batch
                p = probe.Probe(url=urls[idx], final_url=urls[idx], method=kw.get("method", "GET"))
                p.error = f"unhandled: {exc}"
                results[idx] = Result(url=urls[idx], probe=p)
    return [results[i] for i in range(len(urls))]


def dedupe(items) -> list[str]:
    """Deduplicate while preserving first-seen order."""
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        if item and item not in seen:
            seen.add(item)
            out.append(item)
    return out


def _urls_from_json(obj) -> list[str]:
    """Pull endpoint URLs out of a parsed JSON value.

    Supports a bare string, an object with a ``url`` key (feroxbuster emits
    ``{"type": "response", "url": ...}``; non-response objects like statistics
    carry no ``url`` and are skipped), and lists of either.
    """
    out: list[tuple[str, int | None]] = []
    _pairs_from_json(obj, out)
    return [url for url, _ in out]


def _pairs_from_json(obj, out: list[tuple[str, int | None]]) -> None:
    if isinstance(obj, str):
        out.append((obj, None))
    elif isinstance(obj, dict):
        if obj.get("type") not in (None, "response"):
            return
        url = obj.get("url")
        if isinstance(url, str):
            status = obj.get("status")
            out.append((url, status if isinstance(status, int) else None))
    elif isinstance(obj, list):
        for item in obj:
            _pairs_from_json(item, out)


def _pair_from_text_line(line: str) -> tuple[str, int | None] | None:
    """Extract (url, status) from one plain-text line.

    Handles a bare URL/host (a target list) and feroxbuster's column output
    (``200  GET  120l  300w  4500c  https://host/path``), taking the URL token
    and the leading status code when present. A multi-field line with no URL
    token (a banner/header) is skipped.
    """
    parts = line.split()
    http = [p for p in parts if p.startswith(("http://", "https://"))]
    status = None
    if parts and parts[0].isdigit() and 100 <= int(parts[0]) <= 599:
        status = int(parts[0])
    if http:
        return (http[-1], status)
    if len(parts) == 1:
        return (parts[0], None)
    return None


@dataclass
class StatusFilter:
    """Keep/drop targets by HTTP status when the input carries one.

    Codes are exact (``200``) or class wildcards (``2xx``). Targets with no
    known status (plain lists, JSON string arrays) always pass.
    """
    include_exact: set[int] = field(default_factory=set)
    include_class: set[int] = field(default_factory=set)
    exclude_exact: set[int] = field(default_factory=set)
    exclude_class: set[int] = field(default_factory=set)

    @staticmethod
    def _parse(spec: str | None) -> tuple[set[int], set[int]]:
        exact: set[int] = set()
        klass: set[int] = set()
        if not spec:
            return exact, klass
        for tok in spec.replace(",", " ").split():
            t = tok.strip().lower()
            if not t:
                continue
            if len(t) == 3 and t[0] in "12345" and t[1:] == "xx":
                klass.add(int(t[0]))
            elif t.isdigit() and 100 <= int(t) <= 599:
                exact.add(int(t))
            else:
                raise ValueError(f"invalid status code '{tok}' (use e.g. 200, 301, 2xx)")
        return exact, klass

    @classmethod
    def parse(cls, include: str | None, exclude: str | None) -> "StatusFilter":
        ie, ic = cls._parse(include)
        ee, ec = cls._parse(exclude)
        return cls(ie, ic, ee, ec)

    @property
    def active(self) -> bool:
        return bool(self.include_exact or self.include_class
                    or self.exclude_exact or self.exclude_class)

    def allows(self, status: int | None) -> bool:
        if status is None:
            return True  # status unknown for this input; cannot filter
        if status in self.exclude_exact or (status // 100) in self.exclude_class:
            return False
        if self.include_exact or self.include_class:
            return status in self.include_exact or (status // 100) in self.include_class
        return True


def extract_targets(text: str, status_filter: StatusFilter | None = None) -> list[str]:
    """Parse targets from file/stdin text, auto-detecting the format.

    Accepts a plain URL-per-line list (``#`` comments ok), a whole-document
    JSON array/object, and newline-delimited JSON (feroxbuster ``--json``).
    When ``status_filter`` is given, targets whose input carries a status are
    kept only if it passes the filter.
    """
    sf = status_filter
    pairs: list[tuple[str, int | None]] = []

    stripped = text.lstrip()
    if stripped[:1] in "[{":  # whole-document JSON (e.g. a pretty-printed array)
        try:
            _pairs_from_json(json.loads(text), pairs)
            return dedupe([u for u, s in pairs if sf is None or sf.allows(s)])
        except json.JSONDecodeError:
            pass  # likely NDJSON or mixed; fall through to per-line handling

    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line[:1] in "[{":  # a single NDJSON record
            try:
                _pairs_from_json(json.loads(line), pairs)
                continue
            except json.JSONDecodeError:
                pass
        pair = _pair_from_text_line(line)
        if pair:
            pairs.append(pair)
    return dedupe([u for u, s in pairs if sf is None or sf.allows(s)])


# Backwards-compatible alias: used to take an iterable of raw lines.
def read_targets(lines) -> list[str]:
    return extract_targets("\n".join(lines))
