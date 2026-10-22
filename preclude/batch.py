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
    if isinstance(obj, str):
        return [obj]
    if isinstance(obj, dict):
        if obj.get("type") not in (None, "response"):
            return []
        url = obj.get("url")
        return [url] if isinstance(url, str) else []
    if isinstance(obj, list):
        out: list[str] = []
        for item in obj:
            out.extend(_urls_from_json(item))
        return out
    return []


def _url_from_text_line(line: str) -> str | None:
    """Extract a target from one plain-text line.

    Handles a bare URL/host (a target list) and feroxbuster's column output
    (``200  GET  120l  300w  4500c  https://host/path``) by taking the URL
    token. A multi-field line with no URL token (a banner/header) is skipped.
    """
    parts = line.split()
    http = [p for p in parts if p.startswith(("http://", "https://"))]
    if http:
        return http[-1]
    if len(parts) == 1:
        return parts[0]
    return None


def extract_targets(text: str) -> list[str]:
    """Parse targets from file/stdin text, auto-detecting the format.

    Accepts a plain URL-per-line list (``#`` comments ok), a whole-document
    JSON array/object, and newline-delimited JSON (feroxbuster ``--json``).
    """
    stripped = text.lstrip()
    # Whole-document JSON (e.g. a pretty-printed array) — not NDJSON.
    if stripped[:1] in "[{":
        try:
            return dedupe(_urls_from_json(json.loads(text)))
        except json.JSONDecodeError:
            pass  # likely NDJSON or mixed; fall through to per-line handling

    out: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line[:1] in "[{":  # a single NDJSON record
            try:
                out.extend(_urls_from_json(json.loads(line)))
                continue
            except json.JSONDecodeError:
                pass
        url = _url_from_text_line(line)
        if url:
            out.append(url)
    return dedupe(out)


# Backwards-compatible alias: used to take an iterable of raw lines.
def read_targets(lines) -> list[str]:
    return extract_targets("\n".join(lines))
