"""Concurrent scanning of many endpoints."""

from __future__ import annotations

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


def read_targets(lines) -> list[str]:
    """Normalise a list of raw lines into a deduped, ordered target list.

    Blank lines and ``#`` comments are dropped; order is preserved.
    """
    seen: set[str] = set()
    out: list[str] = []
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line not in seen:
            seen.add(line)
            out.append(line)
    return out
