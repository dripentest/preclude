"""Minimal Content-Security-Policy parser and source-expression analysis."""

from __future__ import annotations

from dataclasses import dataclass

# Source expressions that mean "anything can load here".
WILDCARD_SOURCES = {"*", "http:", "https:", "data:", "blob:", "filesystem:", "mediastream:"}


@dataclass
class CSP:
    enforced: bool  # False when it came from Content-Security-Policy-Report-Only
    directives: dict[str, list[str]]

    def get(self, directive: str) -> list[str] | None:
        return self.directives.get(directive)

    def script_sources(self) -> list[str] | None:
        """Effective script sources: script-src falls back to default-src."""
        return self.directives.get("script-src", self.directives.get("default-src"))


def parse(value: str, enforced: bool = True) -> CSP:
    directives: dict[str, list[str]] = {}
    for chunk in value.split(";"):
        tokens = chunk.split()
        if not tokens:
            continue
        name = tokens[0].lower()
        directives[name] = tokens[1:]
    return CSP(enforced=enforced, directives=directives)


def _is_wildcard(token: str) -> bool:
    t = token.strip("'").lower()
    if token in WILDCARD_SOURCES:
        return True
    # host patterns like *.example.com or https://* are broadly permissive
    return t.startswith("*") or t.endswith("://*") or t == "*"


def script_weaknesses(sources: list[str]) -> list[str]:
    """Return human-readable reasons the script policy is weak, if any."""
    toks = [s.lower() for s in sources]
    reasons: list[str] = []
    has_nonce = any(t.startswith("'nonce-") for t in toks)
    has_hash = any(t.startswith("'sha256-") or t.startswith("'sha384-") or t.startswith("'sha512-") for t in toks)
    strict_dynamic = "'strict-dynamic'" in toks

    if "'unsafe-inline'" in toks and not (has_nonce or has_hash):
        # strict-dynamic makes browsers ignore unsafe-inline when a nonce/hash is present
        if not (strict_dynamic and (has_nonce or has_hash)):
            reasons.append("script-src allows 'unsafe-inline'")
    if "'unsafe-eval'" in toks:
        reasons.append("script-src allows 'unsafe-eval'")
    wild = [s for s in sources if _is_wildcard(s)]
    if wild:
        reasons.append("script-src has wildcard source " + " ".join(sorted(set(wild))))
    return reasons
