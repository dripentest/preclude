"""Content-Security-Policy parser and source-expression analysis."""

from __future__ import annotations

from dataclasses import dataclass

# Source expressions that mean "anything can load here".
WILDCARD_SOURCES = {"*", "http:", "https:", "data:", "blob:", "filesystem:", "mediastream:"}

# Hosts historically usable to bypass a host allowlist via JSONP endpoints or
# hosted script frameworks (e.g. AngularJS). Not exhaustive — a high-signal set.
RISKY_SCRIPT_HOSTS = {
    "ajax.googleapis.com", "www.google.com", "google.com", "googleapis.com",
    "cdnjs.cloudflare.com", "cdn.jsdelivr.net", "jsdelivr.net",
    "unpkg.com", "code.jquery.com", "ajax.aspnetcdn.com", "yandex.st",
    "cdnjs.com", "stackpath.bootstrapcdn.com",
}


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


def _source_host(src: str) -> str | None:
    """Reduce a source expression to its host, or None for keywords/schemes."""
    s = src.strip().strip("'").lower()
    if not s or s in ("none", "self", "unsafe-inline", "unsafe-eval", "strict-dynamic",
                       "unsafe-hashes", "report-sample", "wasm-unsafe-eval"):
        return None
    if s.startswith(("nonce-", "sha256-", "sha384-", "sha512-")):
        return None
    if "://" in s:
        s = s.split("://", 1)[1]
    s = s.split("/", 1)[0]  # drop any path
    return s or None


def _is_risky_host(host: str) -> bool:
    if host in RISKY_SCRIPT_HOSTS:
        return True
    bare = host[2:] if host.startswith("*.") else host
    return any(bare == r or bare.endswith("." + r) for r in RISKY_SCRIPT_HOSTS)


def _risky_hosts(sources: list[str]) -> list[str]:
    out = []
    for s in sources:
        h = _source_host(s)
        if h and _is_risky_host(h):
            out.append(h)
    return sorted(set(out))


def _locked(tokens: list[str] | None, allowed: set[str]) -> bool:
    """True when every token is one of the safe keywords (e.g. {'none'})."""
    return bool(tokens) and all(t.strip("'").lower() in allowed for t in tokens)


def script_weaknesses(sources: list[str]) -> list[str]:
    """Reasons the *script* policy is weak, if any (script-src/default-src)."""
    toks = [s.lower() for s in sources]
    reasons: list[str] = []
    has_nonce = any(t.startswith("'nonce-") for t in toks)
    has_hash = any(t.startswith(("'sha256-", "'sha384-", "'sha512-")) for t in toks)
    strict_dynamic = "'strict-dynamic'" in toks
    # With strict-dynamic AND a nonce/hash, browsers ignore the host allowlist
    # (wildcards and JSONP hosts no longer grant script execution).
    host_allowlist_ignored = strict_dynamic and (has_nonce or has_hash)

    if "'unsafe-inline'" in toks and not (has_nonce or has_hash):
        reasons.append("script-src allows 'unsafe-inline'")
    if "'unsafe-eval'" in toks:
        reasons.append("script-src allows 'unsafe-eval'")
    if not host_allowlist_ignored:
        wild = sorted({s for s in sources if _is_wildcard(s)})
        if wild:
            reasons.append("script-src has wildcard source " + " ".join(wild))
        risky = _risky_hosts(sources)
        if risky:
            reasons.append("script-src allows JSONP/CDN bypass host(s): " + " ".join(risky))
    return reasons


def policy_weaknesses(csp: CSP) -> list[str]:
    """All weaknesses across the directives preclude actually judges."""
    reasons: list[str] = []
    default = csp.get("default-src")

    srcs = csp.script_sources()
    if srcs is None:
        reasons.append("no script-src/default-src (inline/remote JS unrestricted)")
    else:
        reasons.extend(script_weaknesses(srcs))

    # object-src should be 'none' (or inherited from a 'none' default-src).
    obj = csp.get("object-src")
    if obj is None:
        if not _locked(default, {"none"}):
            reasons.append("no object-src 'none' (plugin/object injection not blocked)")
    elif not _locked(obj, {"none"}):
        reasons.append("object-src not 'none' (" + " ".join(obj) + ")")

    # base-uri should be 'none' or 'self' to stop base-tag injection.
    base = csp.get("base-uri")
    if base is None:
        reasons.append("no base-uri (base-tag injection / dangling-markup possible)")
    elif not _locked(base, {"none", "self"}):
        reasons.append("base-uri is permissive (" + " ".join(base) + ")")

    # form-action should be constrained to stop form hijacking / exfil.
    form = csp.get("form-action")
    if form is None:
        reasons.append("no form-action (form hijacking / exfil not restricted)")
    elif any(_is_wildcard(t) for t in form):
        reasons.append("form-action is permissive (" + " ".join(form) + ")")

    return reasons
