"""HTTP probing: fetch an endpoint and collect everything the rule engine needs.

Two requests are made against the target:

  1. The primary request (default GET) whose response headers drive most checks.
     Redirects are followed to the final response unless disabled; the hop chain
     is recorded so the report can show it.
  2. A CORS probe: a foreign ``Origin`` on a simple GET (reflection / credentials),
     an ``OPTIONS`` preflight (allowed methods / headers), and a short fuzz of
     crafted origins to expose weak Origin-validation (prefix / suffix / unescaped
     dot / null).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urlparse

import requests

USER_AGENT = "preclude/0.1 (+security-header-triage)"

# A deliberately foreign origin used to test CORS reflection. ``.invalid`` can
# never resolve, so it is safe to send and unmistakable if echoed back.
PROBE_ORIGIN = "https://preclude-probe.invalid"


@dataclass
class Cookie:
    name: str
    secure: bool
    httponly: bool
    samesite: str | None  # 'strict' | 'lax' | 'none' | None
    prefix: str | None  # '__host-' | '__secure-' | None
    raw: str


@dataclass
class CorsBypass:
    """A crafted Origin the server accepted (reflected), i.e. a weak validator."""
    origin: str
    kind: str  # 'reflected-any' | 'prefix' | 'suffix' | 'unescaped-dot' | 'null'
    acac: bool  # Access-Control-Allow-Credentials: true for this origin


@dataclass
class CorsResult:
    probed: bool = False
    # Baseline: a plain foreign Origin on the primary method.
    acao: str | None = None  # Access-Control-Allow-Origin echoed back
    acac: bool = False  # Access-Control-Allow-Credentials: true
    reflected: bool = False  # ACAO echoes the foreign origin verbatim
    # Preflight: OPTIONS with Access-Control-Request-Method/Headers.
    preflight: bool = False
    allow_methods: str | None = None  # Access-Control-Allow-Methods
    allow_headers: str | None = None  # Access-Control-Allow-Headers
    preflight_acac: bool = False
    # Origin-validation fuzzing.
    bypasses: list[CorsBypass] = field(default_factory=list)
    error: str | None = None


@dataclass
class Probe:
    url: str
    final_url: str
    method: str
    status: int | None = None
    scheme: str = ""
    history: list[tuple[int, str]] = field(default_factory=list)
    headers: "requests.structures.CaseInsensitiveDict" = field(default_factory=requests.structures.CaseInsensitiveDict)
    cookies: list[Cookie] = field(default_factory=list)
    cors: CorsResult = field(default_factory=CorsResult)
    error: str | None = None

    def header(self, name: str) -> str | None:
        """Case-insensitive single header lookup (duplicates are comma-joined)."""
        return self.headers.get(name)


def _parse_set_cookie(line: str) -> Cookie:
    parts = [p.strip() for p in line.split(";")]
    name = parts[0].split("=", 1)[0].strip()
    attrs = {}
    for seg in parts[1:]:
        if "=" in seg:
            k, v = seg.split("=", 1)
            attrs[k.strip().lower()] = v.strip()
        else:
            attrs[seg.strip().lower()] = True
    lowname = name.lower()
    prefix = None
    if lowname.startswith("__host-"):
        prefix = "__host-"
    elif lowname.startswith("__secure-"):
        prefix = "__secure-"
    samesite = attrs.get("samesite")
    if isinstance(samesite, str):
        samesite = samesite.lower()
    return Cookie(
        name=name,
        secure="secure" in attrs,
        httponly="httponly" in attrs,
        samesite=samesite,
        prefix=prefix,
        raw=line,
    )


def _extract_set_cookies(resp: requests.Response) -> list[Cookie]:
    lines: list[str] = []
    raw = getattr(resp, "raw", None)
    raw_headers = getattr(raw, "headers", None)
    if raw_headers is not None:
        getter = getattr(raw_headers, "getlist", None) or getattr(raw_headers, "get_all", None)
        if getter is not None:
            try:
                lines = list(getter("Set-Cookie"))
            except Exception:
                lines = []
    if not lines:
        joined = resp.headers.get("Set-Cookie")
        if joined:
            lines = [joined]  # best effort; may fold multiple cookies
    return [_parse_set_cookie(line) for line in lines if line]


def _acac_true(resp: requests.Response) -> bool:
    return (resp.headers.get("Access-Control-Allow-Credentials") or "").strip().lower() == "true"


def _bypass_origins(url: str) -> list[tuple[str, str]]:
    """Crafted (origin, kind) pairs that expose weak Origin validation.

    The host does not need to resolve: we connect to the real target and only
    vary the ``Origin`` header, so synthetic markers are fine and detectable.
    """
    host = (urlparse(url).hostname or "").lower()
    out: list[tuple[str, str]] = [("null", "null")]
    if not host:
        return out
    marker = "preclude-bypass.example"
    # startsWith / "contains host" validators accept host as a subdomain prefix.
    out.append((f"https://{host}.{marker}", "prefix"))
    # endsWith validators accept a different registrable domain ending in host.
    out.append((f"https://preclude{host}", "suffix"))
    # Unescaped '.' in a regex matches any char, so a dash-for-dot host passes.
    if "." in host:
        out.append((f"https://{host.replace('.', '-')}", "unescaped-dot"))
    return out


def _cors_probe(session: requests.Session, url: str, timeout: float, verify: bool) -> CorsResult:
    result = CorsResult(probed=True)

    # 1) Baseline: plain foreign Origin on a simple GET.
    try:
        resp = session.get(url, timeout=timeout, verify=verify, allow_redirects=True,
                           headers={"Origin": PROBE_ORIGIN})
    except requests.RequestException as exc:
        result.error = str(exc)
        return result
    acao = resp.headers.get("Access-Control-Allow-Origin")
    result.acao = acao
    result.acac = _acac_true(resp)
    result.reflected = acao is not None and acao.strip() == PROBE_ORIGIN
    if result.reflected:
        result.bypasses.append(CorsBypass(PROBE_ORIGIN, "reflected-any", result.acac))

    # 2) Preflight: OPTIONS asking for a non-simple method + custom header.
    try:
        pre = session.options(url, timeout=timeout, verify=verify, allow_redirects=True, headers={
            "Origin": PROBE_ORIGIN,
            "Access-Control-Request-Method": "PUT",
            "Access-Control-Request-Headers": "x-preclude-probe,authorization",
        })
        result.preflight = True
        result.allow_methods = pre.headers.get("Access-Control-Allow-Methods")
        result.allow_headers = pre.headers.get("Access-Control-Allow-Headers")
        result.preflight_acac = _acac_true(pre)
    except requests.RequestException:
        pass  # preflight is best-effort; absence is itself informative

    # 3) Fuzz crafted origins to catch weak validators (skip if already reflects any).
    if not result.reflected:
        for origin, kind in _bypass_origins(url):
            try:
                r = session.get(url, timeout=timeout, verify=verify, allow_redirects=True,
                               headers={"Origin": origin})
            except requests.RequestException:
                continue
            got = (r.headers.get("Access-Control-Allow-Origin") or "").strip()
            if got and (got == origin or (kind == "null" and got.lower() == "null")):
                result.bypasses.append(CorsBypass(origin, kind, _acac_true(r)))

    return result


def run(
    url: str,
    method: str = "GET",
    timeout: float = 15.0,
    verify: bool = True,
    follow: bool = True,
    cors: bool = True,
) -> Probe:
    if "://" not in url:
        url = "https://" + url

    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})

    p = Probe(url=url, final_url=url, method=method.upper())
    try:
        resp = session.request(
            method.upper(),
            url,
            timeout=timeout,
            verify=verify,
            allow_redirects=follow,
        )
    except requests.RequestException as exc:
        p.error = str(exc)
        return p

    p.status = resp.status_code
    p.final_url = resp.url
    p.scheme = urlparse(resp.url).scheme.lower()
    p.headers = resp.headers
    p.history = [(r.status_code, r.url) for r in resp.history]
    p.cookies = _extract_set_cookies(resp)

    if cors:
        p.cors = _cors_probe(session, p.final_url, timeout, verify)

    return p
