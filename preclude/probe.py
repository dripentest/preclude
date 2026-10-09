"""HTTP probing: fetch an endpoint and collect everything the rule engine needs.

Two requests are made against the target:

  1. The primary request (default GET) whose response headers drive most checks.
     Redirects are followed to the final response unless disabled; the hop chain
     is recorded so the report can show it.
  2. A CORS probe: the same URL requested with a foreign ``Origin`` header, so the
     engine can see whether the server reflects the origin / allows credentials.
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
class CorsResult:
    probed: bool = False
    acao: str | None = None  # Access-Control-Allow-Origin
    acac: bool = False  # Access-Control-Allow-Credentials: true
    reflected: bool = False  # ACAO echoes the foreign origin
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


def _cors_probe(session: requests.Session, url: str, timeout: float, verify: bool) -> CorsResult:
    result = CorsResult(probed=True)
    try:
        resp = session.get(
            url,
            timeout=timeout,
            verify=verify,
            allow_redirects=True,
            headers={"Origin": PROBE_ORIGIN},
        )
    except requests.RequestException as exc:
        result.error = str(exc)
        return result
    acao = resp.headers.get("Access-Control-Allow-Origin")
    acac = (resp.headers.get("Access-Control-Allow-Credentials") or "").strip().lower() == "true"
    result.acao = acao
    result.acac = acac
    result.reflected = acao is not None and acao.strip() == PROBE_ORIGIN
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
