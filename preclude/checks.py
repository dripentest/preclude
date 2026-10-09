"""Per-class verdict logic.

Each check inspects a :class:`~preclude.probe.Probe` and returns a :class:`Verdict`
for one attack class. Only classes that security *response headers* can actually
speak to live here; server-side classes (SSRF, IDOR, SQLi, authz, logic, ...) are
intentionally absent because headers carry no signal about them.

Status meaning:
  PRECLUDED  a header on this endpoint closes the class; skip it.
  REVIEW     a control exists but is partial, weak, or itself suspicious; verify.
  OPEN       no relevant control is present; test the class normally.
"""

from __future__ import annotations

from dataclasses import dataclass

from . import csp as cspmod
from .probe import Probe

PRECLUDED = "PRECLUDED"
REVIEW = "REVIEW"
OPEN = "OPEN"


@dataclass
class Verdict:
    cls: str  # short class key, e.g. "clickjacking"
    status: str  # PRECLUDED | REVIEW | OPEN
    evidence: str  # header/value that drove the verdict (or "no relevant header")
    note: str = ""  # what to do / why, for REVIEW and OPEN


def _get_csp(p: Probe) -> cspmod.CSP | None:
    enforced = p.header("Content-Security-Policy")
    if enforced:
        return cspmod.parse(enforced, enforced=True)
    ro = p.header("Content-Security-Policy-Report-Only")
    if ro:
        return cspmod.parse(ro, enforced=False)
    return None


def _session_cookies(p: Probe):
    """Cookies that look like auth/session state (best-effort heuristic)."""
    hints = ("sess", "sid", "auth", "token", "jwt", "login", "csrf")
    picked = [c for c in p.cookies if any(h in c.name.lower() for h in hints)]
    return picked or p.cookies


# --------------------------------------------------------------------------- #
# Checks
# --------------------------------------------------------------------------- #

def check_clickjacking(p: Probe) -> Verdict:
    cls = "clickjacking"
    csp = _get_csp(p)
    fa = csp.get("frame-ancestors") if csp else None
    if fa is not None:
        toks = [t.lower() for t in fa]
        wild = any(t == "*" or t.endswith("://*") or t.startswith("*") for t in toks)
        label = "frame-ancestors " + " ".join(fa)
        if "'none'" in toks:
            return Verdict(cls, PRECLUDED, f"CSP {label}")
        if wild:
            return Verdict(cls, REVIEW, f"CSP {label}", "wildcard frame-ancestors allows framing")
        if not csp.enforced:
            return Verdict(cls, REVIEW, f"CSP-Report-Only {label}", "Report-Only is not enforced")
        return Verdict(cls, PRECLUDED, f"CSP {label}")

    xfo = p.header("X-Frame-Options")
    if xfo:
        v = xfo.strip().lower()
        if v in ("deny", "sameorigin"):
            return Verdict(cls, PRECLUDED, f"X-Frame-Options: {xfo}")
        if v.startswith("allow-from"):
            return Verdict(cls, REVIEW, f"X-Frame-Options: {xfo}",
                           "ALLOW-FROM is obsolete and ignored by modern browsers")
        return Verdict(cls, REVIEW, f"X-Frame-Options: {xfo}", "unrecognised value")
    return Verdict(cls, OPEN, "no X-Frame-Options or frame-ancestors",
                   "page is framable; test UI-redress if it has sensitive actions")


def check_mime_sniffing(p: Probe) -> Verdict:
    cls = "mime-sniffing"
    v = p.header("X-Content-Type-Options")
    if v and v.strip().lower() == "nosniff":
        return Verdict(cls, PRECLUDED, f"X-Content-Type-Options: {v}")
    if v:
        return Verdict(cls, REVIEW, f"X-Content-Type-Options: {v}", "value is not 'nosniff'")
    return Verdict(cls, OPEN, "no X-Content-Type-Options",
                   "content sniffing possible; test content-type confusion")


def check_xss(p: Probe) -> Verdict:
    # CSP never *precludes* XSS, it only raises exploitation cost -> PRECLUDED is
    # never returned here by design.
    cls = "xss"
    csp = _get_csp(p)
    if csp is None:
        return Verdict(cls, OPEN, "no Content-Security-Policy",
                       "no CSP mitigation; test reflected/stored/DOM XSS normally")
    if not csp.enforced:
        return Verdict(cls, REVIEW, "Content-Security-Policy-Report-Only",
                       "CSP present but Report-Only, so it blocks nothing")
    srcs = csp.script_sources()
    if srcs is None:
        return Verdict(cls, REVIEW, "CSP without script-src/default-src",
                       "no script restriction; CSP does not constrain inline/remote JS")
    weaknesses = cspmod.script_weaknesses(srcs)
    if weaknesses:
        return Verdict(cls, REVIEW, "CSP script-src", "; ".join(weaknesses))
    return Verdict(cls, REVIEW, "CSP script-src (strict)",
                   "CSP looks strict; XSS exploitation is hard but DOM sinks / bypasses may remain")


def check_csrf(p: Probe) -> Verdict:
    cls = "csrf"
    cookies = _session_cookies(p)
    if not cookies:
        return Verdict(cls, REVIEW, "no Set-Cookie observed",
                       "may use token/header auth; headers cannot confirm CSRF posture")
    # Judge by the weakest relevant cookie.
    samesites = [(c.name, c.samesite) for c in cookies]
    if any(ss == "strict" for _, ss in samesites) and all(ss in ("strict", "lax") or ss is None for _, ss in samesites):
        strict = [n for n, ss in samesites if ss == "strict"]
        return Verdict(cls, PRECLUDED, f"Set-Cookie SameSite=Strict ({', '.join(strict)})")
    if any(ss == "lax" for _, ss in samesites):
        lax = [n for n, ss in samesites if ss == "lax"]
        return Verdict(cls, REVIEW, f"Set-Cookie SameSite=Lax ({', '.join(lax)})",
                       "Lax still allows top-level GET navigation; test state-changing GETs")
    none_or_missing = [n for n, ss in samesites if ss in (None, "none")]
    return Verdict(cls, OPEN, f"Set-Cookie SameSite=None/absent ({', '.join(none_or_missing)})",
                   "cookies sent cross-site; test CSRF on state-changing requests")


def check_cors(p: Probe) -> Verdict:
    cls = "cors"
    c = p.cors
    if not c.probed:
        return Verdict(cls, REVIEW, "CORS not probed", "re-run without --no-cors to judge")
    if c.error:
        return Verdict(cls, REVIEW, "CORS probe failed", c.error)
    if c.acao is None:
        return Verdict(cls, PRECLUDED, "no Access-Control-Allow-Origin for foreign Origin",
                       "same-origin policy blocks cross-origin reads")
    if c.reflected and c.acac:
        return Verdict(cls, REVIEW, f"ACAO reflects Origin + Allow-Credentials: true",
                       "likely exploitable: any origin can read authenticated responses")
    if c.reflected:
        return Verdict(cls, REVIEW, "ACAO reflects arbitrary Origin",
                       "cross-origin reads allowed (no credentials); exposure if data is sensitive")
    if c.acao.strip() == "*":
        return Verdict(cls, REVIEW, "Access-Control-Allow-Origin: *",
                       "any origin can read; exposure if endpoint returns sensitive data")
    if c.acao.strip().lower() == "null":
        return Verdict(cls, REVIEW, "Access-Control-Allow-Origin: null",
                       "'null' is forgeable via sandboxed iframe; test cross-origin read")
    return Verdict(cls, PRECLUDED, f"Access-Control-Allow-Origin: {c.acao} (fixed, not reflected)",
                   "foreign origins are not allowed")


def check_cookie_theft(p: Probe) -> Verdict:
    cls = "cookie-theft"
    cookies = _session_cookies(p)
    if not cookies:
        return Verdict(cls, REVIEW, "no Set-Cookie observed", "no cookie to protect, or token auth")
    insecure = [c.name for c in cookies if not c.httponly]
    if not insecure:
        return Verdict(cls, PRECLUDED, "all session cookies HttpOnly",
                       "cookies unreadable from JS; XSS cannot steal them")
    return Verdict(cls, OPEN, f"cookie without HttpOnly ({', '.join(insecure)})",
                   "readable via document.cookie; session theft possible if XSS exists")


def check_cookie_transport(p: Probe) -> Verdict:
    cls = "cookie-transport"
    cookies = _session_cookies(p)
    if not cookies:
        return Verdict(cls, REVIEW, "no Set-Cookie observed", "")
    insecure = [c.name for c in cookies if not c.secure]
    if not insecure:
        return Verdict(cls, PRECLUDED, "all session cookies Secure")
    return Verdict(cls, OPEN, f"cookie without Secure ({', '.join(insecure)})",
                   "cookie may be sent over http; interceptable on downgrade")


def check_tls_downgrade(p: Probe) -> Verdict:
    cls = "tls-downgrade"
    if p.scheme != "https":
        return Verdict(cls, OPEN, f"endpoint served over {p.scheme or 'http'}",
                       "no transport security; MITM/downgrade trivial")
    hsts = p.header("Strict-Transport-Security")
    if not hsts:
        return Verdict(cls, OPEN, "no Strict-Transport-Security",
                       "first-visit downgrade/strip possible; test SSL-strip")
    low = hsts.lower()
    max_age = 0
    for part in low.split(";"):
        part = part.strip()
        if part.startswith("max-age="):
            try:
                max_age = int(part.split("=", 1)[1])
            except ValueError:
                max_age = 0
    notes = []
    if max_age < 15552000:  # < 180 days
        notes.append(f"max-age={max_age} is short")
    if "includesubdomains" not in low:
        notes.append("no includeSubDomains")
    if notes:
        return Verdict(cls, REVIEW, f"Strict-Transport-Security: {hsts}", "; ".join(notes))
    return Verdict(cls, PRECLUDED, f"Strict-Transport-Security: {hsts} (host-wide)")


def check_mixed_content(p: Probe) -> Verdict:
    cls = "mixed-content"
    if p.scheme != "https":
        return Verdict(cls, OPEN, f"page served over {p.scheme or 'http'}", "not an https page")
    csp = _get_csp(p)
    if csp and ("upgrade-insecure-requests" in csp.directives or "block-all-mixed-content" in csp.directives):
        d = "upgrade-insecure-requests" if "upgrade-insecure-requests" in csp.directives else "block-all-mixed-content"
        return Verdict(cls, PRECLUDED, f"CSP {d}")
    return Verdict(cls, REVIEW, "no upgrade-insecure-requests / block-all-mixed-content",
                   "mixed-content loads not forced to https; check subresources")


def check_referrer_leak(p: Probe) -> Verdict:
    cls = "referrer-leak"
    v = p.header("Referrer-Policy")
    if not v:
        return Verdict(cls, REVIEW, "no Referrer-Policy",
                       "browser default applies; sensitive URLs may leak via Referer")
    # A browser honours the last valid token in a comma-separated list.
    tokens = [t.strip().lower() for t in v.split(",") if t.strip()]
    effective = tokens[-1] if tokens else ""
    safe = {"no-referrer", "same-origin", "strict-origin", "strict-origin-when-cross-origin"}
    if effective in safe:
        return Verdict(cls, PRECLUDED, f"Referrer-Policy: {v}")
    if effective == "unsafe-url":
        return Verdict(cls, REVIEW, f"Referrer-Policy: {v}", "full URL leaked cross-origin")
    return Verdict(cls, REVIEW, f"Referrer-Policy: {v}",
                   f"effective token '{effective}' is weak; URLs may leak")


def check_xs_leaks(p: Probe) -> Verdict:
    cls = "xs-leaks"
    coop = p.header("Cross-Origin-Opener-Policy")
    if coop and coop.strip().lower() in ("same-origin", "same-origin-allow-popups"):
        return Verdict(cls, PRECLUDED, f"Cross-Origin-Opener-Policy: {coop}",
                       "cross-window references severed (tabnabbing / XS-leaks)")
    return Verdict(cls, REVIEW, "no Cross-Origin-Opener-Policy",
                   "cross-window attacks / tabnabbing / XS-leaks not mitigated at header level")


def check_info_disclosure(p: Probe) -> Verdict:
    cls = "info-disclosure"
    banners = []
    for h in ("Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version", "X-Generator"):
        val = p.header(h)
        if val:
            banners.append(f"{h}: {val}")
    if banners:
        return Verdict(cls, REVIEW, "; ".join(banners),
                       "tech/version disclosed; fingerprint for known-CVE paths")
    return Verdict(cls, PRECLUDED, "no Server/X-Powered-By/version banners")


def check_sensitive_caching(p: Probe) -> Verdict:
    cls = "sensitive-caching"
    cc = (p.header("Cache-Control") or "").lower()
    if "no-store" in cc or "private" in cc:
        return Verdict(cls, PRECLUDED, f"Cache-Control: {p.header('Cache-Control')}")
    has_cookies = bool(p.cookies)
    if has_cookies and ("public" in cc or not cc):
        return Verdict(cls, REVIEW, f"Cache-Control: {p.header('Cache-Control') or '(absent)'}",
                       "authenticated-looking response is cacheable; test cache deception/poisoning")
    return Verdict(cls, REVIEW, f"Cache-Control: {p.header('Cache-Control') or '(absent)'}",
                   "verify sensitive data is not cached")


ALL_CHECKS = [
    check_clickjacking,
    check_mime_sniffing,
    check_xss,
    check_csrf,
    check_cors,
    check_cookie_theft,
    check_cookie_transport,
    check_tls_downgrade,
    check_mixed_content,
    check_referrer_leak,
    check_xs_leaks,
    check_info_disclosure,
    check_sensitive_caching,
]


def evaluate(p: Probe) -> list[Verdict]:
    return [check(p) for check in ALL_CHECKS]
