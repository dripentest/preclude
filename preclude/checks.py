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
    exploitable: bool = False  # the probe itself showed a likely-live finding


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
    weaknesses = cspmod.policy_weaknesses(csp)
    if weaknesses:
        return Verdict(cls, REVIEW, "CSP", "; ".join(weaknesses))
    return Verdict(cls, REVIEW, "CSP (strict)",
                   "CSP looks strict (script-src/object-src/base-uri/form-action locked); "
                   "DOM sinks / bypasses may still remain")


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


def _cors_preflight_note(c) -> str:
    """Describe an over-permissive preflight, if any."""
    bits = []
    methods = (c.allow_methods or "")
    headers = (c.allow_headers or "")
    if "*" in methods or any(m in methods.upper() for m in ("PUT", "DELETE", "PATCH")):
        bits.append(f"Allow-Methods: {methods.strip()}")
    if headers.strip() == "*" or "authorization" in headers.lower():
        bits.append(f"Allow-Headers: {headers.strip()}")
    return "; ".join(bits)


def check_cors(p: Probe) -> Verdict:
    cls = "cors"
    c = p.cors
    if not c.probed:
        return Verdict(cls, REVIEW, "CORS not probed", "re-run without --no-cors to judge")
    if c.error:
        return Verdict(cls, REVIEW, "CORS probe failed", c.error)

    # A crafted origin that got reflected is a concrete validator weakness.
    crafted = [b for b in c.bypasses if b.kind != "reflected-any"]
    if crafted:
        with_creds = [b for b in crafted if b.acac]
        worst = (with_creds or crafted)[0]
        kinds = ", ".join(sorted({b.kind for b in crafted}))
        if with_creds:
            return Verdict(cls, REVIEW,
                           f"weak Origin validation ({kinds}) + Allow-Credentials: true",
                           f"exploitable: crafted origin {worst.origin} accepted with credentials",
                           exploitable=True)
        return Verdict(cls, REVIEW, f"weak Origin validation ({kinds})",
                       f"crafted origin {worst.origin} reflected; cross-origin read if data is sensitive")

    pre = _cors_preflight_note(c)
    if c.reflected and c.acac:
        return Verdict(cls, REVIEW, "ACAO reflects Origin + Allow-Credentials: true",
                       "likely exploitable: any origin can read authenticated responses"
                       + (f"; permissive preflight ({pre})" if pre else ""),
                       exploitable=True)
    if c.reflected:
        return Verdict(cls, REVIEW, "ACAO reflects arbitrary Origin",
                       "cross-origin reads allowed (no credentials); exposure if data is sensitive")
    if c.acao is None:
        note = "same-origin policy blocks cross-origin reads"
        if pre and c.preflight_acac:
            return Verdict(cls, REVIEW, "no ACAO on GET, but preflight is permissive",
                           f"{pre}; verify the actual (non-simple) request's CORS response")
        return Verdict(cls, PRECLUDED, "no Access-Control-Allow-Origin for foreign Origin", note)
    if c.acao.strip() == "*":
        return Verdict(cls, REVIEW, "Access-Control-Allow-Origin: *",
                       "any origin can read; exposure if endpoint returns sensitive data")
    if c.acao.strip().lower() == "null":
        return Verdict(cls, REVIEW, "Access-Control-Allow-Origin: null",
                       "'null' is forgeable via sandboxed iframe; test cross-origin read")
    return Verdict(cls, PRECLUDED, f"Access-Control-Allow-Origin: {c.acao} (fixed, not reflected)",
                   "foreign origins are not allowed"
                   + (f"; note permissive preflight ({pre})" if pre else ""))


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


def check_cookie_integrity(p: Probe) -> Verdict:
    # Uses the __Host-/__Secure- cookie name prefixes.
    cls = "cookie-integrity"
    cookies = _session_cookies(p)
    if not cookies:
        return Verdict(cls, REVIEW, "no Set-Cookie observed", "no cookie integrity to assess")
    host_pref = [c.name for c in cookies if c.prefix == "__host-"]
    secure_pref = [c.name for c in cookies if c.prefix == "__secure-"]
    plain = [c.name for c in cookies if not c.prefix]
    if host_pref and not plain:
        return Verdict(cls, PRECLUDED, f"__Host- prefix ({', '.join(host_pref)})",
                       "scope locked to origin + Path=/ with no Domain; "
                       "subdomain overwrite / session fixation prevented")
    if host_pref or secure_pref:
        used = host_pref + secure_pref
        return Verdict(cls, REVIEW, f"partial cookie prefixes ({', '.join(used)})",
                       f"other cookies ({', '.join(plain)}) lack a prefix and stay overwritable; test fixation")
    return Verdict(cls, REVIEW, f"no __Host-/__Secure- prefix ({', '.join(plain)})",
                   "cookie can be overwritten by a sibling subdomain; test session fixation / injection")


def check_permissions_policy(p: Probe) -> Verdict:
    cls = "permissions-policy"
    pp = p.header("Permissions-Policy")
    if pp:
        permissive = any("=*" in d.replace(" ", "") or "=(*)" in d.replace(" ", "")
                         for d in pp.split(","))
        if permissive:
            return Verdict(cls, REVIEW, f"Permissions-Policy: {pp}",
                           "policy present but allows some feature to all origins ('*')")
        return Verdict(cls, PRECLUDED, f"Permissions-Policy: {pp}",
                       "powerful features restricted by policy")
    fp = p.header("Feature-Policy")
    if fp:
        return Verdict(cls, REVIEW, f"Feature-Policy: {fp}",
                       "legacy Feature-Policy; superseded by Permissions-Policy, patchy support")
    return Verdict(cls, REVIEW, "no Permissions-Policy",
                   "powerful features (camera/mic/geolocation/...) not restricted at header level")


def check_coep(p: Probe) -> Verdict:
    cls = "coep"
    coep = p.header("Cross-Origin-Embedder-Policy")
    if coep and coep.strip().lower() in ("require-corp", "credentialless"):
        return Verdict(cls, PRECLUDED, f"Cross-Origin-Embedder-Policy: {coep}",
                       "cross-origin isolation enabled; mitigates XS-leaks / Spectre-class reads")
    return Verdict(cls, REVIEW, "no Cross-Origin-Embedder-Policy",
                   "no cross-origin isolation; XS-leaks / Spectre-class not mitigated")


def check_corp(p: Probe) -> Verdict:
    cls = "corp"
    corp = p.header("Cross-Origin-Resource-Policy")
    if not corp:
        return Verdict(cls, REVIEW, "no Cross-Origin-Resource-Policy",
                       "resource embeddable cross-origin by default; relevant if it is sensitive")
    v = corp.strip().lower()
    if v in ("same-origin", "same-site"):
        return Verdict(cls, PRECLUDED, f"Cross-Origin-Resource-Policy: {corp}",
                       "resource not embeddable across origins")
    if v == "cross-origin":
        return Verdict(cls, OPEN, "Cross-Origin-Resource-Policy: cross-origin",
                       "resource explicitly embeddable by any site")
    return Verdict(cls, REVIEW, f"Cross-Origin-Resource-Policy: {corp}", "unrecognised value")


def check_xss_legacy_filter(p: Probe) -> Verdict:
    cls = "xss-legacy-filter"
    x = p.header("X-XSS-Protection")
    if x is None:
        return Verdict(cls, PRECLUDED, "no X-XSS-Protection",
                       "legacy auditor removed from modern browsers; not a factor")
    if x.strip().lower().startswith("0"):
        return Verdict(cls, PRECLUDED, f"X-XSS-Protection: {x}", "legacy filter correctly disabled")
    return Verdict(cls, REVIEW, f"X-XSS-Protection: {x}",
                   "deprecated filter enabled; can introduce XS-leak/oracle behaviour in old browsers")


def check_clear_site_data(p: Probe) -> Verdict:
    cls = "clear-site-data"
    csd = p.header("Clear-Site-Data")
    if csd:
        return Verdict(cls, PRECLUDED, f"Clear-Site-Data: {csd}",
                       "declarative state clearing present (logout hygiene)")
    return Verdict(cls, REVIEW, "no Clear-Site-Data",
                   "no declarative state clearing; verify logout invalidates the session server-side")


ALL_CHECKS = [
    check_clickjacking,
    check_mime_sniffing,
    check_xss,
    check_csrf,
    check_cors,
    check_cookie_theft,
    check_cookie_transport,
    check_cookie_integrity,
    check_tls_downgrade,
    check_mixed_content,
    check_referrer_leak,
    check_xs_leaks,
    check_coep,
    check_corp,
    check_permissions_policy,
    check_xss_legacy_filter,
    check_clear_site_data,
    check_info_disclosure,
    check_sensitive_caching,
]


def evaluate(p: Probe) -> list[Verdict]:
    return [check(p) for check in ALL_CHECKS]
