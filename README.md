# Preclude

Scan a single endpoint's **security response headers** and preclude the attack
classes that cannot work there — so you stop testing what the headers already
rule out and focus on what's actually reachable.

Preclude only reasons about classes that response headers carry real signal
about (browser-/client-enforced ones). It deliberately says nothing about
server-side classes (SSRF, IDOR, SQLi, authz, business logic, path traversal,
SSTI, ...), because headers are not evidence either way for those — so they are
never printed.

## Install

Clone and run straight away — the only dependency is `requests`:

```bash
git clone https://github.com/dripentest/preclude.git
cd preclude
pip install requests            # if not already present
./bin/preclude scan https://target.example/api/v1/user
```

Put it on your `PATH` (so `preclude` works anywhere):

```bash
ln -s "$PWD/bin/preclude" /usr/local/bin/preclude
```

Or install as a package, which also creates the `preclude` command:

```bash
pip install -e .
```

## Usage

One endpoint — full report:

```bash
preclude scan https://target.example/api/v1/user
```

Many endpoints — ranked **priority map** (where to test first). Sources combine:
positional URLs, a `--file`, or stdin (one URL per line, `#` comments allowed):

```bash
preclude scan https://a.example/login https://a.example/api/users
preclude scan --file targets.txt
cat targets.txt | preclude scan
```

Options:

| Flag | Meaning |
|------|---------|
| `-f, --file` | Read targets from a file (one URL per line). |
| `-X, --method` | Primary request method (default `GET`). |
| `-c, --concurrency` | Parallel requests in batch mode (default 10). |
| `--json`       | Machine-readable JSON, ranked, instead of text. |
| `--full`       | In batch mode, also print each full per-endpoint report. |
| `--no-follow`  | Do not follow redirects; judge the first response. |
| `--no-cors`    | Skip the foreign-`Origin` CORS probe. |
| `-k, --insecure` | Do not verify TLS certificates. |
| `--timeout`    | Per-request timeout, seconds (default 15). |

Two requests are sent per target: the primary request (redirects followed to the
final response, the hop chain is shown), and a CORS probe that repeats the
request with a foreign `Origin` to detect reflection / `Allow-Credentials`.

### Priority map

Each endpoint is scored by its remaining (non-precluded) attack surface, weighted
by how interesting each class is to test; a probe-confirmed live finding (e.g.
reflected CORS with credentials) counts most. Endpoints where the juicy classes
are all `PRECLUDED` sink to the bottom.

```
PRIORITY MAP  (4 endpoints, sorted by remaining attack surface)

score  open  rev  endpoint                top leads
---------------------------------------------------
   40     5    7  http://a.example        xss(open), clickjacking(open), mime-sniffing(open)
   11     0    4  https://b.example       xss, csrf, xs-leaks

legend: (!) probe-confirmed live finding   (open) no control present
```

## Verdicts

Each class gets one of three statuses — no colour, just the word:

- **PRECLUDED** — a header on this endpoint closes the class. Skip it.
- **REVIEW** — a control exists but is partial, weak, or itself suspicious
  (e.g. CORS that reflects the origin). Verify by hand.
- **OPEN** — no relevant control is present. Test the class normally.

## Scope of headers: per-endpoint, with three host-wide exceptions

Almost every security header acts **per response** — CSP / `X-Frame-Options` /
`nosniff` / CORS on `/a` do nothing for `/b`. So scan each endpoint; a verdict
is tied to the endpoint you scanned. Exceptions where a header reaches beyond
one response:

- **HSTS** is host-wide for its `max-age` (and subdomains with
  `includeSubDomains`) — one response protects the whole origin.
- **Set-Cookie flags** scope by the cookie's `Domain`/`Path`, not the URL that
  set them — so the cookie verdict follows the cookie.
- **CSP `frame-ancestors`** overrides `X-Frame-Options` within a response when
  both are present.

## Header → class map (the rule base)

| Header | Class(es) it can decide |
|--------|-------------------------|
| `X-Frame-Options`, CSP `frame-ancestors` | clickjacking |
| `X-Content-Type-Options: nosniff` | mime-sniffing |
| CSP `script-src`/`default-src` | xss (mitigation only — never *precluded*) |
| `Set-Cookie` `SameSite` | csrf |
| `Access-Control-Allow-Origin` (+ `-Credentials`) | cors |
| `Set-Cookie` `HttpOnly` | cookie-theft (via XSS) |
| `Set-Cookie` `Secure` | cookie-transport |
| `Strict-Transport-Security` | tls-downgrade |
| CSP `upgrade-insecure-requests` / `block-all-mixed-content` | mixed-content |
| `Referrer-Policy` | referrer-leak |
| `Cross-Origin-Opener-Policy` | xs-leaks / tabnabbing |
| `Server`, `X-Powered-By`, `X-AspNet*` | info-disclosure |
| `Cache-Control` | sensitive-caching |

Notes baked into the engine: CSP never *precludes* XSS (only raises cost);
`Content-Security-Policy-Report-Only` enforces nothing (always REVIEW);
`X-Frame-Options: ALLOW-FROM` and `X-XSS-Protection` are obsolete and not
treated as protection; a reflected CORS origin with credentials is flagged as
likely exploitable rather than as a control.

## Layout

```
bin/preclude  standalone launcher (runs from a clone, no install)
preclude/
  probe.py      HTTP probing: primary request, redirect chain, cookies, CORS probe
  csp.py        CSP parser + script-source weakness analysis
  checks.py     one verdict function per attack class + the rule logic
  batch.py      concurrent multi-endpoint scanning + target parsing
  prioritize.py scoring and ranking of endpoints by remaining surface
  report.py     strict monochrome rendering (single / priority map / JSON)
  cli.py        `preclude scan <url> [<url> ...]`
```

New classes/headers are added by writing a `check_*` function in `checks.py` and
listing it in `ALL_CHECKS`.

## Authorized use only

Run this against systems you are authorized to test.
