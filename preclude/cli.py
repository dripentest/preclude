"""Command-line entry point: ``preclude scan <url> [<url> ...]``."""

from __future__ import annotations

import argparse
import sys

from . import __version__, batch, report


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="preclude",
        description="Scan endpoints' security headers and preclude attack classes "
                    "that cannot work there.",
    )
    parser.add_argument("--version", action="version", version=f"preclude {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="scan one or more endpoint URLs")
    scan.add_argument("urls", nargs="*", help="target URL(s); scheme defaults to https://")
    scan.add_argument("-f", "--file",
                      help="read targets from a file: URL-per-line list, JSON array, "
                           "or feroxbuster --json (NDJSON); format auto-detected")
    scan.add_argument("-X", "--method", default="GET",
                      help="primary request method (default: GET)")
    scan.add_argument("-c", "--concurrency", type=int, default=10,
                      help="parallel requests in batch mode (default: 10)")
    scan.add_argument("--timeout", type=float, default=15.0,
                      help="per-request timeout in seconds (default: 15)")
    scan.add_argument("--no-follow", action="store_true",
                      help="do not follow redirects; judge the first response")
    scan.add_argument("--no-cors", action="store_true",
                      help="skip the foreign-Origin CORS probe")
    scan.add_argument("-k", "--insecure", action="store_true",
                      help="do not verify TLS certificates")
    scan.add_argument("--json", action="store_true",
                      help="emit machine-readable JSON (ranked) instead of text")
    scan.add_argument("--full", action="store_true",
                      help="in batch mode, also print the full per-endpoint report")
    return parser


def _collect_targets(args) -> list[str]:
    targets: list[str] = list(args.urls)  # explicit command-line URLs, as given
    if args.file:
        with open(args.file, encoding="utf-8") as fh:
            targets.extend(batch.extract_targets(fh.read()))
    if not args.urls and not args.file and not sys.stdin.isatty():
        targets.extend(batch.extract_targets(sys.stdin.read()))
    return batch.dedupe(targets)


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command != "scan":
        parser.print_help()
        return 1

    targets = _collect_targets(args)
    if not targets:
        sys.stderr.write("preclude: no targets given (pass URLs, --file, or stdin)\n")
        return 1

    scan_kw = dict(
        method=args.method,
        timeout=args.timeout,
        verify=not args.insecure,
        follow=not args.no_follow,
        cors=not args.no_cors,
    )
    results = batch.scan_many(targets, concurrency=args.concurrency, **scan_kw)

    if args.json:
        sys.stdout.write(report.render_json(results))
    elif len(results) == 1:
        r = results[0]
        sys.stdout.write(report.render(r.probe, r.verdicts))
    else:
        sys.stdout.write(report.render_priority(results))
        if args.full:
            for r in results:
                sys.stdout.write("\n" + "=" * 60 + "\n")
                sys.stdout.write(report.render(r.probe, r.verdicts))

    if all(r.error for r in results):
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
