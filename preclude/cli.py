"""Command-line entry point: ``preclude scan <url>``."""

from __future__ import annotations

import argparse
import sys

from . import __version__, checks, probe, report


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="preclude",
        description="Scan an endpoint's security headers and preclude attack classes "
                    "that cannot work there.",
    )
    parser.add_argument("--version", action="version", version=f"preclude {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="scan a single endpoint URL")
    scan.add_argument("url", help="target endpoint URL (scheme defaults to https://)")
    scan.add_argument("-X", "--method", default="GET",
                      help="primary request method (default: GET)")
    scan.add_argument("--timeout", type=float, default=15.0,
                      help="per-request timeout in seconds (default: 15)")
    scan.add_argument("--no-follow", action="store_true",
                      help="do not follow redirects; judge the first response")
    scan.add_argument("--no-cors", action="store_true",
                      help="skip the foreign-Origin CORS probe")
    scan.add_argument("-k", "--insecure", action="store_true",
                      help="do not verify TLS certificates")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "scan":
        p = probe.run(
            args.url,
            method=args.method,
            timeout=args.timeout,
            verify=not args.insecure,
            follow=not args.no_follow,
            cors=not args.no_cors,
        )
        if p.error:
            sys.stdout.write(report.render(p, []))
            return 2
        verdicts = checks.evaluate(p)
        sys.stdout.write(report.render(p, verdicts))
        return 0

    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
