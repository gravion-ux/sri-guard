"""Command-line interface for sri-guard.

Exit codes: 0 when no finding reaches the ``--fail-on`` threshold
(``low`` by default, so info-only notes pass), 1 when findings are
present, and 2 for usage errors (argparse also exits with 2).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .report import exit_code_for, render_json, render_text
from .scanner import collect_html_files, normalize_origin, scan_file, scan_url


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sri-guard",
        description=(
            "Check HTML pages for missing, malformed, or mismatching "
            "Subresource Integrity (SRI) metadata on external scripts "
            "and stylesheets."
        ),
    )
    parser.add_argument(
        "paths",
        nargs="*",
        metavar="PATH_OR_URL",
        help="HTML files, directories, or http(s) URLs to scan",
    )
    parser.add_argument(
        "--dir",
        action="append",
        default=[],
        metavar="DIR",
        dest="dirs",
        help="directory to scan recursively for .html/.htm files (repeatable)",
    )
    parser.add_argument(
        "--origin",
        metavar="ORIGIN",
        help="page origin (e.g. https://example.com); matching resources are same-origin",
    )
    parser.add_argument(
        "--mirror",
        metavar="DIR",
        help="directory holding local copies of external resources for offline verification",
    )
    parser.add_argument(
        "--fetch",
        action="store_true",
        help="fetch external resources over HTTP(S) to verify their integrity",
    )
    parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="report format (default: text)",
    )
    parser.add_argument("--json", action="store_true", help="shortcut for --format json")
    parser.add_argument(
        "--output",
        "-o",
        metavar="FILE",
        help="write the report to FILE instead of stdout",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        metavar="SECONDS",
        help="network timeout for URL and resource fetches (default: 10)",
    )
    parser.add_argument(
        "--fail-on",
        choices=("info", "low", "medium", "high", "critical"),
        default="low",
        help="lowest severity that makes the exit code 1 (default: low)",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="fail on info findings too (equivalent to --fail-on info)",
    )
    parser.add_argument("--version", action="version", version=f"sri-guard {__version__}")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.paths and not args.dirs:
        parser.error("provide at least one HTML file, directory, or URL (or use --dir)")
    if args.timeout <= 0:
        parser.error("--timeout must be greater than zero")

    origin: str | None = None
    if args.origin:
        try:
            origin = normalize_origin(args.origin)
        except ValueError as exc:
            parser.error(str(exc))

    mirror_dir: Path | None = None
    if args.mirror:
        mirror_dir = Path(args.mirror)
        if not mirror_dir.is_dir():
            parser.error(f"--mirror directory does not exist: {args.mirror}")

    files: list[Path] = []
    urls: list[str] = []
    for raw in args.paths:
        if raw.startswith(("http://", "https://")):
            urls.append(raw)
            continue
        path = Path(raw)
        if path.is_dir():
            files.extend(collect_html_files(path))
        elif path.is_file():
            files.append(path)
        else:
            parser.error(f"path does not exist: {raw}")
    for raw_dir in args.dirs:
        directory = Path(raw_dir)
        if not directory.is_dir():
            parser.error(f"--dir directory does not exist: {raw_dir}")
        files.extend(collect_html_files(directory))

    files = sorted(set(files))
    sources: list[str] = [str(p) for p in files] + urls
    if not sources:
        parser.error("no HTML files found to scan")

    findings = []
    for path in files:
        findings.extend(
            scan_file(
                path,
                origin=origin,
                mirror_dir=mirror_dir,
                fetch=args.fetch,
                timeout=args.timeout,
            )
        )
    for url in urls:
        try:
            findings.extend(
                scan_url(
                    url,
                    origin=origin,
                    mirror_dir=mirror_dir,
                    fetch=args.fetch,
                    timeout=args.timeout,
                )
            )
        except Exception as exc:  # network/operational failure, not a finding
            print(f"sri-guard: failed to fetch {url}: {exc}", file=sys.stderr)
            return 2

    findings.sort(key=lambda f: (f.source, f.line, f.code))
    report_format = "json" if args.json else args.format
    if report_format == "json":
        report = render_json(findings, sources)
    else:
        report = render_text(findings, sources)
    if args.output:
        Path(args.output).write_text(report, encoding="utf-8")
    else:
        sys.stdout.write(report)

    fail_on = "info" if args.strict else args.fail_on
    return exit_code_for(findings, fail_on=fail_on)


if __name__ == "__main__":
    raise SystemExit(main())
