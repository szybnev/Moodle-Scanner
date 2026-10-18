"""Command line interface (``moodle-scanner`` / ``python scanner.py``)."""

from __future__ import annotations

import argparse
import json
import os
import sys
import traceback
from pathlib import Path

from . import __version__
from .httpclient import DEFAULT_MAX_BODY, DEFAULT_TIMEOUT, DEFAULT_USER_AGENT, HttpClient
from .scan import (
    DATA_DIR,
    EXIT_DATA_ERROR,
    EXIT_INTERNAL,
    EXIT_OK,
    EXIT_SCAN_FAILED,
    EXIT_USAGE,
    SCHEMA_PATH,
    DataBundle,
    DataError,
    ScanOptions,
    scan,
)

BANNER = r"""
___  ___                _ _             _____
|  \/  |               | | |           /  ___|
| .  . | ___   ___   __| | | ___ ______\ `--.  ___ __ _ _ __  _ __   ___ _ __
| |\/| |/ _ \ / _ \ / _` | |/ _ \______|`--. \/ __/ _` | '_ \| '_ \ / _ \ '__|
| |  | | (_) | (_) | (_| | |  __/      /\__/ / (_| (_| | | | | | | |  __/ |
\_|  |_/\___/ \___/ \__,_|_|\___|      \____/ \___\__,_|_| |_|_| |_|\___|_|
"""

EPILOG = """\
exit codes:
  0  scan completed (target is Moodle) / update succeeded
  1  internal error
  2  usage error
  3  target reachable but not identified as Moodle
  4  scan failed (target unreachable) / update failed
  5  bundled data missing or unreadable
  6  scan completed partially (time budget exhausted)
"""


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="moodle-scanner",
        description="Non-destructive Moodle version, advisory and misconfiguration scanner.",
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--version", action="version", version=f"moodle-scanner {__version__}")
    p.add_argument("--url", help="base URL of the Moodle site to scan")

    data = p.add_argument_group("data update")
    data.add_argument(
        "--update", action="store_true", help="build/refresh file fingerprints from moodle/moodle git tags"
    )
    data.add_argument("--vuln", action="store_true", help="refresh security advisories from moodle.org")
    data.add_argument(
        "--update-plugins", action="store_true", help="refresh plugin list from the Moodle plugins directory"
    )
    data.add_argument("--full", action="store_true", help="with --vuln: re-read every advisory page")
    data.add_argument("--force", action="store_true", help="with --update: rebuild even if no new tags")
    data.add_argument(
        "--data-dir", type=Path, default=DATA_DIR, help="directory with fingerprints/advisories/plugins JSON"
    )
    data.add_argument("--cache-dir", type=Path, help="cache for the git tree mirror (default ~/.cache/moodle-scanner)")
    data.add_argument("--git-url", default=None, help=argparse.SUPPRESS)

    out = p.add_argument_group("output")
    out.add_argument("--json", action="store_true", help="print the JSON report to stdout (no text output)")
    out.add_argument("-o", "--output", type=Path, help="write the JSON report to this file")
    out.add_argument("--schema", action="store_true", help="print the JSON Schema of the report and exit")
    out.add_argument("--no-color", action="store_true", help="disable ANSI colours in text output")
    out.add_argument("-q", "--quiet", action="store_true", help="no banner or progress output")

    sc = p.add_argument_group("scan")
    sc.add_argument("--scan", action="store_true", help="accepted for compatibility; advisories are always matched")
    sc.add_argument("--no-checks", action="store_true", help="skip misconfiguration checks")
    sc.add_argument("--plugins", action="store_true", help="enumerate additional plugins (opt-in, many requests)")
    sc.add_argument(
        "--plugins-limit",
        type=int,
        default=200,
        help="number of plugins to probe, most recently released first (default 200, 0 = all ~3100)",
    )
    sc.add_argument("--max-fingerprint-requests", type=int, default=40, help="cap on version-detection requests")

    net = p.add_argument_group("network")
    net.add_argument(
        "--timeout", type=float, default=DEFAULT_TIMEOUT, help="per-request timeout in seconds (default 10)"
    )
    net.add_argument("--max-time", type=float, help="total time budget for the scan in seconds")
    net.add_argument("--rate", type=float, help="maximum requests per second")
    net.add_argument("--concurrency", type=int, default=4, help="parallel requests (default 4)")
    net.add_argument("--insecure", action="store_true", help="do not verify TLS certificates")
    net.add_argument("--proxy", help="HTTP(S) proxy URL, e.g. http://127.0.0.1:8080")
    net.add_argument(
        "-H", "--header", action="append", default=[], metavar="'Name: value'", help="extra request header"
    )
    net.add_argument("--user-agent", default=DEFAULT_USER_AGENT, help="User-Agent header")
    return p


def _headers(values: list[str]) -> dict[str, str]:
    headers = {}
    for raw in values:
        name, sep, value = raw.partition(":")
        if not sep or not name.strip():
            raise ValueError(f"invalid header {raw!r}; expected 'Name: value'")
        headers[name.strip()] = value.strip()
    return headers


def _client(
    args: argparse.Namespace, base_url: str, rate: float | None = None, max_body: int = DEFAULT_MAX_BODY
) -> HttpClient:
    return HttpClient(
        base_url,
        timeout=args.timeout,
        user_agent=args.user_agent,
        headers=_headers(args.header),
        rate=rate if rate is not None else args.rate,
        concurrency=args.concurrency,
        max_time=args.max_time,
        insecure=args.insecure,
        proxy=args.proxy,
        max_body=max_body,
    )


class Printer:
    COLORS = {"critical": "91", "high": "91", "medium": "93", "low": "94", "info": "0", "unknown": "0", "ok": "92"}

    def __init__(self, enabled: bool, color: bool) -> None:
        self.enabled = enabled
        self.color = color

    def __call__(self, text: str = "", level: str | None = None) -> None:
        if not self.enabled:
            return
        if level and self.color:
            text = f"\033[{self.COLORS.get(level, '0')}m{text}\033[0m"
        print(text, file=sys.stdout)


def render_text(report: dict, out: Printer) -> None:
    target = report["target"]
    out(f"Target: {target['url']}")
    if not target["reachable"]:
        for err in report["errors"]:
            out(f"  error ({err['stage']}): {err['message']}", "high")
        return
    if not target["is_moodle"]:
        out("Target does not look like Moodle.", "medium")
        return
    v = report["version"]
    if v["status"] == "exact":
        out(f"Moodle version: {v['version']} (confidence {v['confidence']})", "ok")
    elif v["status"] == "ambiguous":
        out(f"Moodle version: one of {', '.join(v['candidates'])} (confidence {v['confidence']})", "medium")
    elif v["status"] == "branch":
        out(f"Moodle branch: {v['branch']} (from public signals; confidence low)", "medium")
    else:
        out("Moodle version: unknown", "medium")
    for note in v["notes"]:
        out(f"  note: {note}")
    advisories = report["advisories"]
    if advisories:
        out(f"\nAdvisories ({len(advisories)}):")
        for adv in advisories:
            cves = ", ".join(adv["cves"]) or "no CVE"
            flag = "" if adv["match"] == "affected" else " [possible]"
            out(f"- {adv['id']} [{adv['severity_level']}] {adv['title']} ({cves}){flag}", adv["severity_level"])
            out(f"    {adv['reason']}; {adv['url']}")
    elif v["status"] != "unknown":
        out("\nNo matching advisories in the bundled data.", "ok")
    checks = report["misconfigurations"]
    detected = [c for c in checks if c["status"] == "detected"]
    if checks:
        out(f"\nMisconfigurations ({len(detected)} detected, {len(checks)} checked):")
        for c in detected:
            out(f"- [{c['severity']}] {c['title']}", c["severity"])
            for ev in c["evidence"]:
                out(f"    {ev['url']} -> {ev['status']}: {ev['detail']}")
        for c in checks:
            if c["status"] == "inconclusive":
                out(f"- [inconclusive] {c['title']}", "medium")
    plugins = report["plugins"]
    if plugins:
        out(f"\nPlugins: {len(plugins['found'])} found of {plugins['probed']} probed")
        for item in plugins["found"]:
            hint = item.get("version_hint")
            out(f"- {item['component']}" + (f" {hint['release']}" if hint else ""))
    for item in report["limitations"]:
        out(f"\nlimitation: {item}")


def run_update(args: argparse.Namespace, out: Printer) -> int:
    from .update.advisories import update_advisories  # noqa: PLC0415 - update deps only when needed
    from .update.fingerprints import MOODLE_GIT_URL, default_cache_dir, ensure_mirror, update_fingerprints
    from .update.plugins import update_plugins

    args.data_dir.mkdir(parents=True, exist_ok=True)
    cache_dir = args.cache_dir or default_cache_dir()
    git_url = args.git_url or MOODLE_GIT_URL
    token = os.environ.get("GITHUB_TOKEN") or None
    log = out if out.enabled else (lambda _msg: None)
    try:
        if args.update:
            stats = update_fingerprints(
                args.data_dir / "fingerprints.json",
                cache_dir=cache_dir,
                git_url=git_url,
                token=token,
                force=args.force,
                log=log,
            )
            out(f"fingerprints: {stats}", "ok")
        if args.vuln:
            client = _client(args, "https://moodle.org/", rate=args.rate or 2.0)
            stats = update_advisories(args.data_dir / "advisories.json", client, full=args.full, log=log)
            out(f"advisories: {stats}", "ok")
        if args.update_plugins:
            repo = ensure_mirror(cache_dir, git_url, token)
            client = _client(args, "https://download.moodle.org/", rate=args.rate or 2.0, max_body=256 * 1024 * 1024)
            stats = update_plugins(args.data_dir / "plugins.json", client, repo, log=log)
            out(f"plugins: {stats}", "ok")
    except (RuntimeError, OSError, ValueError) as exc:
        print(f"update failed: {exc}", file=sys.stderr)
        return EXIT_SCAN_FAILED
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    color = not args.no_color and sys.stdout.isatty()
    progress = Printer(enabled=not args.json and not args.quiet, color=color)
    results = Printer(enabled=not args.json, color=color)

    if args.schema:
        print(SCHEMA_PATH.read_text(encoding="utf-8"), end="")
        return EXIT_OK
    updating = args.update or args.vuln or args.update_plugins
    if not updating and not args.url:
        parser.print_help()
        return EXIT_USAGE
    progress(BANNER)
    if updating:
        code = run_update(args, progress)
        if code != EXIT_OK or not args.url:
            return code
    try:
        client = _client(args, args.url)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE
    try:
        data = DataBundle.load(args.data_dir, need_plugins=args.plugins)
    except DataError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_DATA_ERROR
    options = ScanOptions(
        checks=not args.no_checks,
        plugins=args.plugins,
        plugins_limit=args.plugins_limit,
        max_fingerprint_requests=args.max_fingerprint_requests,
    )
    try:
        report = scan(client, data, options)
    except Exception as exc:  # noqa: BLE001 - map any bug to the documented exit code 1
        traceback.print_exc(file=sys.stderr)
        print(f"internal error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return EXIT_INTERNAL
    payload = json.dumps(report, indent=2, ensure_ascii=False) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(payload, encoding="utf-8")
    if args.json:
        sys.stdout.write(payload)
    else:
        render_text(report, results)
    return report["exit_code"]
