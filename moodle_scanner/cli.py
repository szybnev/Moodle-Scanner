"""Command line interface (``moodle-scanner`` / ``python scanner.py``)."""

from __future__ import annotations

import argparse
import json
import os
import sys
import textwrap
import traceback
from pathlib import Path
from urllib.parse import urlsplit

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
    out.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="include all advisory candidates, version evidence and probe details",
    )

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


_CHECK_LABELS = {
    "self_registration": "Self-registration",
    "guest_login": "Guest login",
    "web_services": "Web services",
    "debug_display": "Debug traces",
    "dataroot_exposed": "Dataroot files",
    "vcs_exposed": "VCS metadata",
    "config_backup_exposed": "Configuration backups",
    "dev_files_exposed": "Public development files",
    "install_upgrade_exposed": "Installer / upgrade pages",
}


def _wrapped(out: Printer, text: str, indent: str = "  ") -> None:
    for line in textwrap.wrap(
        text, width=100, initial_indent=indent, subsequent_indent=indent, break_long_words=False, break_on_hyphens=False
    ):
        out(line)


def _probe_lines(out: Printer, check: dict, *, verbose: bool) -> None:
    for evidence in check["evidence"]:
        url = evidence["url"]
        if not verbose:
            parts = urlsplit(url)
            url = parts.path + (f"?{parts.query}" if parts.query else "")
        status = f"HTTP {evidence['status']}" if evidence["status"] is not None else "no response"
        _wrapped(out, f"{status}  {url}", "    ")
        if verbose:
            _wrapped(out, evidence["detail"], "      ")


def render_text(report: dict, out: Printer, *, verbose: bool = False) -> None:
    target = report["target"]
    out(f"Target: {target['url']}")
    run_status = "completed" if report["exit_code"] == 0 else "partial" if report["exit_code"] == 6 else "not completed"
    out(f"Run: {run_status} | {report['requests']} requests | {report['duration_seconds']:.1f}s")
    if not target["reachable"]:
        for err in report["errors"]:
            _wrapped(out, f"error ({err['stage']}): {err['message']}")
        return
    if not target["is_moodle"]:
        out("Moodle was not identified; no vulnerability assessment was completed.", "medium")
        return
    version = report["version"]
    if version["status"] == "exact":
        out(f"Version: {version['version']} (fingerprint match; confidence {version['confidence']})")
    elif version["status"] == "ambiguous":
        branches = sorted(
            {".".join(v.split(".")[:2]) for v in version["candidates"]},
            key=lambda b: tuple(int(p) for p in b.split(".")),
        )
        branch_text = ", ".join(branches[:6]) + (f" and {len(branches) - 6} more" if len(branches) > 6 else "")
        _wrapped(
            out,
            f"Version: unresolved; {len(version['candidates'])} candidate releases across branches "
            f"{branch_text} (confidence {version['confidence']})",
            "",
        )
        if any(e["outcome"] == "conflict" for e in version["evidence"]):
            out("  Fingerprints conflict; none of these releases is established as the installed version.")
    elif version["status"] == "branch":
        out(f"Version: only branch {version['branch']} identified; patch level unknown (confidence low)")
    else:
        out("Version: unknown; version-based advisory matching unavailable.", "medium")

    checks = report["misconfigurations"]
    observations = report["observations"]
    findings = [c for c in checks if c["status"] == "detected"]
    observed = [c for c in observations if c["status"] == "detected"]
    unresolved = [c for c in checks + observations if c["status"] == "inconclusive"]
    advisories = report["advisories"]
    plugins = report["plugins"]
    out("\nSUMMARY")
    out(f"  Observed exposure findings: {len(findings)}" if checks else "  Exposure checks: not run")
    out(f"  Checks without a verdict:  {len(unresolved)} / {len(checks) + len(observations)}")
    out(f"  Configuration observations: {len(observed)} (not vulnerabilities)")
    out(f"  Advisory hypotheses:       {len(advisories)} (not verified on the target)")
    out(
        f"  Plugins corroborated:      {len(plugins['found'])}"
        if plugins
        else "  Plugin enumeration:        not requested"
    )

    out("\nOBSERVED EXPOSURES")
    if not findings:
        out("  None confirmed by these checks." if checks else "  Not checked.")
    for check in sorted(findings, key=lambda c: ("critical", "high", "medium", "low", "info").index(c["severity"])):
        _wrapped(out, f"[{check['severity'].upper()}] {check['title']}")
        _probe_lines(out, check, verbose=True)
        _wrapped(out, f"Action: {check['recommendation']}", "    ")

    if observed:
        out("\nCONFIGURATION OBSERVATIONS (not vulnerabilities)")
        for check in observed:
            out(f"  {_CHECK_LABELS.get(check['id'], check['title'])}")
            _probe_lines(out, check, verbose=verbose)
            if verbose:
                _wrapped(out, check["recommendation"], "    ")

    if unresolved:
        out("\nCHECKS WITHOUT A VERDICT (not findings, not proof of safety)")
        for check in unresolved:
            reasons = list(dict.fromkeys(e["detail"] for e in check["evidence"]))
            codes = sorted({e["status"] for e in check["evidence"] if e["status"] is not None})
            status = "HTTP " + "/".join(str(c) for c in codes) if codes else "no response"
            _wrapped(
                out,
                f"{_CHECK_LABELS.get(check['id'], check['title'])}: {status}; "
                + ("; ".join(reasons) or "insufficient evidence"),
            )
            if verbose:
                _probe_lines(out, check, verbose=True)

    if plugins:
        out(f"\nPLUGINS ({len(plugins['found'])} corroborated; {plugins['probed']} probes)")
        for item in plugins["found"]:
            hint = item.get("version_hint")
            out(f"  {item['component']}" + (f" (release hint: {hint['release']})" if hint else ""))
        if plugins["notes"]:
            if verbose:
                for note in plugins["notes"]:
                    _wrapped(out, note)
            else:
                out("  Coverage is incomplete; missing from the list does not prove absence. Details: --verbose.")

    if advisories:
        certain = sum(a["match"] == "version_match" for a in advisories)
        out("\nVERSION-ONLY ADVISORIES")
        out(f"  {certain} version matches; {len(advisories) - certain} possible matches.")
        if not verbose:
            out("  Candidate list omitted from the summary. Use --verbose or --json for every record.")

    if verbose:
        out("\nVERSION EVIDENCE")
        if version["candidates"]:
            _wrapped(out, "Candidates: " + ", ".join(version["candidates"]))
        for note in version["notes"]:
            _wrapped(out, note)
        for ev in version["evidence"]:
            _wrapped(
                out,
                f"{ev['path']}: {ev['outcome']} (HTTP {ev['status']}); "
                + ev.get("matched_versions", ev.get("error", "")),
            )
        for adv in advisories:
            cves = ", ".join(adv["cves"]) or "no CVE"
            flag = "version match" if adv["match"] == "version_match" else "possible version match"
            _wrapped(out, f"{adv['id']} | {cves} | {flag} | advisory severity: {adv['severity_level']}", "")
            _wrapped(out, adv["title"])
            _wrapped(out, f"{adv['reason']}; {adv['url']}")

    if report["errors"]:
        out("\nERRORS")
        for error in report["errors"]:
            _wrapped(out, f"{error['stage']}: {error['message']}")
    if report["limitations"]:
        out("\nLIMITATIONS")
        for limitation in report["limitations"]:
            _wrapped(out, limitation)
    if not verbose:
        out("\nFull details: --verbose | Full structured report: --json or -o FILE")


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
    progress(f"Moodle-Scanner {__version__}")
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
        render_text(report, results, verbose=args.verbose)
        if args.output:
            results(f"JSON report saved: {args.output}")
    return report["exit_code"]
