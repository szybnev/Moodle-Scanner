"""Scan orchestration: one target in, one JSON-serialisable report out."""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .advisories import Advisory, assess_candidates, load_advisories
from .checks import run_checks
from .fingerprints import Detector, FingerprintDB, apply_signals, branch_signals
from .httpclient import HttpClient, Response
from .plugins import PluginDB, enumerate_plugins
from .versions import MoodleVersion

SCHEMA_VERSION = "2.0"
DATA_DIR = Path(__file__).resolve().parent / "data"
SCHEMA_PATH = Path(__file__).resolve().parent / "schema" / "scan-result.schema.json"

EXIT_OK = 0
EXIT_INTERNAL = 1
EXIT_USAGE = 2
EXIT_NOT_MOODLE = 3
EXIT_SCAN_FAILED = 4
EXIT_DATA_ERROR = 5
EXIT_PARTIAL = 6

_MARKERS = [
    (
        "moodle-session-cookie",
        lambda r: re.search(r"(?:^|[;,]\s*)MoodleSession(?:[A-Za-z0-9_-]*)?=", r.headers.get("set-cookie", ""), re.I)
        is not None,
    ),
    ("m-cfg-script", lambda r: re.search(r"\bM\.cfg\s*=", r.text) is not None),
    (
        "moodle-asset-urls",
        lambda r: re.search(r"/(?:theme/(?:yui_combo|styles|image)|lib/javascript)\.php", r.text) is not None,
    ),
    ("moodle-keywords-meta", lambda r: re.search(r'<meta name="keywords" content="moodle', r.text, re.I) is not None),
]


class DataError(Exception):
    """Bundled data files are missing or unreadable."""


@dataclass
class DataBundle:
    fingerprints: FingerprintDB
    advisories: list[Advisory]
    advisories_meta: dict
    plugins: PluginDB | None

    @classmethod
    def load(cls, data_dir: Path, need_plugins: bool) -> DataBundle:
        try:
            fingerprints = FingerprintDB.load(data_dir / "fingerprints.json")
            advisories = load_advisories(data_dir / "advisories.json")
            meta_raw = json.loads((data_dir / "advisories.json").read_text(encoding="utf-8"))
            plugins = PluginDB.load(data_dir / "plugins.json") if need_plugins else None
        except FileNotFoundError as exc:
            raise DataError(f"data file missing: {exc.filename} (run --update / --vuln)") from exc
        except (ValueError, KeyError) as exc:
            raise DataError(f"data file unreadable: {exc}") from exc
        meta = {"count": meta_raw.get("count"), "latest_published": meta_raw.get("latest_published")}
        return cls(fingerprints, advisories, meta, plugins)


@dataclass
class ScanOptions:
    checks: bool = True
    plugins: bool = False
    plugins_limit: int = 200
    max_fingerprint_requests: int = 40


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _markers(pages: list[Response]) -> list[str]:
    found = []
    for name, test in _MARKERS:
        if any(r.status is not None and r.status < 400 and not r.truncated and test(r) for r in pages):
            found.append(name)
    return found


def _advisory_entry(adv: Advisory, status: str, reason: str) -> dict:
    return {
        "id": adv.id,
        "title": adv.title,
        "published": adv.published,
        "severity": adv.severity,
        "severity_level": adv.severity_level,
        "cves": list(adv.cves),
        "trackers": list(adv.trackers),
        "url": adv.url,
        "affected": [str(r) for r in adv.ranges],
        "excluded": [str(r) for r in adv.excluded],
        "earlier_unsupported": adv.earlier_unsupported,
        "fixed": list(adv.fixed),
        "match": "version_match" if status == "affected" else "possible_version_match",
        "evidence_level": "version_only",
        "reason": reason,
    }


_LEVEL_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}


def match_advisories(
    advisories: list[Advisory], candidates: list[MoodleVersion], *, uncertain_version: bool = False
) -> list[dict]:
    out = []
    for adv in advisories:
        hit = assess_candidates(adv, candidates)
        if hit:
            status = "possibly_affected" if uncertain_version else hit.status
            reason = hit.reason
            if uncertain_version:
                reason += "; installed release is not established: patched or unlisted builds may be present"
            out.append(_advisory_entry(adv, status, reason))
    out.sort(key=lambda a: (a["match"] != "version_match", _LEVEL_ORDER[a["severity_level"]], a["published"]))
    return out


def scan(client: HttpClient, data: DataBundle, options: ScanOptions) -> dict:
    started = time.monotonic()
    started_at = _now()
    errors: list[dict] = []
    limitations: list[str] = []

    home = client.get("/", follow_redirects=True)
    login = client.get("/login/index.php", follow_redirects=True)
    pages = [home, login]
    reachable = any(r.status is not None for r in pages)
    report: dict = {
        "schema_version": SCHEMA_VERSION,
        "scanner": {"name": "moodle-scanner", "version": __version__},
        "target": {"url": client.base_url, "reachable": reachable, "is_moodle": False, "markers": []},
        "started_at": started_at,
        "data": {
            "fingerprints_latest_tag": data.fingerprints.latest_tag,
            "fingerprint_tags": len(data.fingerprints.tags),
            "fingerprint_files": len(data.fingerprints.files),
            "advisories_count": data.advisories_meta.get("count"),
            "advisories_latest_published": data.advisories_meta.get("latest_published"),
        },
        "version": None,
        "advisories": [],
        "misconfigurations": [],
        "observations": [],
        "plugins": None,
        "errors": errors,
        "limitations": limitations,
    }
    if not reachable:
        errors.append({"stage": "connect", "message": home.error or login.error or "no response"})
        return _finish(report, client, started, EXIT_SCAN_FAILED)

    markers = _markers(pages)
    detector = Detector(client, data.fingerprints, max_requests=options.max_fingerprint_requests)
    result = detector.run()
    result = apply_signals(result, branch_signals(client, pages))
    matched_files = sum(1 for e in result.evidence if e.outcome == "match")
    is_moodle = (matched_files >= 2 and result.status != "unknown") or ("m-cfg-script" in markers and len(markers) >= 2)
    report["target"].update({"is_moodle": is_moodle, "markers": markers})
    report["version"] = result.to_json()
    if not is_moodle:
        return _finish(report, client, started, EXIT_NOT_MOODLE)

    if result.status in ("exact", "ambiguous"):
        candidates = result.candidate_versions
    elif result.status == "branch" and result.branch:
        candidates = [
            v for v in (MoodleVersion.parse(t) for t in data.fingerprints.tags) if v.branch_str == result.branch
        ]
        limitations.append(
            f"only the branch ({result.branch}) is known; {len(candidates)} bundled releases are considered "
            "as candidates, not an exhaustive list of possible installations. All matches are "
            "'possible_version_match'; a newer patched release may be installed."
        )
    else:
        candidates = []
        limitations.append("version unknown: advisories not matched")
    if candidates:
        report["advisories"] = match_advisories(
            data.advisories,
            candidates,
            uncertain_version=result.status != "exact" or result.confidence != "high",
        )
        if report["advisories"]:
            limitations.append(
                "advisories are version-only correlations, not verified vulnerabilities: "
                "authentication, enabled components, configuration and backported fixes were not checked"
            )
        unparsed = sum(1 for a in data.advisories if a.parse_status == "unparsed")
        if unparsed:
            limitations.append(
                f"{unparsed} advisories (pre-2017, Moodle <= 3.0 era) have no machine-readable version range"
            )
        newest = max(candidates)
        latest = MoodleVersion.parse(data.fingerprints.latest_tag)
        if newest.release >= latest.release:
            limitations.append(
                f"detected version is at or beyond the newest release in the bundled data ({latest}); "
                "advisories published after the data refresh are not known"
            )

    if options.checks:
        for check in run_checks(client):
            key = "observations" if check.kind == "observation" else "misconfigurations"
            report[key].append(check.to_json())
    if options.plugins:
        if data.plugins is None:
            errors.append({"stage": "plugins", "message": "plugin data not loaded"})
        else:
            report["plugins"] = enumerate_plugins(client, data.plugins, options.plugins_limit, result.branch).to_json()
    code = EXIT_PARTIAL if client.budget_exhausted else EXIT_OK
    if client.budget_exhausted:
        limitations.append("time budget exhausted; results are partial")
    return _finish(report, client, started, code)


def _finish(report: dict, client: HttpClient, started: float, code: int) -> dict:
    report["finished_at"] = _now()
    report["duration_seconds"] = round(time.monotonic() - started, 3)
    report["requests"] = client.request_count
    report["exit_code"] = code
    return report
