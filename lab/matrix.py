"""Expected-vs-actual validation matrix for the lab scans.

Ground truth per instance comes from ``lab/results/<name>.truth.json`` (git tag
and Moodle settings read back with ``admin/cli/cfg.php`` after seeding).

Advisory expectations use an oracle that is deliberately independent of the
scanner's range matcher: it reads the raw "Versions fixed" text and the raw
"Versions affected" text of every advisory and decides from the fix list
(a version is affected when a fix for its branch exists and is newer, or when
its branch received no fix, is older than the newest fixed branch and the
advisory says "earlier/other unsupported versions"). Disagreements are listed
for manual review instead of being silently counted.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from moodle_scanner.versions import MoodleVersion  # noqa: E402

CHECK_IDS = [
    "self_registration",
    "guest_login",
    "web_services",
    "debug_display",
    "dataroot_exposed",
    "vcs_exposed",
    "config_backup_exposed",
    "dev_files_exposed",
    "install_upgrade_exposed",
]
_VER_RE = re.compile(r"\d+\.\d+(?:\.\d+)?")
_RANGE_RE = re.compile(r"(\d+\.\d+(?:\.\d+)?)\+?\s*(?:to|-)\s*(\d+\.\d+(?:\.\d+)?)")


def expected_checks(truth: dict) -> dict[str, bool]:
    seeds = set(truth["seeds"])
    return {
        "self_registration": truth["registerauth"] == "email" and "email" in truth["auth"].split(","),
        "guest_login": truth["guestloginbutton"] == "1",
        "web_services": truth["enablewebservices"] == "1",
        "debug_display": truth["debugdisplay"] == "1" and int(truth["debug"] or 0) > 0,
        "dataroot_exposed": "moodledata" in seeds,
        "vcs_exposed": "git" in seeds,
        "config_backup_exposed": "configbackup" in seeds,
        "dev_files_exposed": not truth["hardened"],
        "install_upgrade_exposed": False,
    }


def oracle_affected(adv: dict, version: MoodleVersion) -> bool | None:
    """Independent reading of one advisory; None when the text has no versions.

    Lower bounds: "X.Y to X.Y.Z" starts at X.Y.0; a lone "X.Y.Z" means the
    issue was introduced in that release (regressions such as MSA-25-0037).
    """
    affected_text = re.sub(r"\([^)]*\)", " ", adv["affected_text"].lower())
    fixed = [MoodleVersion.parse(v) for v in _VER_RE.findall(adv["fixed_text"])]
    listed = [MoodleVersion.parse(v) for v in _VER_RE.findall(affected_text)]
    if not listed:
        return None
    lower_bounds = [MoodleVersion.parse(lo) for lo, _ in _RANGE_RE.findall(affected_text)]
    singles_text = _RANGE_RE.sub(" ", affected_text)
    lower_bounds += [MoodleVersion.parse(v) for v in re.findall(r"\d+\.\d+\.\d+", singles_text)]
    branch_lower = [lb for lb in lower_bounds if lb.branch == version.branch]
    if branch_lower and version.release < min(branch_lower).release:
        return False
    same_branch_fix = [f for f in fixed if f.branch == version.branch]
    if same_branch_fix:
        if version.release >= min(same_branch_fix).release:
            return False
        return any(v.branch == version.branch for v in listed)
    if any(v.branch == version.branch for v in listed):
        # Branch listed but no fix for it (e.g. "2.4" with fix 2.4.1 missing).
        return True
    if "unsupported" in affected_text or "earlier" in affected_text:
        newest = max(v.branch for v in listed + fixed)
        return version.branch < newest
    return False


def _mark(ok: bool) -> str:
    return "yes" if ok else "**NO**"


def _validate_schema(report: dict) -> str:
    try:
        import jsonschema  # noqa: PLC0415 - dev dependency
    except ImportError:
        return "not checked (jsonschema not installed)"
    schema = json.loads((ROOT / "moodle_scanner" / "schema" / "scan-result.schema.json").read_text())
    validator = jsonschema.Draft202012Validator(schema, format_checker=jsonschema.FormatChecker())
    errors = sorted(validator.iter_errors(report), key=lambda e: list(e.path))
    if not errors:
        return "valid"
    return "INVALID: " + "; ".join(f"{list(e.path)}: {e.message}" for e in errors[:3])


def build_matrix(instances: list[dict], results: Path) -> str:
    advisories = json.loads((ROOT / "moodle_scanner" / "data" / "advisories.json").read_text())["advisories"]
    summary = []
    sections = []
    for inst in instances:
        name = inst["name"]
        report_path = results / f"{name}.json"
        truth_path = results / f"{name}.truth.json"
        if not report_path.exists() or not truth_path.exists():
            summary.append(f"| {name} | {inst['tag']} | not scanned | | | | | |")
            continue
        report = json.loads(report_path.read_text())
        truth = json.loads(truth_path.read_text())
        exit_code = (results / f"{name}.exit").read_text().strip() if (results / f"{name}.exit").exists() else "?"
        expected_version = MoodleVersion.parse(truth["tag"])
        v = report["version"] or {}
        version_ok = v.get("version") == str(expected_version)
        schema = _validate_schema(report)

        reported = {a["id"]: a for a in report["advisories"]}
        oracle = {}
        for adv in advisories:
            verdict = oracle_affected(adv, expected_version)
            if verdict:
                oracle[adv["id"]] = adv
        missing = sorted(set(oracle) - set(reported))
        extra = sorted(set(reported) - set(oracle))
        possible = sorted(i for i, a in reported.items() if a["match"] != "affected")

        checks = {c["id"]: c for c in report["misconfigurations"]}
        expected = expected_checks(truth)
        check_rows = []
        check_ok = 0
        for cid in CHECK_IDS:
            got = checks.get(cid, {}).get("status")
            exp = expected[cid]
            ok = (got == "detected") == exp
            check_ok += ok
            check_rows.append(f"| {cid} | {'detected' if exp else 'absent'} | {got} | {_mark(ok)} |")

        plugin_expected = set(truth.get("plugins", []))
        found = {p["component"] for p in (report.get("plugins") or {}).get("found", [])}
        plugins_missing = sorted(plugin_expected - found)
        plugins_extra = sorted(found - plugin_expected)

        summary.append(
            f"| {name} | {truth['tag']} | {v.get('version')} ({v.get('confidence')}) {_mark(version_ok)} "
            f"| {len(reported)} / {len(oracle)} | {len(missing)} / {len(extra)} "
            f"| {check_ok}/{len(CHECK_IDS)} | {len(found & plugin_expected)}/{len(plugin_expected)}, FP {len(plugins_extra)} "
            f"| {schema.split(':')[0]} | {exit_code} |"
        )
        lines = [
            f"### {name} — Moodle {truth['tag']}" + (" (hardened negative control)" if truth["hardened"] else ""),
            "",
            f"- Seeds: {', '.join(truth['seeds']) or 'none (Moodle defaults)'}; settings read back: "
            + ", ".join(
                f"{k}={truth[k]!r}"
                for k in (
                    "auth",
                    "registerauth",
                    "guestloginbutton",
                    "enablewebservices",
                    "enablemobilewebservice",
                    "debug",
                    "debugdisplay",
                )
            ),
            f"- Version: expected `{expected_version}`, reported `{v.get('version')}` status `{v.get('status')}` "
            f"candidates `{', '.join(v.get('candidates', []))}` confidence `{v.get('confidence')}` -> {_mark(version_ok)}",
            f"- Requests: {report['requests']}; duration {report['duration_seconds']} s; exit code {exit_code}; JSON schema: {schema}",
            f"- Advisories: reported {len(reported)} ({len(possible)} possibly-affected), oracle {len(oracle)}; "
            f"missing {missing or 'none'}; extra {extra or 'none'}",
            f"- Spot check CVE-2025-32044 (MSA-25-0011, affects 4.5.0 to 4.5.2): expected "
            f"{'reported' if (4, 5, 0) <= expected_version.release <= (4, 5, 2) else 'not reported'}, actual "
            f"{'reported' if any('CVE-2025-32044' in a['cves'] for a in reported.values()) else 'not reported'}",
            f"- Plugins: expected {sorted(plugin_expected) or 'none'}; found {sorted(found) or 'none'}; "
            f"missing {plugins_missing or 'none'}; false positives {plugins_extra or 'none'}",
            "",
            "| check | expected | reported | correct |",
            "|---|---|---|---|",
            *check_rows,
            "",
        ]
        sections.append("\n".join(lines))
    header = [
        "# Lab validation matrix",
        "",
        "Generated by `uv run python lab/lab.py matrix` from the JSON reports in `lab/results/`.",
        "Do not edit by hand; rerun the lab instead (see [lab.md](lab.md)).",
        "",
        "Advisory columns: `reported / oracle` counts, then `missing / extra` relative to the oracle described in",
        "`lab/matrix.py` (an independent reading of the moodle.org fixed-version lists).",
        "",
        "| instance | tag | detected version | advisories reported / oracle | missing / extra | misconfig checks correct | plugins found, FP | schema | exit |",
        "|---|---|---|---|---|---|---|---|---|",
        *summary,
        "",
        "## Per instance",
        "",
    ]
    return "\n".join(header + sections)
