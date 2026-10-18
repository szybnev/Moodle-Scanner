"""Validate reports against seeded exposure and independently documented cases.

Do not derive an advisory oracle from the same bundled version lists as the
scanner: agreement between two parsers does not establish exploitability.
"""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OBSERVATION_IDS = {"self_registration", "guest_login", "web_services", "dev_files_exposed"}

# Manually reviewed CNA source, NOT derived from the scanner database:
# https://cveawg.mitre.org/api/cve/CVE-2025-32044
# 4.5.0..4.5.2 is the affected RELEASE range. The target is not affected when
# zend.exception_ignore_args=1, so even a range match is not vulnerability proof.
REST_RANGE_EXPECTED = {"m311": False, "m401": False, "m405": True, "m500": False, "m503": False}


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


def _validate_schema(report: dict) -> str:
    import jsonschema

    schema = json.loads((ROOT / "moodle_scanner/schema/scan-result.schema.json").read_text())
    errors = list(
        jsonschema.Draft202012Validator(schema, format_checker=jsonschema.FormatChecker()).iter_errors(report)
    )
    return "valid" if not errors else "INVALID: " + "; ".join(e.message for e in errors[:3])


def build_matrix(instances: list[dict], results: Path) -> str:
    summary, sections, failures = [], [], []
    for inst in instances:
        name = inst["name"]
        report_path, truth_path = results / f"{name}.json", results / f"{name}.truth.json"
        if not report_path.exists() or not truth_path.exists():
            failures.append(f"{name}: report or ground truth missing")
            continue
        report = json.loads(report_path.read_text())
        truth = json.loads(truth_path.read_text())
        expected_version = truth["tag"].removeprefix("v")
        version = report["version"] or {}
        candidates = version.get("candidates", [])
        version_ok = (
            version.get("version") == expected_version
            if version.get("status") == "exact"
            else version.get("status") == "ambiguous" and expected_version in candidates
        )
        if not version_ok:
            failures.append(f"{name}: expected release {expected_version} not represented correctly")
        schema = _validate_schema(report)
        if schema != "valid" or report["exit_code"] != 0:
            failures.append(f"{name}: schema={schema}, exit={report['exit_code']}")
        advisories = report["advisories"]
        if any(
            a.get("evidence_level") != "version_only" or a["match"] not in {"version_match", "possible_version_match"}
            for a in advisories
        ):
            failures.append(f"{name}: advisory presented without version-only evidence qualification")
        rest_matches = [a for a in advisories if "CVE-2025-32044" in a["cves"]]
        rest_ok = bool(rest_matches) == REST_RANGE_EXPECTED[name]
        if not rest_ok:
            failures.append(f"{name}: CVE-2025-32044 release-range match incorrect")
        checks = {c["id"]: c for c in report["misconfigurations"] + report["observations"]}
        expected = expected_checks(truth)
        check_rows, correct, inconclusive = [], 0, 0
        for cid, present in expected.items():
            result = checks.get(cid, {})
            expected_kind = "observation" if cid in OBSERVATION_IDS else "finding"
            kind_ok = result.get("kind") == expected_kind
            status_ok = result.get("status") == ("detected" if present else "not_detected")
            ok = kind_ok and status_ok
            correct += ok
            unknown = kind_ok and result.get("status") == "inconclusive"
            inconclusive += unknown
            if not ok and not (unknown and not present):
                failures.append(
                    f"{name}: {cid} expected {expected_kind}/{present}, got {result.get('kind')}/{result.get('status')}"
                )
            verdict = "yes" if ok else "coverage gap" if unknown and not present else "**NO**"
            check_rows.append(
                f"| {cid} | {expected_kind} | {'present' if present else 'absent'} | {result.get('status')} | {verdict} |"
            )
        findings = [c for c in report["misconfigurations"] if c["status"] == "detected"]
        if truth["hardened"] and findings:
            failures.append(f"{name}: finding on hardened control")
        plugins_expected = set(truth.get("plugins", []))
        found = {p["component"] for p in (report.get("plugins") or {}).get("found", [])}
        extra, missed = found - plugins_expected, plugins_expected - found
        if extra:
            failures.append(f"{name}: false-positive plugins {sorted(extra)}")
        # Missing plugin corroboration is an explicit coverage gap, not a reason
        # to restore the old empty-200 presence heuristic.
        summary.append(
            f"| {name} | {expected_version} | {version.get('status')}: {version.get('version') or ', '.join(candidates)} "
            f"| {len(advisories)} | {len(findings)} | {correct}/{len(expected)}, inconclusive {inconclusive} "
            f"| {len(found & plugins_expected)}/{len(plugins_expected)}, FP {len(extra)} | {schema} |"
        )
        sections += [
            f"### {name}",
            "",
            f"- Release identity: {'accepted' if version_ok else '**FAIL**'}; confidence {version.get('confidence')}.",
            f"- CVE-2025-32044 release-range case: {'pass' if rest_ok else '**FAIL**'}; target exploitation **not tested**.",
            f"- {len(advisories)} version-only advisory candidates; not a count of confirmed vulnerabilities.",
            f"- Requests: {report['requests']}; duration: {report['duration_seconds']} s; exit: {report['exit_code']}.",
            f"- Installed plugins: {sorted(plugins_expected)}; corroborated: {sorted(found)}; coverage gaps: {sorted(missed)}.",
            "",
            "| Check | Classification | Ground truth | Result | Correct |",
            "|---|---|---|---|---|",
            *check_rows,
            "",
        ]
    return (
        "\n".join(
            [
                "# Lab validation matrix",
                "",
                "Generated by `uv run python lab/lab.py matrix`; reports are in `lab/results/`.",
                "The previous count-based advisory oracle was withdrawn: it reused the same source facts and unsupported-version assumptions as the scanner.",
                "This matrix checks seeded HTTP exposure and observations separately. Advisory counts are NOT an FP metric or proof of exploitability.",
                "CVE-2025-32044 is a manually reviewed release-range control using the [CNA record](https://cveawg.mitre.org/api/cve/CVE-2025-32044); PHP configuration can prevent the vulnerability on a matching release.",
                "Public static files may not distinguish an rc from a final release; preserving both candidates is correct, selecting one is not.",
                "Plugin coverage gaps are reported rather than inferring installation from an empty HTTP 200 response.",
                "",
                "An inconclusive negative control is a coverage gap, not a verified absence or a false positive. Missing a seeded positive remains a validation failure.",
                "Validation: " + ("**FAIL**" if failures else "PASS (only the cases documented below)"),
                *[f"- {f}" for f in failures],
                "",
                "| Instance | Installed | Reported candidates | Advisory hypotheses | Exposure findings | Checks correct | Plugins / installed, FP | Schema |",
                "|---|---|---|---:|---:|---|---|---|",
                *summary,
                "",
                *sections,
            ]
        )
        + "\n"
    )
