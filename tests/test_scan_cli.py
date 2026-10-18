"""End-to-end scans through the CLI against a local replay server."""

from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest

from moodle_scanner.cli import main
from moodle_scanner.scan import SCHEMA_PATH

from .support import Reply, serve_version

SCHEMA = json.loads(SCHEMA_PATH.read_text())


def run_scan(site, data_dir: Path, tmp_path: Path, *extra: str) -> tuple[int, dict]:
    out = tmp_path / "report.json"
    code = main(["--url", site.url, "--json", "-o", str(out), "--data-dir", str(data_dir), *extra])
    report = json.loads(out.read_text())
    jsonschema.Draft202012Validator(SCHEMA, format_checker=jsonschema.FormatChecker()).validate(report)
    assert report["exit_code"] == code
    return code, report


def detected(report: dict) -> set[str]:
    return {c["id"] for c in report["misconfigurations"] if c["status"] == "detected"}


def test_exact_version_and_cve_2025_32044(site, data_dir, tmp_path):
    serve_version(site, "v4.5.1")
    code, report = run_scan(site, data_dir, tmp_path)
    assert code == 0
    assert report["version"]["status"] == "exact" and report["version"]["version"] == "4.5.1"
    ids = {a["id"]: a for a in report["advisories"]}
    assert ids["MSA-25-0011"]["match"] == "version_match"
    assert "CVE-2025-32044" in ids["MSA-25-0011"]["cves"]
    assert "MSA-24-0040" not in ids  # 4.5 is newer than every listed branch


def test_hardened_site_has_no_findings(site, data_dir, tmp_path):
    serve_version(site, "v5.3.0", blocked=("/lib/upgrade.txt",))
    code, report = run_scan(site, data_dir, tmp_path)
    assert code == 0
    assert "5.3.0" in report["version"]["candidates"]
    assert detected(report) == set()


def test_prerelease_twin_does_not_guess_final_release(site, data_dir, tmp_path):
    serve_version(site, "v5.3.0")
    _, report = run_scan(site, data_dir, tmp_path)
    v = report["version"]
    assert v["candidates"] == ["5.3.0-rc2", "5.3.0"]
    assert v["status"] == "ambiguous" and v["version"] is None


def test_regression_no_hash_match_is_unknown_not_indexerror(site, data_dir, tmp_path):
    # Upstream: sorted_versions[0] on an empty list -> IndexError.
    site.load("moodle_pages")
    site.add("/lib/javascript-static.js", Reply(200, b"locally modified file"))
    code, report = run_scan(site, data_dir, tmp_path)
    assert code == 0  # still Moodle (M.cfg + MoodleSession markers)
    assert report["version"]["status"] == "unknown"
    assert report["advisories"] == []
    assert any("version unknown" in item for item in report["limitations"])


def test_branch_fallback_from_upgrade_notes(site, data_dir, tmp_path):
    site.load("moodle_pages")
    site.add("/lib/upgrade.txt", Reply(200, "=== 4.5 ===\ncustomised by the site\n"))
    _, report = run_scan(site, data_dir, tmp_path)
    v = report["version"]
    assert v["status"] == "branch" and v["branch"] == "4.5" and v["method"] == "public-signals"
    # Bundled releases are not exhaustive: a newer patched release may be installed.
    assert {a["id"]: a["match"] for a in report["advisories"]} == {"MSA-25-0011": "possible_version_match"}


def test_not_moodle_exit_code(site, data_dir, tmp_path):
    site.add("/", Reply(200, "<html><body>Welcome to nginx</body></html>"))
    code, report = run_scan(site, data_dir, tmp_path)
    assert code == 3 and report["target"]["is_moodle"] is False


def test_unreachable_exit_code(data_dir, tmp_path):
    out = tmp_path / "r.json"
    code = main(
        ["--url", "http://127.0.0.1:9/", "--json", "-o", str(out), "--data-dir", str(data_dir), "--timeout", "1"]
    )
    report = json.loads(out.read_text())
    assert code == 4 and report["target"]["reachable"] is False and report["errors"]


def test_missing_data_exit_code(site, tmp_path, capsys):
    code = main(["--url", site.url, "--json", "--data-dir", str(tmp_path / "empty")])
    assert code == 5
    assert "data file missing" in capsys.readouterr().err


def test_misconfigurations_detected(site, data_dir, tmp_path):
    serve_version(site, "v4.5.1")
    site.load("misconfigured")
    _, report = run_scan(site, data_dir, tmp_path)
    assert detected(report) == {
        "debug_display",
        "dataroot_exposed",
        "vcs_exposed",
        "config_backup_exposed",
    }
    config = next(c for c in report["misconfigurations"] if c["id"] == "config_backup_exposed")
    text = json.dumps(config)
    assert "dbpass" in text and "not-a-real-secret" not in text  # setting names only, never values


def test_scanner_only_sends_get_or_head(site, data_dir, tmp_path):
    serve_version(site, "v4.5.1")
    site.load("misconfigured")
    run_scan(site, data_dir, tmp_path, "--plugins")
    assert {method for method, _, _ in site.requests} <= {"GET", "HEAD"}


def test_plugins_enumeration_skips_core_and_requires_component_evidence(site, data_dir, tmp_path):
    serve_version(site, "v4.5.1")
    site.load("misconfigured")
    site.add("/blocks/xp/version.php", Reply(200, b""))
    site.add("/mod/chat/version.php", Reply(200, b""))  # core in 4.5: must not be reported
    site.add("/blocks/xp/CHANGES.md", Reply(200, "# block_xp\n\n## 21.0\n- changes\n"))
    _, report = run_scan(site, data_dir, tmp_path, "--plugins")
    found = {p["component"]: p for p in report["plugins"]["found"]}
    assert set(found) == {"block_xp", "mod_customcert"}
    assert found["block_xp"]["version_hint"]["release"] == "21.0"


def test_plugins_skipped_on_catch_all_site(site, data_dir, tmp_path):
    serve_version(site, "v4.5.1")
    site.default = Reply(200, b"")
    _, report = run_scan(site, data_dir, tmp_path, "--plugins", "--no-checks")
    assert report["plugins"]["found"] == []


def test_regression_requests_time_out(site, data_dir, tmp_path):
    # Upstream called requests.get() without a timeout and could hang forever.
    serve_version(site, "v4.5.1")
    site.add("/login/signup.php", Reply(200, "slow", delay=3))
    _, report = run_scan(site, data_dir, tmp_path, "--timeout", "0.5")
    signup = next(c for c in report["observations"] if c["id"] == "self_registration")
    assert signup["status"] == "inconclusive"
    assert "timed out" in signup["evidence"][0]["detail"].lower()


def test_time_budget_marks_partial(site, data_dir, tmp_path):
    serve_version(site, "v4.5.1")
    site.add("/login/signup.php", Reply(200, "slow", delay=3))
    code, report = run_scan(site, data_dir, tmp_path, "--max-time", "1.5")
    assert code == 6
    assert any("time budget" in item for item in report["limitations"])


def test_custom_headers_and_user_agent(site, data_dir, tmp_path):
    serve_version(site, "v4.5.1")
    run_scan(site, data_dir, tmp_path, "-H", "X-Scan-Id: 42", "--user-agent", "rift-test/1", "--no-checks")
    _, _, headers = site.requests[0]
    assert headers.get("X-Scan-Id") == "42" and headers.get("User-Agent") == "rift-test/1"


@pytest.mark.parametrize("argv", [[], ["--url", "ftp://example"], ["--url", "http://127.0.0.1/", "-H", "broken"]])
def test_usage_errors(argv, data_dir):
    assert main([*argv, "--data-dir", str(data_dir)]) == 2
