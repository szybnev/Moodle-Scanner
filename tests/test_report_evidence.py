"""Reports must distinguish evidence, inventory and version-only hypotheses."""

from __future__ import annotations

from .support import Reply, serve_version
from .test_scan_cli import run_scan


def test_branch_hint_never_claims_all_installed_versions_are_affected(site, data_dir, tmp_path):
    site.load("moodle_pages")
    site.add("/lib/upgrade.txt", Reply(200, "=== 4.5 ===\ncustomised by the site\n"))
    _, report = run_scan(site, data_dir, tmp_path)
    # The local DB ends at 4.5.2, but the target could be patched 4.5.3+.
    hit = next(a for a in report["advisories"] if a["id"] == "MSA-25-0011")
    assert hit["match"] == "possible_version_match"
    assert hit["evidence_level"] == "version_only"


def test_exact_fingerprint_does_not_claim_exploit_verification(site, data_dir, tmp_path):
    serve_version(site, "v4.5.1")
    _, report = run_scan(site, data_dir, tmp_path)
    hit = next(a for a in report["advisories"] if a["id"] == "MSA-25-0011")
    assert hit["match"] == "version_match"
    assert hit["evidence_level"] == "version_only"
    assert "CVE-2025-32044" in hit["cves"]


def test_optional_login_features_are_inventory_not_security_findings(site, data_dir, tmp_path):
    serve_version(site, "v4.5.1")
    site.load("misconfigured")
    _, report = run_scan(site, data_dir, tmp_path)
    assert not {"guest_login", "self_registration", "web_services", "dev_files_exposed"} & {
        c["id"] for c in report["misconfigurations"]
    }
    observations = {c["id"]: c for c in report["observations"]}
    assert observations["guest_login"]["status"] == "detected"
    assert observations["self_registration"]["status"] == "detected"
    assert all(c["kind"] == "observation" and c["severity"] == "info" for c in observations.values())
    # Actual exposure must survive the classification change.
    assert any(c["id"] == "config_backup_exposed" and c["status"] == "detected" for c in report["misconfigurations"])


def test_generic_error_page_and_parameter_error_are_not_findings(site, data_dir, tmp_path):
    site.load("moodle_pages")
    site.default = Reply(200, "<html><body>Page not found</body></html>", {"Content-Type": "text/html"})
    site.add(
        "/login/token.php",
        Reply(
            200, '{"errorcode":"invalidparameter","error":"Missing parameter"}', {"Content-Type": "application/json"}
        ),
    )
    _, report = run_scan(site, data_dir, tmp_path)
    assert not [c for c in report["misconfigurations"] if c["status"] == "detected"]
    assert not [c for c in report["observations"] if c["id"] == "web_services" and c["status"] == "detected"]


def test_single_shared_static_file_does_not_identify_moodle(site, data_dir, tmp_path):
    site.add("/", Reply(200, "<html>Unrelated site</html>"))
    site.add("/lib/javascript-static.js", Reply(200, b"js-45"))
    _, report = run_scan(site, data_dir, tmp_path)
    assert report["target"]["is_moodle"] is False
    assert report["advisories"] == []


def test_unrelated_cookie_and_config_script_do_not_identify_moodle(site, data_dir, tmp_path):
    site.add(
        "/",
        Reply(
            200, "<script>M.cfg = {};</script>", {"Set-Cookie": "notMoodleSession=example", "Content-Type": "text/html"}
        ),
    )
    _, report = run_scan(site, data_dir, tmp_path)
    assert report["target"]["is_moodle"] is False
    assert report["advisories"] == []


def test_error_page_markers_do_not_identify_moodle(site, data_dir, tmp_path):
    body = '<script>M.cfg = {};</script><meta name="keywords" content="moodle">'
    site.add("/", Reply(503, body, {"Set-Cookie": "MoodleSession=example"}))
    site.add("/login/index.php", Reply(503, body))
    _, report = run_scan(site, data_dir, tmp_path)
    assert report["target"]["is_moodle"] is False
    assert report["misconfigurations"] == []
