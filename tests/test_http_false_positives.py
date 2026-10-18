"""Offline regressions at the public check/plugin boundary; bodies are synthetic."""

from __future__ import annotations

import json
from html import escape
from urllib.parse import urlsplit

import pytest

from moodle_scanner.checks import (
    check_config_backups,
    check_debug_display,
    check_dev_files,
    check_install_upgrade,
    check_self_registration,
    check_vcs,
    check_web_services,
    run_checks,
)
from moodle_scanner.httpclient import HttpClient, Response
from moodle_scanner.plugins import PluginDB, enumerate_plugins

from .support import PLUGINS, Reply

SIGNUP = (
    "<form method='post' action='/login/signup.php'><input name='username'>"
    "<input name='email'><input type='password' name='password'></form>"
)
INSTALL = "<form action='/install.php' method='post'><input name='stage' value='1'></form>"
UPGRADE = "<form method='post' action='/admin/index.php'><input name='confirmupgrade' value='1'></form>"
CONFIG = "<?php\n$CFG->dbhost = 'private-db';\n$CFG->dbpass = 'private-password';\n"
TRACE = {
    "errorcode": "invalidparameter",
    "stacktrace": "* line 42 of /private/app/lib/example.php: synthetic exception thrown",
}


def plugins() -> PluginDB:
    return PluginDB(types=PLUGINS["types"], plugins=[PLUGINS["plugins"][0]])


@pytest.mark.parametrize("body", [b"", "<html><body>Page not found</body></html>"])
def test_generic_success_pages_never_become_findings(site, body):
    site.default = Reply(200, body)
    site.add(
        "/login/token.php", Reply(200, json.dumps({"errorcode": "invalidparameter", "error": "Missing parameter"}))
    )
    checks = run_checks(HttpClient(site.url))
    assert not [check for check in checks if check.status == "detected"]
    assert not any(path == "/lib/tests/fixtures/empty.txt" for _, path, _ in site.requests)


def test_enabled_benign_features_are_only_observations(site):
    site.add("/login/signup.php", Reply(200, SIGNUP))
    site.add(
        "/login/index.php",
        Reply(200, "<form method='post' action='/login/index.php'><input value='guest' name='username'></form>"),
    )
    site.add("/login/token.php?appsitecheck=1", Reply(200, '{"appsitecheck":"ok"}'))
    site.add("/composer.json", Reply(200, '{"name":"moodle/moodle"}'))
    checks = run_checks(HttpClient(site.url))
    detected = {check.id: check for check in checks if check.status == "detected"}
    assert set(detected) == {"self_registration", "guest_login", "web_services", "dev_files_exposed"}
    assert all(check.kind == "observation" and check.severity == "info" for check in detected.values())
    assert all(check.to_json()["kind"] == "observation" for check in detected.values())
    assert all(method == "GET" for method, _, _ in site.requests)


@pytest.mark.parametrize("errorcode", ["invalidparameter", "missingparam", "invalidlogin", "unexpected"])
def test_web_service_error_codes_do_not_prove_enabled(site, errorcode):
    site.add("/login/token.php?appsitecheck=1", Reply(200, json.dumps({"errorcode": errorcode, "error": "example"})))
    result = check_web_services(HttpClient(site.url))
    assert result.status == "inconclusive"
    assert result.kind == "observation"


def test_explicit_web_services_disabled_is_not_detected(site):
    site.add("/login/token.php?appsitecheck=1", Reply(200, '{"errorcode":"enablewsdescription"}'))
    assert check_web_services(HttpClient(site.url)).status == "not_detected"


@pytest.mark.parametrize("body", [SIGNUP, INSTALL, UPGRADE, CONFIG, "ref: refs/heads/main\n", json.dumps(TRACE)])
def test_catch_all_replays_of_real_markers_are_not_attributed_to_endpoints(site, body):
    site.default = Reply(200, body)
    checks = run_checks(HttpClient(site.url))
    assert not [check for check in checks if check.status == "detected"]
    assert any(check.status == "inconclusive" for check in checks)


def test_marker_laden_html_documentation_is_not_exposure(site):
    markers = (
        SIGNUP
        + INSTALL
        + UPGRADE
        + CONFIG
        + "\n[core]\nrepositoryformatversion = 0\nrevlogv1\n"
        + "This directory contains the content of uploaded files and is controlled by Moodle code.\n"
        + "Debug info: Stack trace: line 42 of /private/file.php: example\n"
        + '{"name":"moodle/moodle","packages":[],"content-hash":"example"}\n'
        + "# Moodle Upgrade notes\n<phpunit></phpunit>\n<COMPATIBILITY_MATRIX/>"
    )
    # Both escaped examples and real tags nested in code are documentation, not forms.
    site.default = Reply(
        200, "<html><body><pre>" + escape(markers) + "</pre><code>" + markers + "</code></body></html>"
    )
    assert not [r for r in run_checks(HttpClient(site.url)) if r.status == "detected"]


@pytest.mark.parametrize("path,body", [("/install.php", INSTALL), ("/admin/index.php", UPGRADE)])
def test_real_anonymous_setup_forms_remain_findings(site, path, body):
    site.add(path, Reply(200, body))
    result = check_install_upgrade(HttpClient(site.url))
    assert result.status == "detected"
    assert result.kind == "finding"
    assert result.evidence[0]["url"].endswith(path)


@pytest.mark.parametrize(
    "body",
    [
        '<html><title>Installation documentation</title><p>name="stage" id="installform"</p></html>',
        '<html><p>name="confirmupgrade" name="confirmrelease" id="upgradesettings"</p></html>',
        '<form method="post" action="/login/index.php"><input name="username"><input name="password"></form>',
        '<div class="error">Installation is not available</div>',
    ],
)
def test_login_errors_and_installer_marker_text_are_not_setup_access(site, body):
    site.add("/install.php", Reply(200, body))
    site.add("/admin/index.php", Reply(200, body))
    assert check_install_upgrade(HttpClient(site.url)).status == "not_detected"


def test_redirect_to_login_does_not_confirm_setup_access(site):
    site.add("/admin/index.php", Reply(302, UPGRADE, {"Location": "/login/index.php"}))
    site.add("/login/index.php", Reply(200, UPGRADE))
    result = check_install_upgrade(HttpClient(site.url))
    assert result.status == "inconclusive"
    assert not any(path == "/login/index.php" for _, path, _ in site.requests)


def test_true_source_trace_dataroot_and_vcs_exposures_remain_findings(site):
    site.load("misconfigured")
    results = {result.id: result for result in run_checks(HttpClient(site.url))}
    for check_id in ("config_backup_exposed", "debug_display", "dataroot_exposed", "vcs_exposed"):
        assert results[check_id].status == "detected"
        assert results[check_id].kind == "finding"
    report = json.dumps([result.to_json() for result in results.values()])
    assert "not-a-real-secret" not in report
    assert "feedbeef" not in report
    assert "line 497" not in report


def test_debug_heading_without_a_trace_is_not_a_finding(site):
    site.add("/course/view.php?id=-1", Reply(200, "<p>Debug info: Stack trace:</p>"))
    assert check_debug_display(HttpClient(site.url)).status == "not_detected"


def test_structured_html_trace_is_retained_without_disclosing_contents(site):
    site.add(
        "/course/view.php?id=-1",
        Reply(500, '<ul class="stacktrace"><li>line 42 of /private/custom.php: example failure</li></ul>'),
    )
    result = check_debug_display(HttpClient(site.url))
    assert result.status == "detected"
    assert "/private/custom.php" not in json.dumps(result.to_json())


def test_php_comment_example_is_not_a_configuration_backup(site):
    site.add("/config.php.bak", Reply(200, "<?php\n/*\n$CFG->dbhost = 'sample';\n$CFG->dbpass = 'sample';\n*/\n"))
    assert check_config_backups(HttpClient(site.url)).status == "not_detected"


@pytest.mark.parametrize("status", [401, 403, 429, 500])
def test_blocked_responses_are_inconclusive_even_when_other_probes_are_missing(site, status):
    site.add("/.git/HEAD", Reply(status, "ref: refs/heads/main\n"))
    assert check_vcs(HttpClient(site.url)).status == "inconclusive"


def test_truncated_positive_bodies_are_inconclusive(site):
    site.add("/config.php.bak", Reply(200, CONFIG + " " * 200))
    result = check_config_backups(HttpClient(site.url, max_body=len(CONFIG)))
    assert result.status == "inconclusive"
    assert "private-password" not in json.dumps(result.to_json())


def test_unavailable_negative_control_is_not_confirmed(site):
    site.default = Reply(403, "Forbidden")
    site.add("/.git/HEAD", Reply(200, "ref: refs/heads/main\n"))
    assert check_vcs(HttpClient(site.url)).status == "inconclusive"


def test_manifest_marker_substrings_are_not_parsed_json(site):
    site.add("/composer.json", Reply(200, 'Documentation mentions "moodle/moodle"'))
    site.add("/package.json", Reply(200, '{"name":"unrelated", "description":"Moodle example"}'))
    assert check_dev_files(HttpClient(site.url)).status == "not_detected"


def test_cross_origin_signup_form_is_not_a_moodle_signup_form(site):
    site.add(
        "/login/signup.php", Reply(200, SIGNUP.replace("/login/signup.php", "https://other.invalid/login/signup.php"))
    )
    assert check_self_registration(HttpClient(site.url)).status == "not_detected"


@pytest.mark.parametrize("body", [b"", b"Direct access to this script is forbidden."])
def test_plugin_blank_php_or_guard_alone_never_proves_presence(site, body):
    site.add("/blocks/xp/version.php", Reply(200, body))
    result = enumerate_plugins(HttpClient(site.url), plugins())
    assert result.found == []
    assert any("unconfirmed" in note for note in result.notes)
    assert any("coverage" in note for note in result.notes)


@pytest.mark.parametrize("body", [b"", b"<html>Not found</html>"])
def test_global_plugin_catch_all_is_not_presence(site, body):
    site.default = Reply(200, body)
    result = enumerate_plugins(HttpClient(site.url), plugins())
    assert result.found == []
    assert result.notes


def test_type_specific_php_catch_all_is_not_plugin_presence():
    def transport(request):
        path = urlsplit(request.url).path
        if path.startswith("/blocks/") and path.endswith(".php"):
            return Response(request.url, 200)
        if path == "/blocks/xp/README.md":
            return Response(request.url, 200, body=b"# block_xp\n## 21.0\n")
        return Response(request.url, 404)

    result = enumerate_plugins(HttpClient("http://replay.invalid", transport=transport), plugins())
    assert result.found == []
    assert any("controls" in note for note in result.notes)


def test_plugin_requires_component_specific_artifact_and_retains_true_presence(site):
    site.add("/blocks/xp/version.php", Reply(200, b""))
    site.add("/blocks/xp/README.md", Reply(200, "# block_xp\n\n## 21.0\nSynthetic plugin release\n"))
    result = enumerate_plugins(HttpClient(site.url), plugins())
    assert len(result.found) == 1
    assert result.found[0]["component"] == "block_xp"
    assert result.found[0]["evidence"].endswith("/blocks/xp/README.md")
    assert result.found[0]["version_hint"]["release"] == "21.0"


@pytest.mark.parametrize(
    "body",
    [
        "# Changelog\n## 21.0\n",
        "<html><h1>block_xp</h1><p>21.0</p></html>",
        "# Other plugin\nExamples include block_xp release 21.0\n",
    ],
)
def test_generic_release_text_and_html_do_not_corroborate_plugin(site, body):
    site.add("/blocks/xp/version.php", Reply(200, b""))
    site.add("/blocks/xp/README.md", Reply(200, body))
    assert enumerate_plugins(HttpClient(site.url), plugins()).found == []


def test_plugin_release_mentioned_in_prose_is_not_a_version_hint(site):
    site.add("/blocks/xp/version.php", Reply(200, b""))
    site.add("/blocks/xp/README.md", Reply(200, "# block_xp\nCompatibility notes mention old release 21.0.\n"))
    result = enumerate_plugins(HttpClient(site.url), plugins())
    assert len(result.found) == 1
    assert "version_hint" not in result.found[0]


def test_truncated_plugin_artifact_cannot_confirm_presence(site):
    site.add("/blocks/xp/version.php", Reply(200, b""))
    site.add("/blocks/xp/README.md", Reply(200, "# block_xp\n" + "x" * 200))
    assert enumerate_plugins(HttpClient(site.url, max_body=40), plugins()).found == []


def test_soft_404_pages_do_not_hide_corroborated_plugin_artifacts(site):
    site.default = Reply(200, "<html>Not found</html>")
    site.add("/blocks/xp/version.php", Reply(200, b""))
    site.add("/blocks/xp/README.md", Reply(200, "# block_xp\n## 21.0\n"))
    result = enumerate_plugins(HttpClient(site.url), plugins())
    assert [entry["component"] for entry in result.found] == ["block_xp"]


def test_component_markdown_catch_all_is_not_plugin_evidence():
    def transport(request):
        path = urlsplit(request.url).path
        if path == "/blocks/xp/version.php":
            return Response(request.url, 200)
        if path.endswith(".md"):
            return Response(request.url, 200, body=b"# block_xp\n## 21.0\n")
        return Response(request.url, 404)

    result = enumerate_plugins(HttpClient("http://replay.invalid", transport=transport), plugins())
    assert result.found == []
    assert any("unconfirmed" in note for note in result.notes)


@pytest.mark.parametrize(
    "path,body",
    [
        ("/.git/HEAD", b"ref: refs/heads/main\n"),
        ("/.git/config", b"[core]\nrepositoryformatversion = 0\n"),
        ("/.hg/requires", b"revlogv1\nstore\nfncache\n"),
        ("/.svn/wc.db", b"SQLite format 3\x00" + b"\x00" * 100 + b"WCROOT NODES"),
    ],
)
def test_structured_vcs_artifacts_remain_findings(site, path, body):
    site.add(path, Reply(200, body))
    result = check_vcs(HttpClient(site.url))
    assert result.status == "detected"
    assert result.kind == "finding"


@pytest.mark.parametrize(
    "path,body",
    [
        ("/.git/HEAD", "ref: refs/heads/main\nThis is only an example."),
        ("/.git/config", "Documentation about [core] configuration."),
        ("/.hg/requires", "This store contains documentation."),
        ("/.svn/wc.db", "SQLite format 3 examples"),
    ],
)
def test_vcs_marker_prose_is_not_a_repository_exposure(site, path, body):
    site.add(path, Reply(200, body))
    assert check_vcs(HttpClient(site.url)).status == "not_detected"


@pytest.mark.parametrize("control_body", [b"", b"<html>Application error</html>"])
def test_stable_500_controls_preserve_true_config_and_dataroot_exposure(site, control_body):
    site.default = Reply(500, control_body)
    site.add("/config.php.bak", Reply(200, CONFIG))
    site.add(
        "/moodledata/filedir/warning.txt",
        Reply(
            200,
            "This directory contains the content of uploaded files and is controlled by Moodle code.",
        ),
    )
    results = {result.id: result for result in run_checks(HttpClient(site.url))}
    assert results["config_backup_exposed"].status == "detected"
    assert results["dataroot_exposed"].status == "detected"
    assert results["vcs_exposed"].status == "inconclusive"
    assert "private-password" not in json.dumps([r.to_json() for r in results.values()])


@pytest.mark.parametrize(
    "path,body,check_id",
    [
        ("/config.php.bak", CONFIG, "config_backup_exposed"),
        (
            "/moodledata/filedir/warning.txt",
            "This directory contains the content of uploaded files and is controlled by Moodle code.",
            "dataroot_exposed",
        ),
    ],
)
def test_500_controls_containing_positive_evidence_reject_attribution(site, path, body, check_id):
    site.default = Reply(500, body + "\n")
    site.add(path, Reply(200, body))
    results = {result.id: result for result in run_checks(HttpClient(site.url))}
    assert results[check_id].status == "inconclusive"
    assert any("same evidence" in e["detail"] for e in results[check_id].evidence)


@pytest.mark.parametrize("status", [401, 403, 429, 502, 503, 504])
def test_auth_rate_limit_and_gateway_controls_are_not_usable(site, status):
    site.default = Reply(status, "")
    site.add("/config.php.bak", Reply(200, CONFIG))
    assert check_config_backups(HttpClient(site.url)).status == "inconclusive"


def test_inconsistent_500_controls_are_not_usable():
    controls = 0

    def transport(request):
        nonlocal controls
        path = urlsplit(request.url).path
        if path == "/config.php.bak":
            return Response(request.url, 200, body=CONFIG.encode())
        if path.startswith("/zz"):
            controls += 1
            return Response(request.url, 500, body=str(controls).encode())
        return Response(request.url, 404)

    result = check_config_backups(HttpClient("http://replay.invalid", transport=transport))
    assert result.status == "inconclusive"
    assert controls == 2


@pytest.mark.parametrize("failure", ["truncated", "transport"])
def test_incomplete_500_controls_are_not_usable(failure):
    def transport(request):
        path = urlsplit(request.url).path
        if path == "/config.php.bak":
            return Response(request.url, 200, body=CONFIG.encode())
        if path.startswith("/zz"):
            return Response(
                request.url,
                500,
                truncated=failure == "truncated",
                error="incomplete response" if failure == "transport" else None,
            )
        return Response(request.url, 404)

    result = check_config_backups(HttpClient("http://replay.invalid", transport=transport))
    assert result.status == "inconclusive"


def composer_plugins() -> PluginDB:
    return PluginDB(
        types={"block": "blocks"},
        plugins=[
            {"component": "block_sample", "last_released": 1, "versions": []},
        ],
    )


def composer_manifest() -> dict:
    return {
        "name": "example-vendor/moodle-block_sample",
        "type": "moodle-block",
        "extra": {"installer-name": "sample"},
    }


@pytest.mark.parametrize("missing_status", [404, 500])
def test_structured_plugin_composer_identity_confirms_presence(site, missing_status):
    site.default = Reply(missing_status, "")
    site.add("/blocks/sample/version.php", Reply(200, b""))
    site.add("/blocks/sample/composer.json", Reply(200, json.dumps(composer_manifest())))
    result = enumerate_plugins(HttpClient(site.url), composer_plugins())
    assert [entry["component"] for entry in result.found] == ["block_sample"]
    assert result.found[0]["evidence"].endswith("/blocks/sample/composer.json")
    assert "version_hint" not in result.found[0]


@pytest.mark.parametrize(
    "field,value",
    [
        ("name", "example-vendor/moodle-block_different"),
        ("name", "moodle-block_sample"),
        ("type", "moodle-mod"),
        ("extra", {"installer-name": "different"}),
        ("extra", {"unrelated": "sample"}),
        ("extra", "sample"),
    ],
)
def test_mismatched_composer_identity_is_not_plugin_presence(site, field, value):
    manifest = composer_manifest()
    manifest[field] = value
    site.add("/blocks/sample/version.php", Reply(200, b""))
    site.add("/blocks/sample/composer.json", Reply(200, json.dumps(manifest)))
    assert enumerate_plugins(HttpClient(site.url), composer_plugins()).found == []


def test_500_plugin_control_containing_same_manifest_rejects_presence():
    manifest = json.dumps(composer_manifest()).encode()

    def transport(request):
        path = urlsplit(request.url).path
        if path == "/blocks/sample/version.php":
            return Response(request.url, 200)
        if path == "/blocks/sample/composer.json":
            return Response(request.url, 200, body=manifest)
        if path.endswith(".json"):
            return Response(request.url, 500, body=manifest + b"\n")
        return Response(request.url, 404)

    result = enumerate_plugins(HttpClient("http://replay.invalid", transport=transport), composer_plugins())
    assert result.found == []
