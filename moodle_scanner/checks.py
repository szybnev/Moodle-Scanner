"""Read-only misconfiguration checks.

Every check issues only GET (or HEAD) requests for public URLs; nothing logs in,
submits a form, creates an account, or changes server state. Each check returns
``detected``, ``not_detected``, ``inconclusive`` (no usable answer, e.g. network
error or budget exhausted) with evidence.

Evidence never includes secrets: for exposed configuration files only the names
of recognised settings are reported, never their values.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from dataclasses import dataclass, field

from .httpclient import HttpClient, Response


@dataclass
class CheckResult:
    id: str
    title: str
    severity: str  # critical | high | medium | low | info
    status: str  # detected | not_detected | inconclusive
    evidence: list[dict] = field(default_factory=list)
    recommendation: str = ""

    def to_json(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity,
            "status": self.status,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
        }


def _ev(resp: Response, detail: str) -> dict:
    return {"url": resp.url, "status": resp.status, "detail": detail}


def _inconclusive(responses: list[Response]) -> bool:
    return bool(responses) and all(r.status is None for r in responses)


def _result(
    check_id: str, title: str, severity: str, recommendation: str, evidence: list[dict], responses: list[Response]
) -> CheckResult:
    if evidence:
        status = "detected"
    elif _inconclusive(responses):
        status = "inconclusive"
        evidence = [{"url": r.url, "status": None, "detail": r.error or "no response"} for r in responses[:3]]
    else:
        status = "not_detected"
    return CheckResult(check_id, title, severity, status, evidence, recommendation)


# --- self registration -----------------------------------------------------


def check_self_registration(client: HttpClient) -> CheckResult:
    resp = client.get("/login/signup.php")
    evidence = []
    body = resp.text if resp.status == 200 else ""
    if (
        re.search(r"<form[^>]+action=\"[^\"]*signup\.php", body)
        and 'name="email"' in body
        and 'name="password"' in body
    ):
        evidence.append(_ev(resp, "account sign-up form is served to anonymous users"))
    return _result(
        "self_registration",
        "Email-based self-registration is enabled",
        "medium",
        "Disable self-registration (Site administration > Plugins > Authentication > Self registration) unless required.",
        evidence,
        [resp],
    )


# --- guest login ---------------------------------------------------------------

_GUEST_RE = re.compile(r'id="guestlogin"|name="username"\s+value="guest"|value="guest"\s+name="username"')


def check_guest_login(client: HttpClient) -> CheckResult:
    resp = client.get("/login/index.php")
    evidence = []
    if resp.status == 200 and _GUEST_RE.search(resp.text):
        evidence.append(_ev(resp, "login page offers 'Log in as a guest'"))
    return _result(
        "guest_login",
        "Guest login button is shown",
        "low",
        "Hide the guest login button (guestloginbutton) and disable guest access unless content is meant to be public.",
        evidence,
        [resp],
    )


# --- web services ---------------------------------------------------------------


def _json(resp: Response) -> dict | None:
    if resp.status is None or not resp.body:
        return None
    try:
        data = json.loads(resp.text)
    except ValueError:
        return None
    return data if isinstance(data, dict) else None


def check_web_services(client: HttpClient) -> CheckResult:
    resp = client.get("/login/token.php")
    data = _json(resp)
    evidence = []
    if data is not None and "errorcode" in data and data["errorcode"] != "enablewsdescription":
        evidence.append(
            _ev(resp, f"token endpoint is active (errorcode={data['errorcode']}); web services are enabled")
        )
    return _result(
        "web_services",
        "Web services token endpoint is enabled",
        "low",
        "Enable web services and the mobile service only if used; enforce strong passwords and rate limiting on /login/token.php.",
        evidence,
        [resp],
    )


# --- debug display -----------------------------------------------------------------

_DEBUG_HTML_RE = re.compile(r"Debug info:|Stack trace:|class=\"[^\"]*debuggingmessage|line \d+ of [/\\][\w/\\.-]+\.php")


def check_debug_display(client: HttpClient) -> CheckResult:
    responses = [client.get("/login/token.php"), client.get("/course/view.php?id=-1")]
    evidence = []
    data = _json(responses[0])
    if data and (data.get("stacktrace") or data.get("debuginfo")):
        evidence.append(_ev(responses[0], "JSON error includes stacktrace/debuginfo"))
    for resp in responses[1:]:
        if resp.status is not None and (m := _DEBUG_HTML_RE.search(resp.text)):
            evidence.append(_ev(resp, f"error page shows developer debugging output ({m.group(0)[:60]})"))
    return _result(
        "debug_display",
        "Debug messages are displayed to visitors",
        "medium",
        "Set debug to NONE/MINIMAL and disable debugdisplay on production sites.",
        evidence,
        responses,
    )


# --- dataroot ---------------------------------------------------------------------------

DATAROOT_PREFIXES = ("moodledata", "moodle_data", "moodle-data", "data")
_DATAROOT_MARKER = "This directory contains the content of uploaded files"


def check_dataroot(client: HttpClient) -> CheckResult:
    paths = [f"/{p}/filedir/warning.txt" for p in DATAROOT_PREFIXES]
    responses = list(client.get_many(paths).values())
    evidence = [
        _ev(r, "Moodle dataroot file store marker is downloadable")
        for r in responses
        if r.status == 200 and _DATAROOT_MARKER in r.text
    ]
    return _result(
        "dataroot_exposed",
        "Moodle data directory (dataroot) is reachable over HTTP",
        "high",
        "Move the dataroot outside the web root; it holds uploaded files, sessions and caches.",
        evidence,
        responses,
    )


# --- VCS metadata ------------------------------------------------------------------------

_VCS_PROBES: list[tuple[str, Callable[[Response], bool], str]] = [
    ("/.git/HEAD", lambda r: bool(re.match(r"(ref: refs/|[0-9a-f]{40})", r.text)), "git HEAD"),
    ("/.git/config", lambda r: "[core]" in r.text, "git config"),
    ("/.svn/wc.db", lambda r: r.body.startswith(b"SQLite format 3"), "subversion working copy DB"),
    ("/.hg/requires", lambda r: "revlogv1" in r.text or "store" in r.text.split(), "mercurial requires"),
]


def check_vcs(client: HttpClient) -> CheckResult:
    results = client.get_many([p for p, _, _ in _VCS_PROBES])
    evidence = []
    for path, matcher, label in _VCS_PROBES:
        resp = results[path]
        if resp.status == 200 and matcher(resp):
            evidence.append(_ev(resp, f"{label} is downloadable"))
    return _result(
        "vcs_exposed",
        "Version control metadata is exposed",
        "high",
        "Deny access to dot directories (.git, .svn, .hg) in the web server configuration.",
        evidence,
        list(results.values()),
    )


# --- config backups ----------------------------------------------------------------------

CONFIG_BACKUP_PATHS = (
    "/config.php.bak",
    "/config.php~",
    "/config.php.old",
    "/config.php.orig",
    "/config.php.save",
    "/config.php.swp",
    "/.config.php.swp",
    "/config.php.txt",
    "/config.bak",
    "/config.old",
    "/config.txt",
)
_CFG_KEY_RE = re.compile(r"\$CFG->(dbtype|dbhost|dbname|dbuser|dbpass|prefix|wwwroot|dataroot|passwordsaltmain)\b")


def check_config_backups(client: HttpClient) -> CheckResult:
    results = client.get_many(CONFIG_BACKUP_PATHS)
    evidence = []
    for path in CONFIG_BACKUP_PATHS:
        resp = results[path]
        if resp.status != 200:
            continue
        keys = sorted(set(_CFG_KEY_RE.findall(resp.body.decode("latin-1"))))
        if len(keys) >= 2:
            evidence.append(_ev(resp, "Moodle config source exposed; contains settings: " + ", ".join(keys)))
    return _result(
        "config_backup_exposed",
        "Backup or editor copy of config.php is downloadable",
        "critical",
        "Delete the file, rotate the database password and salts it contains, and deny backup extensions in the web server.",
        evidence,
        list(results.values()),
    )


# --- developer files ------------------------------------------------------------------------

_DEV_FILES: list[tuple[str, Callable[[Response], bool]]] = [
    ("/composer.json", lambda r: '"moodle/moodle"' in r.text),
    ("/composer.lock", lambda r: '"packages"' in r.text and '"content-hash"' in r.text),
    ("/package.json", lambda r: '"name"' in r.text and "moodle" in r.text.lower()),
    ("/Gruntfile.js", lambda r: "grunt" in r.text.lower()),
    ("/phpunit.xml.dist", lambda r: "<phpunit" in r.text),
    ("/behat.yml.dist", lambda r: "default:" in r.text),
    ("/lib/upgrade.txt", lambda r: "===" in r.text),
    ("/UPGRADING.md", lambda r: "# Moodle Upgrade notes" in r.text),
    ("/admin/environment.xml", lambda r: "<COMPATIBILITY_MATRIX" in r.text),
    ("/README.md", lambda r: "moodle" in r.text.lower()),
    ("/lib/tests/fixtures/empty.txt", lambda r: r.status == 200),
]


def check_dev_files(client: HttpClient) -> CheckResult:
    results = client.get_many([p for p, _ in _DEV_FILES])
    evidence = []
    for path, matcher in _DEV_FILES:
        resp = results[path]
        if resp.status == 200 and not resp.truncated and matcher(resp):
            detail = "developer file is downloadable"
            if path == "/lib/upgrade.txt" and (m := re.search(r"^===\s*(\d+\.\d+(?:\.\d+)?)\s*===", resp.text, re.M)):
                detail += f" (leaks version {m.group(1)})"
            evidence.append(_ev(resp, detail))
    return _result(
        "dev_files_exposed",
        "Developer, test or upgrade-notes files are downloadable",
        "low",
        "Deny access to composer/npm manifests, upgrade notes, tests and fixtures as recommended by the Moodle security docs "
        "(or serve only the public/ directory on Moodle 5.1+).",
        evidence,
        list(results.values()),
    )


# --- install/upgrade --------------------------------------------------------------------------

_INSTALLER_RE = re.compile(r'name="stage"|id="installform"|<title>[^<]*Installation', re.I)
_UPGRADE_RE = re.compile(r'name="confirmupgrade"|name="confirmrelease"|name="confirmplugincheck"|id="upgradesettings"')


def check_install_upgrade(client: HttpClient) -> CheckResult:
    install = client.get("/install.php")
    admin = client.get("/admin/index.php", follow_redirects=True)
    evidence = []
    if install.status == 200 and _INSTALLER_RE.search(install.text):
        evidence.append(_ev(install, "web installer is reachable"))
    if admin.status == 200 and "/login/" not in admin.url and _UPGRADE_RE.search(admin.text):
        evidence.append(_ev(admin, "upgrade confirmation page is reachable without login"))
    return _result(
        "install_upgrade_exposed",
        "Installer or upgrade page is reachable",
        "critical",
        "Complete the installation/upgrade, set $CFG->upgradekey, and block install.php once installed.",
        evidence,
        [install, admin],
    )


ALL_CHECKS: list[Callable[[HttpClient], CheckResult]] = [
    check_self_registration,
    check_guest_login,
    check_web_services,
    check_debug_display,
    check_dataroot,
    check_vcs,
    check_config_backups,
    check_dev_files,
    check_install_upgrade,
]


def run_checks(client: HttpClient) -> list[CheckResult]:
    return [check(client) for check in ALL_CHECKS]
