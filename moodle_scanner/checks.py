"""Read-only checks with endpoint-specific evidence and negative controls.

Detected configuration observations are not vulnerabilities. Incomplete, blocked
or unattributable responses remain inconclusive. Evidence never contains secret
values or raw debug output.
"""

from __future__ import annotations

import configparser
import json
import re
import secrets
from collections.abc import Callable
from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit, urlunsplit
from xml.etree import ElementTree

from .httpclient import HttpClient, Response


@dataclass
class CheckResult:
    id: str
    title: str
    severity: str  # critical | high | medium | low | info
    status: str  # detected | not_detected | inconclusive
    evidence: list[dict] = field(default_factory=list)
    recommendation: str = ""
    kind: str = "finding"  # finding | observation

    def to_json(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity,
            "status": self.status,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
            "kind": self.kind,
        }


def _ev(resp: Response, detail: str) -> dict:
    return {"url": resp.url, "status": resp.status, "detail": detail}


def _control_path(path: str) -> str:
    """Keep the same directory, extension and query for the missing-file control."""
    parts = urlsplit(path)
    parent, _, name = parts.path.rpartition("/")
    return urlunsplit(("", "", f"{parent}/zz{secrets.token_hex(8)}-{name}", parts.query, ""))


def _unusable(resp: Response, statuses: tuple[int, ...] = (200,)) -> bool:
    return (
        resp.status is None
        or resp.truncated
        or bool(resp.error or resp.redirect_chain)
        or (resp.status not in statuses and resp.status not in (404, 410))
    )


def _negative_controls(client: HttpClient, path: str) -> list[Response]:
    controls = [client.get(path)]
    if controls[0].status == 500:
        # Repeated complete 500 responses can contrast actual endpoint content.
        # This does not establish that the control URL is absent.
        controls.append(client.get(_control_path(path)))
    return controls


def _controls_usable(controls: list[Response]) -> bool:
    errors = [r.body for r in controls if r.status == 500]
    for resp in controls:
        if resp.error or resp.truncated or resp.redirect_chain:
            return False
        if resp.status in (200, 404, 410):
            continue
        if resp.status != 500:
            return False
        if errors.count(resp.body) < 2:
            return False
    return True


def _plain(resp: Response) -> bool:
    # PHP, XML and JavaScript source may contain '<'; reject HTML wrappers, not source.
    return not re.search(r"<!doctype\s+html|<(?:html|body|head|pre|code)\b", resp.text, re.I)


Matcher = Callable[[Response], bool]
Detail = str | Callable[[Response], str]


def _run_check(
    client: HttpClient,
    check_id: str,
    title: str,
    severity: str,
    recommendation: str,
    probes: list[tuple[str, Matcher, Detail]],
    *,
    kind: str = "finding",
    statuses: tuple[int, ...] = (200,),
) -> CheckResult:
    evidence = []
    limitations = []
    responses = client.get_many(path for path, _, _ in probes)
    for path, matches, detail in probes:
        resp = responses[path]
        if _unusable(resp, statuses):
            reason = "response truncated" if resp.truncated else resp.error or "response blocked or redirected"
            limitations.append(_ev(resp, reason))
            continue
        if resp.status not in statuses or not matches(resp):
            continue
        controls = _negative_controls(client, _control_path(path))
        if any(control.body == resp.body or matches(control) for control in controls):
            limitations.append(_ev(resp, "same evidence returned for a nonexistent sibling URL (catch-all)"))
            continue
        if not _controls_usable(controls):
            limitations.append(_ev(resp, "negative control unavailable; endpoint evidence is unconfirmed"))
            continue
        evidence.append(_ev(resp, detail(resp) if callable(detail) else detail))
    status = "detected" if evidence else "inconclusive" if limitations else "not_detected"
    return CheckResult(check_id, title, severity, status, evidence + limitations, recommendation, kind)


class _Page(HTMLParser):
    """Read actual form controls, not marker text inside documentation/scripts."""

    def __init__(self, text: str) -> None:
        super().__init__(convert_charrefs=True)
        self.forms: list[tuple[dict, list[dict]]] = []
        self.current: tuple[dict, list[dict]] | None = None
        self.ignored = 0
        self.feed(text)

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in ("pre", "code", "script", "template"):
            self.ignored += 1
        if self.ignored:
            return
        attributes = dict(attrs)
        if tag == "form":
            self.current = (attributes, [])
            self.forms.append(self.current)
        elif tag in ("input", "button") and self.current is not None:
            self.current[1].append(attributes)

    def handle_endtag(self, tag: str) -> None:
        if tag in ("pre", "code", "script", "template") and self.ignored:
            self.ignored -= 1
        if tag == "form":
            self.current = None


def _form(resp: Response, endpoint: str, fields: set[str], *, guest: bool = False) -> bool:
    for attrs, controls in _Page(resp.text).forms:
        action = urlsplit(urljoin(resp.url, attrs.get("action") or ""))
        origin = urlsplit(resp.url)
        if (action.scheme, action.netloc) != (origin.scheme, origin.netloc) or not action.path.endswith("/" + endpoint):
            continue
        if (attrs.get("method") or "get").lower() != "post":
            continue
        names = {control.get("name") for control in controls}
        if fields <= names and (
            not guest or any(c.get("name") == "username" and c.get("value") == "guest" for c in controls)
        ):
            return True
    return False


def check_self_registration(client: HttpClient) -> CheckResult:
    return _run_check(
        client,
        "self_registration",
        "Account self-registration form is offered",
        "info",
        "Review whether public account registration is intended; form visibility alone is not a vulnerability.",
        [
            (
                "/login/signup.php",
                lambda r: _form(r, "login/signup.php", {"username", "password", "email"}),
                "anonymous account sign-up form is served; account creation was not attempted",
            )
        ],
        kind="observation",
    )


def check_guest_login(client: HttpClient) -> CheckResult:
    return _run_check(
        client,
        "guest_login",
        "Guest login option is offered",
        "info",
        "Review guest access policy; a guest button does not establish access to private course content.",
        [
            (
                "/login/index.php",
                lambda r: _form(r, "login/index.php", {"username"}, guest=True),
                "login form offers a guest account; no guest session was created",
            )
        ],
        kind="observation",
    )


def _json(resp: Response) -> dict | None:
    if not resp.body or resp.truncated or resp.error:
        return None
    try:
        data = json.loads(resp.text)
    except ValueError:
        return None
    return data if isinstance(data, dict) else None


def check_web_services(client: HttpClient) -> CheckResult:
    path = "/login/token.php?appsitecheck=1"
    result = _run_check(
        client,
        "web_services",
        "Web services availability check succeeds",
        "info",
        "Review whether web services are intended; availability alone does not establish an authentication weakness.",
        [
            (
                path,
                lambda r: _json(r) == {"appsitecheck": "ok"},
                "public appsitecheck reports web services available; authentication was not attempted",
            )
        ],
        kind="observation",
    )
    resp = client.get(path)
    data = _json(resp)
    if result.status == "not_detected" and data and data.get("errorcode") != "enablewsdescription":
        result.status = "inconclusive"
        result.evidence.append(_ev(resp, "JSON response does not establish web services availability"))
    return result


_TRACE_RE = re.compile(r"\bline\s+\d+\s+of\s+[/\\][\w/\\. -]+\.php\s*:", re.I)


def _json_debug(resp: Response) -> bool:
    data = _json(resp)
    if not data or not isinstance(data.get("errorcode"), str):
        return False
    trace = data.get("stacktrace")
    if isinstance(trace, list):
        trace = "\n".join(line for line in trace if isinstance(line, str))
    return isinstance(trace, str) and bool(_TRACE_RE.search(trace))


def _html_debug(resp: Response) -> bool:
    # The headings alone are common documentation; require an actual path/line frame.
    return bool(
        re.search(r"class=['\"][^'\"]*\b(?:backtrace|stacktrace|debuggingmessage)\b", resp.text, re.I)
        and _TRACE_RE.search(resp.text)
        and not re.search(r"<(?:pre|code)\b", resp.text, re.I)
    )


def check_debug_display(client: HttpClient) -> CheckResult:
    return _run_check(
        client,
        "debug_display",
        "Developer stack traces are displayed to visitors",
        "medium",
        "Disable debugdisplay on production sites and review the server-side error.",
        [
            ("/login/token.php", _json_debug, "JSON error exposes a PHP stack trace (contents redacted)"),
            ("/course/view.php?id=-1", _html_debug, "error page exposes a PHP stack trace (contents redacted)"),
        ],
        statuses=(200, 400, 404, 500),
    )


DATAROOT_PREFIXES = ("moodledata", "moodle_data", "moodle-data", "data")
_DATAROOT_MARKER = "This directory contains the content of uploaded files"


def check_dataroot(client: HttpClient) -> CheckResult:
    return _run_check(
        client,
        "dataroot_exposed",
        "Moodle data directory marker is reachable over HTTP",
        "high",
        "Move dataroot outside the web root and verify uploaded files, sessions and caches are not public.",
        [
            (
                f"/{p}/filedir/warning.txt",
                lambda r: _plain(r) and r.text.lstrip().startswith(_DATAROOT_MARKER) and "Moodle" in r.text,
                "Moodle file store marker is downloadable; individual uploaded files were not requested",
            )
            for p in DATAROOT_PREFIXES
        ],
    )


def _git_config(resp: Response) -> bool:
    if not _plain(resp):
        return False
    config = configparser.ConfigParser(interpolation=None)
    try:
        config.read_string(resp.text)
        return config.get("core", "repositoryformatversion", fallback="") in ("0", "1")
    except configparser.Error:
        return False


_VCS_PROBES: list[tuple[str, Matcher, Detail]] = [
    (
        "/.git/HEAD",
        lambda r: bool(re.fullmatch(r"(?:ref: refs/[\w./-]+|[0-9a-f]{40}|[0-9a-f]{64})\s*", r.text)),
        "git HEAD is downloadable",
    ),
    ("/.git/config", _git_config, "git repository configuration is downloadable (values redacted)"),
    (
        "/.svn/wc.db",
        lambda r: r.body.startswith(b"SQLite format 3\x00") and b"WCROOT" in r.body and b"NODES" in r.body,
        "Subversion working copy database is downloadable (contents redacted)",
    ),
    (
        "/.hg/requires",
        lambda r: _plain(r)
        and "revlogv1" in r.text.splitlines()
        and all(re.fullmatch(r"[a-z0-9-]+", line) for line in r.text.splitlines()),
        "Mercurial repository requirements are downloadable",
    ),
]


def check_vcs(client: HttpClient) -> CheckResult:
    return _run_check(
        client,
        "vcs_exposed",
        "Version control metadata is exposed",
        "high",
        "Deny access to dot directories (.git, .svn, .hg) in the web server configuration.",
        _VCS_PROBES,
    )


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
_CFG_KEY_RE = re.compile(
    r"^\s*\$CFG->(dbtype|dbhost|dbname|dbuser|dbpass|prefix|wwwroot|dataroot|passwordsaltmain)\s*=\s*"
    r"(?:'[^'\r\n]*'|\"[^\"\r\n]*\")\s*;",
    re.M,
)


def _config_keys(resp: Response) -> list[str]:
    if not _plain(resp) or not resp.body.lstrip().startswith(b"<?php"):
        return []
    source = re.sub(r"/\*.*?\*/", "", resp.text, flags=re.S)
    return sorted(set(_CFG_KEY_RE.findall(source)))


def check_config_backups(client: HttpClient) -> CheckResult:
    return _run_check(
        client,
        "config_backup_exposed",
        "Backup or editor copy of config.php is downloadable",
        "high",
        "Remove exposed configuration copies, deny backup extensions, and rotate any live credentials they contain.",
        [
            (
                path,
                lambda r: len(_config_keys(r)) >= 2 and bool({"dbpass", "passwordsaltmain"} & set(_config_keys(r))),
                lambda r: "PHP configuration source exposed; settings (values redacted): " + ", ".join(_config_keys(r)),
            )
            for path in CONFIG_BACKUP_PATHS
        ],
    )


def _xml_root(resp: Response, name: str) -> bool:
    if not _plain(resp):
        return False
    try:
        return ElementTree.fromstring(resp.body).tag == name
    except ElementTree.ParseError:
        return False


def _composer_lock(resp: Response) -> bool:
    data = _json(resp)
    return bool(
        data
        and isinstance(data.get("packages"), list)
        and re.fullmatch(r"[0-9a-f]{32,64}", str(data.get("content-hash", "")))
    )


_DEV_FILES: list[tuple[str, Matcher, Detail]] = [
    ("/composer.json", lambda r: (_json(r) or {}).get("name") == "moodle/moodle", "Moodle Composer manifest is public"),
    ("/composer.lock", _composer_lock, "Composer dependency lockfile is public"),
    (
        "/package.json",
        lambda r: (_json(r) or {}).get("name") in ("moodle", "moodle/moodle"),
        "Moodle npm manifest is public",
    ),
    (
        "/Gruntfile.js",
        lambda r: _plain(r)
        and bool(re.search(r"module\.exports\s*=\s*function", r.text))
        and "grunt.initConfig(" in r.text,
        "Grunt build configuration is public",
    ),
    ("/phpunit.xml.dist", lambda r: _xml_root(r, "phpunit"), "PHPUnit configuration template is public"),
    (
        "/behat.yml.dist",
        lambda r: _plain(r) and bool(re.search(r"^default:\s*$", r.text, re.M)) and "behat" in r.text.lower(),
        "Behat configuration template is public",
    ),
    (
        "/lib/upgrade.txt",
        lambda r: _plain(r) and bool(re.match(r"\s*===\s*\d+\.\d+(?:\.\d+)?\s*===", r.text)),
        "upgrade notes are public; a heading does not establish the installed patch version",
    ),
    (
        "/UPGRADING.md",
        lambda r: _plain(r) and bool(re.match(r"\s*# Moodle Upgrade notes\b", r.text)),
        "Moodle upgrade notes are public",
    ),
    (
        "/admin/environment.xml",
        lambda r: _xml_root(r, "COMPATIBILITY_MATRIX"),
        "environment compatibility manifest is public",
    ),
    (
        "/README.md",
        lambda r: _plain(r) and bool(re.match(r"\s*#+\s+Moodle\b", r.text, re.I)),
        "Moodle readme is public",
    ),
]


def check_dev_files(client: HttpClient) -> CheckResult:
    return _run_check(
        client,
        "dev_files_exposed",
        "Public development manifests or upgrade notes",
        "info",
        "Review deployment policy for public development files; their availability alone is not a vulnerability.",
        _DEV_FILES,
        kind="observation",
    )


def _installer(resp: Response) -> bool:
    return _form(resp, "install.php", {"stage"})


def _upgrade(resp: Response) -> bool:
    return any(
        _form(resp, "admin/index.php", {name}) for name in ("confirmupgrade", "confirmrelease", "confirmplugincheck")
    )


def check_install_upgrade(client: HttpClient) -> CheckResult:
    return _run_check(
        client,
        "install_upgrade_exposed",
        "Installer or upgrade confirmation form is publicly reachable",
        "high",
        "Complete installation/upgrade, configure an upgrade key and restrict administrative setup endpoints.",
        [
            ("/install.php", _installer, "installer stage form is served; installation was not attempted"),
            ("/admin/index.php", _upgrade, "upgrade confirmation form is served; no upgrade was attempted"),
        ],
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
