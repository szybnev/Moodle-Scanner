"""Opt-in, evidence-based enumeration of additional plugins.

A blank PHP response is only a candidate. Presence requires a component-specific
public artifact and missing-path controls in the same plugin type and directory.
Plugins with no such public artifact remain unconfirmed, not proven absent.
Release headings are hints, never proof of the installed plugin build.
"""

from __future__ import annotations

import json
import re
import secrets
from dataclasses import dataclass, field
from pathlib import Path

from .checks import _controls_usable, _negative_controls
from .httpclient import HttpClient, Response

DEFAULT_LIMIT = 200
VERSION_FILES = ("CHANGES.md", "CHANGELOG.md", "README.md")
ARTIFACT_FILES = (*VERSION_FILES, "composer.json")


@dataclass
class PluginDB:
    types: dict[str, str]
    plugins: list[dict]

    @classmethod
    def load(cls, path: Path) -> PluginDB:
        data = json.loads(path.read_text(encoding="utf-8"))
        return cls(types=data["types"], plugins=data["plugins"])

    def directory(self, component: str) -> str | None:
        ptype, _, name = component.partition("_")
        base = self.types.get(ptype)
        if not base or not name:
            return None
        return f"/{base}/{name}"

    def ranked(self, limit: int) -> list[dict]:
        """Most recently released plugins first (a proxy for active installs); limit 0 = all."""
        ordered = sorted(self.plugins, key=lambda p: (-p["last_released"], p["component"]))
        return ordered[:limit] if limit > 0 else ordered


@dataclass
class PluginResult:
    enabled: bool
    probed: int = 0
    found: list[dict] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_json(self) -> dict:
        return {"enabled": self.enabled, "probed": self.probed, "found": self.found, "notes": self.notes}


def _usable(resp: Response) -> bool:
    return not (resp.error or resp.truncated or resp.redirect_chain)


def _candidate(resp: Response) -> bool:
    """An empty PHP response or a known access guard is not presence evidence."""
    return (
        _usable(resp)
        and resp.status == 200
        and resp.body.strip()
        in (
            b"",
            b"Direct access to this script is forbidden.",
            b"Direct access to this script is forbidden",
        )
    )


def _artifact(resp: Response, component: str) -> bool:
    if not _usable(resp) or not resp.body:
        return False
    if re.search(r"<!doctype\s+html|<(?:html|body|pre|code)\b", resp.text, re.I):
        return False
    try:
        manifest = json.loads(resp.text)
    except ValueError:
        manifest = None
    if isinstance(manifest, dict):
        ptype, _, name = component.partition("_")
        package = manifest.get("name")
        extra = manifest.get("extra")
        return bool(
            isinstance(package, str)
            and re.fullmatch(rf"[a-z0-9][a-z0-9_.-]*/moodle-{re.escape(component)}", package)
            and manifest.get("type") == f"moodle-{ptype}"
            and isinstance(extra, dict)
            and extra.get("installer-name") == name
        )
    component = re.escape(component)
    return bool(
        re.search(
            rf"^(?:#{{1,3}}\s+[^\n]*\b{component}\b|(?:Moodle\s+)?component\s*:\s*`?{component}`?\s*$)",
            resp.text[:20000],
            re.I | re.M,
        )
    )


def _version_hint(resp: Response, plugin: dict) -> dict | None:
    # Mentioning a release in prose or listing several historical releases does
    # not identify the current version; do not select the newest catalogue entry.
    matches = {
        (v["release"], v["version"])
        for v in plugin["versions"]
        if v["release"]
        and re.search(
            rf"^#{{1,3}}\s+(?:version\s+|release\s+|v)?{re.escape(v['release'])}(?:\s|$)",
            resp.text[:20000],
            re.I | re.M,
        )
    }
    if len(matches) != 1:
        return None
    release, version = matches.pop()
    return {"release": release, "version": version, "source": resp.url}


def enumerate_plugins(
    client: HttpClient, db: PluginDB, limit: int = DEFAULT_LIMIT, branch: str | None = None
) -> PluginResult:
    """Probe the ``limit`` highest-ranked plugins.

    Components that ship with core in the detected ``branch`` (e.g. mod_chat
    before 5.0) are skipped; with an unknown branch they are probed and
    annotated with the branches where they are core.
    """
    result = PluginResult(enabled=True)
    canary = f"/local/zz{secrets.token_hex(6)}/version.php"
    canary_controls = _negative_controls(client, canary)
    canary_resp = canary_controls[0]
    result.probed += len(canary_controls)
    if not _controls_usable(canary_controls):
        result.notes.append("enumeration skipped: missing-plugin control is unavailable or blocked")
        return result
    if canary_resp.status == 200:
        result.notes.append("site answers 200 for non-existent plugin paths; per-plugin controls are required")
    candidates = []
    for plugin in db.ranked(limit):
        if branch and branch in plugin.get("core_in", ()):
            continue
        directory = db.directory(plugin["component"])
        if directory:
            candidates.append((plugin, directory))
        else:
            result.notes.append(f"unknown plugin type for {plugin['component']}")
    responses = client.get_many([f"{d}/version.php" for _, d in candidates])
    result.probed += len(responses)
    for plugin, directory in candidates:
        resp = responses[f"{directory}/version.php"]
        if not _candidate(resp):
            if not _usable(resp) or resp.status not in (404, 410):
                result.notes.append(f"{plugin['component']}: presence unconfirmed; PHP probe is not usable evidence")
            continue
        token = secrets.token_hex(8)
        parent = directory.rsplit("/", 1)[0]
        controls = [
            control
            for path in (f"{parent}/zz{token}/version.php", f"{directory}/zz{token}.php")
            for control in _negative_controls(client, path)
        ]
        result.probed += len(controls)
        if not _controls_usable(controls) or any(_candidate(r) for r in controls):
            result.notes.append(f"{plugin['component']}: presence unconfirmed; PHP missing-path controls are ambiguous")
            continue
        artifact = None
        for name in ARTIFACT_FILES:
            candidate = client.get(f"{directory}/{name}")
            result.probed += 1
            if candidate.status != 200 or not _artifact(candidate, plugin["component"]):
                continue
            controls = [
                control
                for path in (f"{directory}/zz{token}-{name}", f"{parent}/zz{token}/{name}")
                for control in _negative_controls(client, path)
            ]
            result.probed += len(controls)
            if not _controls_usable(controls) or any(
                r.body == candidate.body or _artifact(r, plugin["component"]) for r in controls
            ):
                continue
            artifact = candidate
            break
        if artifact is None:
            result.notes.append(
                f"{plugin['component']}: presence unconfirmed; blank/guarded PHP has no corroborated component artifact"
            )
            continue
        entry = {"component": plugin["component"], "path": directory + "/", "evidence": artifact.url}
        if plugin.get("core_in"):
            entry["core_in"] = plugin["core_in"]
        hint = _version_hint(artifact, plugin)
        if hint:
            entry["version_hint"] = hint
        result.found.append(entry)
    if client.budget_exhausted:
        result.notes.append("time budget exhausted during plugin enumeration; results are partial")
    result.notes.append(
        "plugin advisories are not matched: no structured, redistributable plugin advisory source is bundled"
    )
    result.notes.append(
        "coverage is limited to plugins with public component-specific artifacts; absence from found does not prove absence"
    )
    return result
