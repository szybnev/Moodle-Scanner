"""Opt-in enumeration of additional (non-core) plugins and themes.

For each plugin from the Moodle plugins directory list, the scanner requests
``/<plugin dir>/version.php``. Moodle's ``version.php`` files print nothing,
so an installed plugin answers ``200`` with an empty body and a missing one
answers ``404``. A random, certainly-missing plugin path is requested first;
if the site answers it with 200 (catch-all routing), enumeration is skipped
because results would be meaningless.

Plugin versions are reported only when the site exposes them in a changelog or
readme that mentions a release name known for that plugin.
"""

from __future__ import annotations

import json
import re
import secrets
from dataclasses import dataclass, field
from pathlib import Path

from .httpclient import HttpClient, Response

DEFAULT_LIMIT = 200
VERSION_FILES = ("CHANGES.md", "CHANGELOG.md", "README.md")


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


def _is_installed(resp: Response) -> bool:
    """version.php exists: 200 with an empty body or a short die() message, not an HTML page."""
    if resp.status != 200:
        return False
    body = resp.body.strip()
    return len(body) < 256 and b"<" not in body


def _version_hint(client: HttpClient, directory: str, plugin: dict) -> dict | None:
    releases = [v for v in plugin["versions"] if v["release"]]
    if not releases:
        return None
    for name in VERSION_FILES:
        resp = client.get(f"{directory}/{name}")
        if resp.status != 200 or not resp.body:
            continue
        head = resp.text[:20000]
        for v in releases:
            if re.search(rf"(?<![\w.]){re.escape(v['release'])}(?![\w.])", head):
                return {"release": v["release"], "version": v["version"], "source": resp.url}
    return None


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
    canary_resp = client.get(canary)
    result.probed += 1
    if canary_resp.status is None:
        result.notes.append(f"enumeration skipped: canary request failed ({canary_resp.error})")
        return result
    if canary_resp.status == 200:
        result.notes.append("enumeration skipped: site answers 200 for non-existent plugin paths")
        return result
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
        if not _is_installed(resp):
            continue
        entry = {"component": plugin["component"], "path": directory + "/", "evidence": resp.url}
        if plugin.get("core_in"):
            entry["core_in"] = plugin["core_in"]
        hint = _version_hint(client, directory, plugin)
        if hint:
            entry["version_hint"] = hint
        result.found.append(entry)
    if client.budget_exhausted:
        result.notes.append("time budget exhausted during plugin enumeration; results are partial")
    result.notes.append(
        "plugin advisories are not matched: no structured, redistributable plugin advisory source is bundled"
    )
    return result
