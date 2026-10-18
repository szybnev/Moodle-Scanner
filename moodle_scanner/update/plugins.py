"""Build ``plugins.json``: plugin type directories and the public plugin list.

* Plugin type -> directory comes from ``lib/components.json`` and every
  ``db/subplugins.json`` in the moodle/moodle git mirror (union over the
  newest tag of each branch, so old and new layouts are covered).
* Additional plugins come from the Moodle plugins directory API
  (``download.moodle.org/api/1.3/pluglist.php``). Only component names,
  version numbers, release names and supported Moodle branches are stored.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

from ..httpclient import HttpClient
from ..versions import MoodleVersion
from .fingerprints import _git, release_tags

PLUGLIST_URL = "https://download.moodle.org/api/1.3/pluglist.php"
SCHEMA_VERSION = 1
VERSIONS_PER_PLUGIN = 10


def _read_blob_json(repo: Path, blob: str, cache: dict[str, dict]) -> dict:
    if blob not in cache:
        try:
            cache[blob] = json.loads(_git(repo, "cat-file", "-p", blob))
        except (RuntimeError, ValueError):
            cache[blob] = {}
    return cache[blob]


def plugin_types(repo: Path, log: Callable[[str], None] = print) -> tuple[dict[str, str], dict[str, list[str]]]:
    """Plugin type directories and core plugin components, from branch heads >= 2.6.

    Returns ``(types, core_in)``: ``types`` maps plugin type to URL-relative
    directory (union over branches); ``core_in`` maps a component to the
    branches where it ships with Moodle core. Blobs are read by id so files
    shared across branches are fetched once (the mirror is blob-less; each
    first read is a lazy network fetch).
    """
    newest_per_branch: dict[tuple[int, int], str] = {}
    for tag in release_tags(repo):
        v = MoodleVersion.parse(tag)
        if v.is_prerelease or v.branch < (2, 6):
            continue
        newest_per_branch[v.branch] = tag
    types: dict[str, str] = {}
    cache: dict[str, dict] = {}
    version_files: dict[tuple[int, int], list[str]] = {}
    for branch in sorted(newest_per_branch):
        tag = newest_per_branch[branch]
        blobs: dict[str, str] = {}
        for line in _git(repo, "ls-tree", "-r", "--full-tree", tag).splitlines():
            meta, _, path = line.partition("\t")
            blobs[path] = meta.split()[2]
        prefix = "public/" if "public/index.php" in blobs else ""
        version_files[branch] = [
            p.removeprefix(prefix)[: -len("/version.php")]
            for p in blobs
            if p.endswith("/version.php") and p.startswith(prefix) and "/tests/" not in p
        ]
        if "lib/components.json" in blobs:
            components = _read_blob_json(repo, blobs["lib/components.json"], cache)
            for ptype, directory in (components.get("plugintypes") or {}).items():
                types[ptype] = directory.removeprefix("public/")
        for path, blob in blobs.items():
            if not path.endswith("db/subplugins.json") or "/tests/" in path:
                continue
            data = _read_blob_json(repo, blob, cache)
            parent = path[: -len("db/subplugins.json")].rstrip("/").removeprefix(prefix)
            for ptype, directory in (data.get("subplugintypes") or {}).items():
                types[ptype] = f"{parent}/{directory}"
            for ptype, directory in (data.get("plugintypes") or {}).items():
                types.setdefault(ptype, directory.removeprefix("public/"))
        log(f"plugin types after {tag}: {len(types)}")
    dir_to_type = {directory: ptype for ptype, directory in types.items()}
    core_in: dict[str, list[str]] = {}
    for branch, dirs in sorted(version_files.items()):
        for plugin_dir in dirs:
            base, _, name = plugin_dir.rpartition("/")
            ptype = dir_to_type.get(base)
            if ptype:
                core_in.setdefault(f"{ptype}_{name}", []).append(f"{branch[0]}.{branch[1]}")
    return dict(sorted(types.items())), core_in


def plugin_list(client: HttpClient) -> list[dict]:
    resp = client.get(PLUGLIST_URL)
    if not resp.ok or resp.truncated:
        raise RuntimeError(f"plugins directory API: HTTP {resp.status} {resp.error or ''}".strip())
    data = json.loads(resp.text)
    plugins = []
    for item in data.get("plugins", []):
        component = item.get("component") or ""
        if "_" not in component:
            continue
        versions = sorted(item.get("versions") or [], key=lambda v: str(v.get("version", "")), reverse=True)
        plugins.append(
            {
                "component": component,
                "last_released": int(item.get("timelastreleased") or 0),
                "versions": [
                    {
                        "version": str(v.get("version", "")),
                        "release": str(v.get("release") or ""),
                        "moodle": sorted({s.get("release", "") for s in v.get("supportedmoodles") or []}),
                    }
                    for v in versions[:VERSIONS_PER_PLUGIN]
                ],
            }
        )
    plugins.sort(key=lambda p: p["component"])
    return plugins


def update_plugins(path: Path, client: HttpClient, repo: Path, log: Callable[[str], None] = print) -> dict[str, int]:
    types, core_in = plugin_types(repo, log=log)
    plugins = plugin_list(client)
    for plugin in plugins:
        branches = core_in.get(plugin["component"])
        if branches:
            plugin["core_in"] = branches
    data = {
        "schema_version": SCHEMA_VERSION,
        "source": PLUGLIST_URL,
        "types": types,
        "plugins": plugins,
    }
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    tmp.replace(path)
    return {"types": len(types), "plugins": len(plugins)}
