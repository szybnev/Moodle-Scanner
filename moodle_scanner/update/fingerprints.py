"""Build ``fingerprints.json`` from the moodle/moodle git repository.

How it works:

1. Keep a bare, blob-less, depth-1 mirror of every release tag in the cache
   directory (``git fetch --depth=1 --filter=blob:none``). Only trees are
   downloaded, about 40 MB for all tags; later runs fetch only new tags.
2. ``git ls-tree`` gives the git blob id of every file in every tag. A git blob
   id is ``sha1("blob <size>\\0" + content)``, so the scanner can hash a file it
   downloads from a site and compare it without the DB ever storing file
   content. No Moodle source is copied into this repository: only paths, blob
   ids and tag names (facts).
3. Pick a pool of web-served static files that, together, tell all release
   tags apart (greedy partition refinement, repeated for redundancy so that a
   blocked file has substitutes).

From Moodle 5.1 the web root is the ``public/`` directory; paths are stored as
URL paths (``public/`` stripped) and only files below ``public/`` count.
"""

from __future__ import annotations

import base64
import heapq
import json
import os
import subprocess
from collections import Counter, defaultdict
from collections.abc import Callable
from pathlib import Path

from ..fingerprints import is_commonly_blocked
from ..versions import is_release_tag, tag_sort_key

MOODLE_GIT_URL = "https://github.com/moodle/moodle.git"
SCHEMA_VERSION = 1
SERVED_EXTENSIONS = frozenset(
    {
        ".js",
        ".mjs",
        ".map",
        ".css",
        ".scss",
        ".less",
        ".mustache",
        ".json",
        ".xml",
        ".xsd",
        ".txt",
        ".md",
        ".html",
        ".htm",
        ".svg",
        ".png",
        ".gif",
        ".jpg",
        ".jpeg",
        ".ico",
        ".woff",
        ".woff2",
        ".ttf",
        ".csv",
        ".feature",
    }
)
ROUNDS = 3


def default_cache_dir() -> Path:
    base = os.environ.get("XDG_CACHE_HOME") or str(Path.home() / ".cache")
    return Path(base) / "moodle-scanner"


def _git(repo: Path, *args: str, token: str | None = None) -> str:
    cmd = ["git"]
    if token:
        cred = base64.b64encode(f"x-access-token:{token}".encode()).decode()
        cmd += ["-c", f"http.https://github.com/.extraheader=Authorization: Basic {cred}"]
    cmd += ["-C", str(repo), *args]
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        raise RuntimeError(f"git {' '.join(args[:2])} failed: {proc.stderr.strip()}")
    return proc.stdout


def ensure_mirror(cache_dir: Path, url: str = MOODLE_GIT_URL, token: str | None = None) -> Path:
    """Create or refresh the tree-only mirror; returns the bare repo path."""
    repo = cache_dir / "moodle.git"
    if not (repo / "HEAD").exists():
        repo.mkdir(parents=True, exist_ok=True)
        _git(repo, "init", "--quiet", "--bare")
        _git(repo, "remote", "add", "origin", url)
        _git(repo, "config", "remote.origin.promisor", "true")
        _git(repo, "config", "remote.origin.partialclonefilter", "blob:none")
    else:
        _git(repo, "remote", "set-url", "origin", url)
    _git(
        repo,
        "fetch",
        "--quiet",
        "--depth=1",
        "--filter=blob:none",
        "--no-tags",
        "--force",
        "origin",
        "+refs/tags/*:refs/tags/*",
        token=token,
    )
    return repo


def release_tags(repo: Path) -> list[str]:
    tags = [t for t in _git(repo, "tag", "--list").split() if is_release_tag(t)]
    return sorted(tags, key=tag_sort_key)


def served_files(repo: Path, tag: str) -> dict[str, str]:
    """Map URL path -> git blob id for web-served static files of ``tag``."""
    listing = _git(repo, "ls-tree", "-r", "--full-tree", tag)
    entries: dict[str, str] = {}
    rows = []
    public_layout = False
    for line in listing.splitlines():
        meta, _, path = line.partition("\t")
        mode, kind, sha = meta.split()
        if kind != "blob" or mode == "120000":
            continue
        rows.append((path, sha))
        if path == "public/index.php":
            public_layout = True
    for path, sha in rows:
        if public_layout:
            if not path.startswith("public/"):
                continue
            path = path[len("public") :]
        else:
            path = "/" + path
        if any(part.startswith(".") for part in path.split("/")[1:]):
            continue
        dot = path.rfind(".")
        if dot == -1 or path[dot:].lower() not in SERVED_EXTENSIONS:
            continue
        entries[path] = sha
    return entries


def select_pool(tags: list[str], files: dict[str, dict[str, list[int]]], rounds: int = ROUNDS) -> list[str]:
    """Greedy partition refinement over tags; returns selected paths.

    The score of a path is the number of still-indistinguishable tag pairs it
    separates, counting only pairs where both tags contain the file (a missing
    file is a 404, which says nothing). Scores only shrink as the partition is
    refined, so lazy evaluation with a heap is exact.
    """
    weights = {p: (0.25 if is_commonly_blocked(p) else 1.0) for p in files}
    chosen: list[str] = []
    for _ in range(rounds):
        labels = [0] * len(tags)
        heap = [(-_score(files[p], labels) * weights[p], p) for p in files if p not in chosen]
        heapq.heapify(heap)
        picked_this_round = 0
        while heap:
            neg, path = heapq.heappop(heap)
            if neg == 0:
                break
            fresh = -_score(files[path], labels) * weights[path]
            if heap and fresh > heap[0][0]:
                heapq.heappush(heap, (fresh, path))
                continue
            if fresh == 0:
                break
            chosen.append(path)
            picked_this_round += 1
            labels = _refine(labels, files[path])
        if picked_this_round == 0:
            break
    return chosen


def _score(groups: dict[str, list[int]], labels: list[int]) -> int:
    per_class: dict[int, Counter[str]] = defaultdict(Counter)
    for blob, idxs in groups.items():
        for i in idxs:
            per_class[labels[i]][blob] += 1
    total = 0
    for counts in per_class.values():
        if len(counts) < 2:
            continue
        present = sum(counts.values())
        total += (present * present - sum(c * c for c in counts.values())) // 2
    return total


def _refine(labels: list[int], groups: dict[str, list[int]]) -> list[int]:
    blob_of: dict[int, str] = {}
    for blob, idxs in groups.items():
        for i in idxs:
            blob_of[i] = blob
    mapping: dict[tuple[int, str | None], int] = {}
    new = []
    for i, label in enumerate(labels):
        key = (label, blob_of.get(i))
        new.append(mapping.setdefault(key, len(mapping)))
    return new


def build_db(repo: Path, log: Callable[[str], None] = print) -> dict:
    tags = release_tags(repo)
    if not tags:
        raise RuntimeError("no release tags found in the mirror")
    files: dict[str, dict[str, list[int]]] = defaultdict(lambda: defaultdict(list))
    for idx, tag in enumerate(tags):
        for path, sha in served_files(repo, tag).items():
            files[path][sha].append(idx)
        if (idx + 1) % 100 == 0:
            log(f"indexed {idx + 1}/{len(tags)} tags")
    varying = {p: dict(g) for p, g in files.items() if len(g) > 1}
    log(f"{len(files)} served files, {len(varying)} vary between tags; selecting pool")
    pool = select_pool(tags, varying)
    log(f"selected {len(pool)} fingerprint files")
    pool_files = {p: {blob: sorted(idxs) for blob, idxs in sorted(varying[p].items())} for p in sorted(pool)}
    return {
        "schema_version": SCHEMA_VERSION,
        "source": MOODLE_GIT_URL,
        "hash": "git-blob-sha1",
        "latest_tag": tags[-1],
        "tag_count": len(tags),
        "tags": tags,
        "files": pool_files,
    }


def write_db(path: Path, db: dict) -> None:
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(db, indent=1, sort_keys=False) + "\n", encoding="utf-8")
    tmp.replace(path)


def existing_tags(path: Path) -> set[str]:
    if not path.exists():
        return set()
    return set(json.loads(path.read_text(encoding="utf-8")).get("tags", []))


def update_fingerprints(
    path: Path,
    *,
    cache_dir: Path | None = None,
    git_url: str = MOODLE_GIT_URL,
    token: str | None = None,
    force: bool = False,
    log: Callable[[str], None] = print,
) -> dict[str, int]:
    """Build the DB from scratch when absent, otherwise only when tags changed."""
    cache_dir = cache_dir or default_cache_dir()
    before = existing_tags(path)
    log(f"syncing tag trees from {git_url} into {cache_dir}")
    repo = ensure_mirror(cache_dir, git_url, token)
    tags = release_tags(repo)
    new = [t for t in tags if t not in before]
    if before and not new and not force:
        log(f"fingerprint DB already covers all {len(tags)} release tags (latest {tags[-1]})")
        return {"tags": len(tags), "new_tags": 0, "files": -1}
    log(f"{len(new)} new tags" + (f" (newest {new[-1]})" if new else ""))
    db = build_db(repo, log=log)
    write_db(path, db)
    return {"tags": db["tag_count"], "new_tags": len(new), "files": len(db["files"])}
