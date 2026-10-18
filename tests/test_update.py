"""Data update paths, offline: a local git repository stands in for moodle/moodle,
and the replay server stands in for moodle.org."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from moodle_scanner.cli import main
from moodle_scanner.fingerprints import git_blob_sha1
from moodle_scanner.httpclient import HttpClient
from moodle_scanner.update.advisories import update_advisories
from moodle_scanner.update.fingerprints import update_fingerprints

from .support import Reply


def git(repo: Path, *args: str) -> str:
    env = {
        "GIT_AUTHOR_NAME": "t",
        "GIT_AUTHOR_EMAIL": "t@example.invalid",
        "GIT_COMMITTER_NAME": "t",
        "GIT_COMMITTER_EMAIL": "t@example.invalid",
        "HOME": str(repo),
        "PATH": "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin",
    }
    return subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, text=True, env=env).stdout


class UpstreamRepo:
    """Tiny stand-in for moodle/moodle with invented file contents."""

    def __init__(self, path: Path) -> None:
        self.path = path
        path.mkdir()
        git(path, "init", "-q", "-b", "main")
        git(path, "config", "uploadpack.allowFilter", "true")

    @property
    def url(self) -> str:
        return self.path.resolve().as_uri()

    def release(self, tag: str, files: dict[str, str]) -> None:
        for existing in self.path.rglob("*"):
            if existing.is_file() and ".git" not in existing.parts:
                existing.unlink()
        for rel, content in files.items():
            target = self.path / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content)
        git(self.path, "add", "-A")
        git(self.path, "commit", "-q", "-m", tag, "--allow-empty")
        git(self.path, "tag", tag)


@pytest.fixture
def upstream(tmp_path: Path) -> UpstreamRepo:
    repo = UpstreamRepo(tmp_path / "upstream")
    repo.release("v4.4.0", {"index.php": "<?php", "lib/javascript-static.js": "js-a", "theme/s.css": "css-1"})
    repo.release("v4.5.0", {"index.php": "<?php", "lib/javascript-static.js": "js-b", "theme/s.css": "css-1"})
    repo.release("v4.5.1", {"index.php": "<?php", "lib/javascript-static.js": "js-b", "theme/s.css": "css-2"})
    # Moodle 5.1+ layout: web root is public/; root files are not served.
    repo.release(
        "v5.1.0",
        {
            "composer.json": "{}",
            "public/index.php": "<?php",
            "public/lib/javascript-static.js": "js-c",
            "public/theme/s.css": "css-3",
        },
    )
    return repo


def load(path: Path) -> dict:
    return json.loads(path.read_text())


def test_regression_update_builds_db_from_empty_state(upstream, tmp_path):
    # Upstream only updated when moodle_hashes.txt already had a first line.
    data_dir = tmp_path / "data"
    code = main(
        [
            "--update",
            "-q",
            "--data-dir",
            str(data_dir),
            "--cache-dir",
            str(tmp_path / "cache"),
            "--git-url",
            upstream.url,
        ]
    )
    assert code == 0
    db = load(data_dir / "fingerprints.json")
    assert db["tags"] == ["v4.4.0", "v4.5.0", "v4.5.1", "v5.1.0"]
    js = db["files"]["/lib/javascript-static.js"]
    assert js[git_blob_sha1(b"js-c")] == [3]  # public/ stripped for 5.1+
    assert not any(p.startswith("/public/") or p == "/composer.json" for p in db["files"])


def test_regression_incremental_update_processes_only_new_tags(upstream, tmp_path):
    db_path = tmp_path / "fingerprints.json"
    cache = tmp_path / "cache"
    assert update_fingerprints(db_path, cache_dir=cache, git_url=upstream.url, log=lambda _m: None)["new_tags"] == 4
    assert update_fingerprints(db_path, cache_dir=cache, git_url=upstream.url, log=lambda _m: None) == {
        "tags": 4,
        "new_tags": 0,
        "files": -1,
    }
    upstream.release("v4.5.2", {"index.php": "<?php", "lib/javascript-static.js": "js-b", "theme/s.css": "css-4"})
    stats = update_fingerprints(db_path, cache_dir=cache, git_url=upstream.url, log=lambda _m: None)
    assert stats["new_tags"] == 1
    assert load(db_path)["latest_tag"] == "v5.1.0"


def test_regression_new_double_digit_minor_is_newer(tmp_path):
    # Upstream: new_versions[0] > first_version compared "v5.10.0" < "v5.9.0" as strings.
    repo = UpstreamRepo(tmp_path / "up")
    repo.release("v5.9.0", {"index.php": "<?php", "a.js": "1"})
    repo.release("v5.9.1", {"index.php": "<?php", "a.js": "2"})
    db_path = tmp_path / "fp.json"
    update_fingerprints(db_path, cache_dir=tmp_path / "c", git_url=repo.url, log=lambda _m: None)
    repo.release("v5.10.0", {"index.php": "<?php", "a.js": "3"})
    stats = update_fingerprints(db_path, cache_dir=tmp_path / "c", git_url=repo.url, log=lambda _m: None)
    assert stats["new_tags"] == 1
    db = load(db_path)
    assert db["latest_tag"] == "v5.10.0" and db["tags"][-1] == "v5.10.0"


def test_update_output_is_deterministic(upstream, tmp_path):
    a, b = tmp_path / "a.json", tmp_path / "b.json"
    update_fingerprints(a, cache_dir=tmp_path / "c1", git_url=upstream.url, log=lambda _m: None)
    update_fingerprints(b, cache_dir=tmp_path / "c2", git_url=upstream.url, log=lambda _m: None)
    assert a.read_bytes() == b.read_bytes()


# --- advisories ----------------------------------------------------------------------


def msa_article(post: int, msa: str, title: str, affected: str, fixed: str, cve: str) -> str:
    return f"""
<article id="p{post}" class="forum-post-container" data-post-id="{post}">
  <h3 class="h6" data-region-content="forum-post-core-subject" data-reply-subject="{msa}: {title}">{msa}: {title}</h3>
  <time datetime="2025-03-26T02:00:00+08:00">x</time>
  <a href="https://moodle.org/mod/forum/discuss.php?d={post + 1000}#p{post}">Permalink</a>
  <table><tbody>
    <tr><td><em>Severity/Risk:</em></td><td><strong>Serious</strong></td></tr>
    <tr><td><em>Versions affected:</em></td><td>{affected}</td></tr>
    <tr><td><em>Versions fixed:</em></td><td><strong>{fixed}</strong></td></tr>
    <tr><td><em>Reported by:</em></td><td>Someone</td></tr>
    <tr><td><em>CVE identifier:</em></td><td>{cve}</td></tr>
    <tr><td><em>Tracker issue:</em></td><td>MDL-84879 Something</td></tr>
  </tbody></table>
</article>"""


def page(articles: list[str], last_page: int) -> str:
    pager = "".join(f'<li class="page-item" data-page-number="{n}"></li>' for n in range(1, last_page + 2))
    return f"<html><body><nav><ul>{pager}</ul></nav>{''.join(articles)}</body></html>"


def test_advisories_build_and_incremental_stop(site, tmp_path):
    p0 = page(
        [
            msa_article(
                2,
                "MSA-25-0011",
                "Unauthenticated REST API user data exposure",
                "4.5 to 4.5.2",
                "4.5.3",
                "CVE-2025-32044",
            )
        ],
        last_page=1,
    )
    p1 = page(
        [
            msa_article(
                1, "MSA-24-0040", "IDOR", "4.4 to 4.4.3 and earlier unsupported versions", "4.4.4", "CVE-2024-48901"
            )
        ],
        last_page=1,
    )
    site.add("/security/index.php?o=3&s=10&p=0", Reply(200, p0))
    site.add("/security/index.php?o=3&s=10&p=1", Reply(200, p1))
    db = tmp_path / "advisories.json"
    client = HttpClient(site.url)
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr("moodle_scanner.update.msa_scrape.SECURITY_INDEX", site.url + "security/index.php")
        stats = update_advisories(db, client, log=lambda _m: None)
        assert stats == {"pages": 2, "added": 2, "total": 2}
        data = load(db)
        first = data["advisories"][0]
        assert first["id"] == "MSA-25-0011" and first["affected"] == [{"from": "4.5.0", "to": "4.5.2"}]
        assert first["url"] == "https://moodle.org/mod/forum/discuss.php?d=1002"
        assert first["cves"] == ["CVE-2025-32044"] and first["trackers"] == ["MDL-84879"]
        assert set(first) >= {"id", "title", "severity", "affected_text", "fixed_text", "fixed", "parse_status"}
        # Incremental: page 0 has nothing new, so page 1 is not requested again.
        site.requests.clear()
        stats = update_advisories(db, HttpClient(site.url), log=lambda _m: None)
        assert stats["pages"] == 1 and stats["added"] == 0
        assert [p for _, p, _ in site.requests] == ["/security/index.php?o=3&s=10&p=0"]
