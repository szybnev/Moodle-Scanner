"""Test support: a local HTTP server replaying recorded responses, and synthetic data files.

The recorded responses mirror status codes, headers and the specific markers
observed on the lab instances (see docs/validation-matrix.md). Bodies are
minimal hand-written stand-ins: no Moodle source or page content is copied
into this repository.
"""

from __future__ import annotations

import json
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from moodle_scanner.fingerprints import git_blob_sha1

FIXTURES = Path(__file__).parent / "fixtures"


@dataclass
class Reply:
    status: int = 200
    body: bytes | str = b""
    headers: dict[str, str] = field(default_factory=dict)
    delay: float = 0.0

    def payload(self) -> bytes:
        return self.body.encode() if isinstance(self.body, str) else self.body


class FixtureSite:
    """Routes keyed by path (including query string); everything else is 404."""

    def __init__(self) -> None:
        self.routes: dict[str, Reply | Callable[[], Reply]] = {}
        self.requests: list[tuple[str, str, dict[str, str]]] = []
        self.default = Reply(404, "<html><body>Not Found</body></html>", {"Content-Type": "text/html"})
        self._server: ThreadingHTTPServer | None = None

    @property
    def url(self) -> str:
        assert self._server is not None
        host, port = self._server.server_address[:2]
        return f"http://{host}:{port}/"

    def add(self, path: str, reply: Reply | Callable[[], Reply]) -> None:
        self.routes[path] = reply

    def load(self, name: str) -> None:
        """Load a recorded response set from tests/fixtures/<name>.json."""
        data = json.loads((FIXTURES / f"{name}.json").read_text())
        for path, spec in data["responses"].items():
            self.add(path, Reply(spec.get("status", 200), spec.get("body", ""), spec.get("headers", {})))

    def start(self) -> None:
        site = self

        class Handler(BaseHTTPRequestHandler):
            def _serve(self, with_body: bool) -> None:
                site.requests.append((self.command, self.path, dict(self.headers)))
                route = site.routes.get(self.path, site.default)
                reply = route() if callable(route) else route
                if reply.delay:
                    time.sleep(reply.delay)
                body = reply.payload()
                self.send_response(reply.status)
                for key, value in reply.headers.items():
                    self.send_header(key, value)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                if with_body:
                    try:
                        self.wfile.write(body)
                    except (BrokenPipeError, ConnectionResetError):
                        pass

            def do_GET(self) -> None:  # noqa: N802 - stdlib naming
                self._serve(True)

            def do_HEAD(self) -> None:  # noqa: N802
                self._serve(False)

            def log_message(self, *args) -> None:  # noqa: ANN002
                return

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._server.daemon_threads = True
        threading.Thread(target=self._server.serve_forever, daemon=True).start()

    def stop(self) -> None:
        if self._server:
            self._server.shutdown()
            self._server.server_close()


# --- synthetic data ------------------------------------------------------------

TAGS = ["v4.4.0", "v4.5.0-rc1", "v4.5.0", "v4.5.1", "v4.5.2", "v5.3.0-rc2", "v5.3.0"]

# File content per tag: invented byte strings standing in for static assets.
FILES: dict[str, dict[str, bytes]] = {
    "/lib/javascript-static.js": {
        "v4.4.0": b"js-44",
        "v4.5.0-rc1": b"js-45",
        "v4.5.0": b"js-45",
        "v4.5.1": b"js-45",
        "v4.5.2": b"js-45",
        "v5.3.0-rc2": b"js-53",
        "v5.3.0": b"js-53",
    },
    "/lib/amd/build/editor.min.js": {
        "v4.4.0": b"ed-1",
        "v4.5.0-rc1": b"ed-2",
        "v4.5.0": b"ed-2",
        "v4.5.1": b"ed-3",
        "v4.5.2": b"ed-3",
        "v5.3.0-rc2": b"ed-9",
        "v5.3.0": b"ed-9",
    },
    "/theme/boost/style/moodle.css": {
        "v4.4.0": b"css-a",
        "v4.5.0-rc1": b"css-b",
        "v4.5.0": b"css-c",
        "v4.5.1": b"css-c",
        "v4.5.2": b"css-d",
        "v5.3.0-rc2": b"css-z",
        "v5.3.0": b"css-z",
    },
    "/lib/upgrade.txt": {
        "v4.4.0": b"=== 4.4 ===\n",
        "v4.5.0-rc1": b"=== 4.5 ===\n",
        "v4.5.0": b"=== 4.5 ===\n",
        "v4.5.1": b"=== 4.5 ===\n",
        "v4.5.2": b"=== 4.5 ===\nx\n",
    },
}


def fingerprint_db() -> dict:
    files: dict[str, dict[str, list[int]]] = {}
    for path, per_tag in FILES.items():
        groups: dict[str, list[int]] = {}
        for idx, tag in enumerate(TAGS):
            if tag in per_tag:
                groups.setdefault(git_blob_sha1(per_tag[tag]), []).append(idx)
        files[path] = groups
    return {
        "schema_version": 1,
        "source": "test",
        "hash": "git-blob-sha1",
        "latest_tag": TAGS[-1],
        "tag_count": len(TAGS),
        "tags": TAGS,
        "files": files,
    }


def advisory(msa: str, affected: str, fixed: str, cve: str = "", severity: str = "Serious") -> dict:
    from moodle_scanner.update.advisories import advisory_record
    from moodle_scanner.update.msa_scrape import RawAdvisory

    raw = RawAdvisory(
        msa_id=msa,
        title=f"Test advisory {msa}",
        published="2025-03-26",
        url="https://moodle.org/mod/forum/discuss.php?d=1",
        fields={"severity": severity, "affected": affected, "fixed": fixed, "cve": cve, "tracker": "MDL-1 test"},
    )
    return advisory_record(raw)


ADVISORIES = [
    advisory("MSA-25-0011", "4.5 to 4.5.2", "4.5.3", "CVE-2025-32044"),
    advisory(
        "MSA-24-0040",
        "4.4 to 4.4.3, 4.1 to 4.1.13 and earlier unsupported versions",
        "4.4.4 and 4.1.14",
        "CVE-2024-48901",
        "Minor",
    ),
    advisory("MSA-26-0001", "5.3.0", "5.3.1", "CVE-2026-00001", "Critical"),
]

PLUGINS = {
    "schema_version": 1,
    "source": "test",
    "types": {"mod": "mod", "block": "blocks", "local": "local", "theme": "theme"},
    "plugins": [
        {
            "component": "block_xp",
            "last_released": 3,
            "versions": [{"version": "2026100300", "release": "21.0", "moodle": ["4.5"]}],
        },
        {
            "component": "mod_customcert",
            "last_released": 2,
            "versions": [{"version": "2021051704", "release": "3.11.3", "moodle": ["3.11"]}],
        },
        {"component": "mod_chat", "last_released": 1, "versions": [], "core_in": ["4.4", "4.5"]},
    ],
}


def write_data(directory: Path) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "fingerprints.json").write_text(json.dumps(fingerprint_db()))
    (directory / "advisories.json").write_text(
        json.dumps(
            {"schema_version": 1, "count": len(ADVISORIES), "latest_published": "2025-03-26", "advisories": ADVISORIES}
        )
    )
    (directory / "plugins.json").write_text(json.dumps(PLUGINS))
    return directory


def serve_version(site: FixtureSite, tag: str, blocked: tuple[str, ...] = ()) -> None:
    """Serve the synthetic static files of ``tag`` plus a minimal Moodle login page."""
    for path, per_tag in FILES.items():
        if tag in per_tag and path not in blocked:
            site.add(path, Reply(200, per_tag[tag], {"Content-Type": "application/octet-stream"}))
    site.load("moodle_pages")
