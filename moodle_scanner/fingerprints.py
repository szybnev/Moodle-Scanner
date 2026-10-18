"""Version detection from web-served static files and public page signals.

The fingerprint DB maps URL paths to ``git blob id -> tag indices``. Detection
is adaptive: at each step it fetches the pool file that best splits the
remaining candidate tags, so a typical scan needs 10-20 requests. Files that
are missing (404), blocked, or locally modified carry no information and are
simply skipped; contradictory matches (weekly builds, patched files) are kept
as evidence and resolved by majority instead of crashing.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from .httpclient import HttpClient, Response
from .versions import MoodleVersion

_BLOCKED_NAME_RE = re.compile(
    r"/(?:upgrade\.txt|UPGRADING\.md|README[^/]*|readme[^/]*|environment\.xml|install\.xml|thirdpartylibs\.xml"
    r"|composer\.(?:json|lock)|package\.json|npm-shrinkwrap\.json|Gruntfile\.js)$"
    r"|/(?:tests|fixtures|behat|vendor|node_modules)/"
    r"|\.(?:feature|md)$"
)

DEFAULT_MAX_REQUESTS = 40
CONFIRMATIONS = 2


def is_commonly_blocked(path: str) -> bool:
    """Developer-only files that hardened sites usually deny (Moodle security docs)."""
    return bool(_BLOCKED_NAME_RE.search(path))


def git_blob_sha1(content: bytes) -> str:
    return hashlib.sha1(b"blob %d\0" % len(content) + content).hexdigest()  # noqa: S324 - git object id, not security


@dataclass
class FingerprintDB:
    tags: list[str]
    files: dict[str, dict[str, frozenset[int]]]
    latest_tag: str

    @classmethod
    def load(cls, path: Path) -> FingerprintDB:
        data = json.loads(path.read_text(encoding="utf-8"))
        files = {p: {blob: frozenset(idxs) for blob, idxs in groups.items()} for p, groups in data["files"].items()}
        return cls(tags=data["tags"], files=files, latest_tag=data["latest_tag"])

    def present(self, path: str) -> frozenset[int]:
        out: set[int] = set()
        for idxs in self.files[path].values():
            out |= idxs
        return frozenset(out)


@dataclass
class FileEvidence:
    path: str
    status: int | None
    outcome: str  # match | unknown_hash | not_found | error | conflict
    sha1: str | None = None
    matched: list[str] = field(default_factory=list)
    error: str | None = None

    def to_json(self) -> dict:
        data: dict = {"path": self.path, "status": self.status, "outcome": self.outcome}
        if self.sha1:
            data["sha1"] = self.sha1
        if self.matched:
            data["matched_versions"] = _summarize(self.matched)
        if self.error:
            data["error"] = self.error
        return data


@dataclass
class VersionResult:
    status: str  # exact | ambiguous | branch | unknown
    confidence: str  # high | medium | low | none
    method: str  # file-fingerprint | public-signals | none
    candidates: list[str] = field(default_factory=list)
    version: str | None = None
    branch: str | None = None
    evidence: list[FileEvidence] = field(default_factory=list)
    signals: list[dict] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def candidate_versions(self) -> list[MoodleVersion]:
        return [MoodleVersion.parse(c) for c in self.candidates]

    def to_json(self) -> dict:
        versions = self.candidate_versions
        return {
            "status": self.status,
            "version": self.version,
            "candidates": self.candidates,
            "range": {"min": str(min(versions)), "max": str(max(versions))} if versions else None,
            "branch": self.branch,
            "confidence": self.confidence,
            "method": self.method,
            "evidence": [e.to_json() for e in self.evidence],
            "signals": self.signals,
            "notes": self.notes,
        }


def _summarize(versions: list[str]) -> str:
    if len(versions) <= 3:
        return ", ".join(versions)
    return f"{versions[0]} .. {versions[-1]} ({len(versions)} tags)"


def _pairs(path_groups: dict[str, frozenset[int]], candidates: frozenset[int]) -> int:
    counts = [len(idxs & candidates) for idxs in path_groups.values()]
    present = sum(counts)
    return (present * present - sum(c * c for c in counts)) // 2


class Detector:
    def __init__(self, client: HttpClient, db: FingerprintDB, max_requests: int = DEFAULT_MAX_REQUESTS) -> None:
        self.client = client
        self.db = db
        self.max_requests = max_requests
        self._versions = [MoodleVersion.parse(t) for t in db.tags]

    def _tag_names(self, idxs: frozenset[int] | set[int]) -> list[str]:
        return [str(self._versions[i]) for i in sorted(idxs, key=lambda i: self._versions[i])]

    def _probe(self, path: str) -> tuple[FileEvidence, frozenset[int] | None]:
        resp: Response = self.client.get(path)
        if resp.status is None:
            return FileEvidence(path, None, "error", error=resp.error), None
        if resp.status != 200 or resp.truncated:
            return FileEvidence(path, resp.status, "not_found"), None
        sha = git_blob_sha1(resp.body)
        matched = self.db.files[path].get(sha)
        if not matched:
            return FileEvidence(path, resp.status, "unknown_hash", sha1=sha), None
        return FileEvidence(path, resp.status, "match", sha1=sha, matched=self._tag_names(matched)), matched

    def run(self) -> VersionResult:
        candidates = frozenset(range(len(self.db.tags)))
        tried: set[str] = set()
        evidence: list[FileEvidence] = []
        matches: list[frozenset[int]] = []
        requests = 0
        while requests < self.max_requests and len(candidates) > 1 and not self.client.budget_exhausted:
            best_path, best_score = None, 0.0
            for path, groups in self.db.files.items():
                if path in tried:
                    continue
                score = _pairs(groups, candidates) * (0.25 if is_commonly_blocked(path) else 1.0)
                if score > best_score:  # files iterate in sorted path order: ties keep the first path
                    best_path, best_score = path, score
            if best_path is None or best_score == 0:
                break
            tried.add(best_path)
            requests += 1
            ev, matched = self._probe(best_path)
            evidence.append(ev)
            if matched is None:
                continue
            narrowed = candidates & matched
            if narrowed:
                candidates = narrowed
                matches.append(matched)
            else:
                ev.outcome = "conflict"
                matches.append(matched)
        if len(candidates) == 1 and matches and not self.client.budget_exhausted:
            (only,) = candidates
            extra = sorted(
                (p for p in self.db.files if p not in tried and only in self.db.present(p)),
                key=lambda p: (is_commonly_blocked(p), min(len(i) for i in self.db.files[p].values() if only in i), p),
            )
            confirmed = 0
            for path in extra:
                if confirmed >= CONFIRMATIONS or requests >= self.max_requests + CONFIRMATIONS * 2:
                    break
                tried.add(path)
                requests += 1
                ev, matched = self._probe(path)
                evidence.append(ev)
                if matched is None:
                    continue
                matches.append(matched)
                if only in matched:
                    confirmed += 1
                else:
                    ev.outcome = "conflict"
        return self._conclude(candidates, matches, evidence)

    def _conclude(
        self, candidates: frozenset[int], matches: list[frozenset[int]], evidence: list[FileEvidence]
    ) -> VersionResult:
        if not matches:
            return VersionResult(status="unknown", confidence="none", method="none", evidence=evidence)
        conflicts = [e for e in evidence if e.outcome == "conflict"]
        notes = []
        if conflicts:
            # Majority vote across every matched file: weekly builds and local
            # patches produce a minority of files from a neighbouring release.
            support: dict[int, int] = {}
            for m in matches:
                for i in m:
                    support[i] = support.get(i, 0) + 1
            top = max(support.values())
            chosen = frozenset(i for i, n in support.items() if n == top)
            notes.append(
                f"{len(conflicts)} file(s) matched other releases (weekly build, partial upgrade or local patch); "
                f"version chosen by majority of {len(matches)} matching files"
            )
            candidates = chosen
        names = self._tag_names(candidates)
        versions = [MoodleVersion.parse(n) for n in names]
        branches = {v.branch_str for v in versions}
        branch = branches.pop() if len(branches) == 1 else None
        unknown = [e.path for e in evidence if e.outcome == "unknown_hash"]
        if unknown:
            notes.append(
                f"{len(unknown)} file(s) had hashes of no release (modified or newer weekly build): "
                + ", ".join(unknown[:5])
            )
        version = None
        if len(names) == 1:
            agreeing = sum(1 for m in matches if candidates <= m)
            confidence = "high" if agreeing >= 2 and not conflicts else "medium"
            status = "exact"
            version = names[0]
        elif len({v.release for v in versions}) == 1 and not versions[-1].is_prerelease:
            # Typically x.y.z-rcN vs x.y.z: the final release only bumps
            # version.php, which is never served. Production sites run finals.
            status = "exact"
            confidence = "medium"
            version = names[-1]
            notes.append(
                f"{version} is indistinguishable from its pre-release(s) {', '.join(names[:-1])} by public files; "
                "reporting the final release"
            )
        else:
            confidence = "medium" if branch else "low"
            status = "ambiguous"
            notes.append(f"{len(names)} releases share identical public files: {_summarize(names)}")
        return VersionResult(
            status=status,
            confidence=confidence,
            method="file-fingerprint",
            candidates=names,
            version=version,
            branch=branch,
            evidence=evidence,
            notes=notes,
        )


_UPGRADE_TXT_RE = re.compile(r"^===\s*(\d+\.\d+)(?:\.\d+)?\s*===", re.M)
_UPGRADING_MD_RE = re.compile(r"^##\s*v?(\d+\.\d+)(?:\.\d+)?\+?\s*$", re.M)
_DOCS_LINK_RE = re.compile(r"docs\.moodle\.org/(\d)(\d{1,2})/")


def branch_signals(client: HttpClient, pages: list[Response]) -> list[dict]:
    """Major.minor hints from public text when file hashes do not match."""
    signals = []
    for resp in pages:
        for m in _DOCS_LINK_RE.finditer(resp.text):
            signals.append({"source": resp.url, "kind": "docs-link", "branch": f"{m.group(1)}.{int(m.group(2))}"})
            break
    for path, regex, kind in (
        ("/lib/upgrade.txt", _UPGRADE_TXT_RE, "upgrade-notes"),
        ("/UPGRADING.md", _UPGRADING_MD_RE, "upgrade-notes"),
    ):
        resp = client.get(path)
        if resp.status == 200 and (m := regex.search(resp.text)):
            signals.append({"source": resp.url, "kind": kind, "branch": m.group(1)})
    return signals


def apply_signals(result: VersionResult, signals: list[dict]) -> VersionResult:
    result.signals = signals
    if result.status != "unknown" or not signals:
        return result
    branches = sorted({s["branch"] for s in signals}, key=lambda b: tuple(int(x) for x in b.split(".")))
    newest = branches[-1]
    result.status = "branch"
    result.method = "public-signals"
    result.branch = newest
    result.confidence = "low"
    result.candidates = []
    if len(branches) > 1:
        result.notes.append("public signals disagree: " + ", ".join(branches))
    return result
