"""Moodle security advisories (MSA): structured ranges and version matching.

Advisory text on moodle.org lists affected versions per stable branch, e.g.
``"4.4 to 4.4.3, 4.3 to 4.3.7, 4.1 to 4.1.13 and earlier unsupported versions"``.
This module turns that text into explicit ranges once, at data-update time,
and matches a detected version against the stored ranges at scan time.

"Earlier unsupported versions" is an imprecise historical qualifier, not proof
that a vulnerability existed in every older release. It produces possible
matches only, and never fills gaps between explicitly listed branches.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from .versions import MoodleVersion

_VER = r"\d+\.\d+(?:\.(?:\d+|x))?"
_TOKEN_RE = re.compile(
    rf"(?P<lo>{_VER})\+?\s*(?:to|-|through|until)\s*(?P<hi>{_VER})\+?"
    rf"|(?:<=|up to|upto)\s*(?P<upto>{_VER})\+?"
    rf"|(?:<|prior to|before)\s*(?P<below>{_VER})\+?"
    rf"|(?P<single>{_VER})\+?"
)
_EARLIER_RE = re.compile(
    r"(?:and\s+)?(?:all\s+)?(?:earlier|older|previous|prior|other)\s+(?:unsupported\s+|supported\s+)?versions?"
    r"|(?:and|or)\s+(?:earlier|older|below)\b",
)
_PAREN_RE = re.compile(r"\([^)]*\)")
_FILLER_RE = re.compile(r"\b(?:moodle|versions?|only|branch(?:es)?|lts|and|or|to)\b|[,;&.:+\s]")
_EXCLUSION_RE = re.compile(r"\b(?:except(?:ing)?|excluding|not affected|unaffected)\b")

INF_PATCH = 10**6


@dataclass(frozen=True)
class AffectedRange:
    """Inclusive range of releases within one branch (or spanning branches)."""

    lo: tuple[int, int, int]
    hi: tuple[int, int, int]

    @property
    def branches(self) -> set[tuple[int, int]]:
        if self.lo[:2] == self.hi[:2]:
            return {self.lo[:2]}
        return {self.lo[:2], self.hi[:2]}

    def to_json(self) -> dict[str, str]:
        hi_patch = "x" if self.hi[2] >= INF_PATCH else str(self.hi[2])
        return {"from": "{}.{}.{}".format(*self.lo), "to": f"{self.hi[0]}.{self.hi[1]}.{hi_patch}"}

    @classmethod
    def from_json(cls, data: dict[str, str]) -> AffectedRange:
        return cls(lo=_release(data["from"], upper=False), hi=_release(data["to"], upper=True))

    def __str__(self) -> str:
        data = self.to_json()
        return data["from"] if data["from"] == data["to"] else f"{data['from']} to {data['to']}"


def _release(text: str, *, upper: bool) -> tuple[int, int, int]:
    parts = text.split(".")
    major, minor = int(parts[0]), int(parts[1])
    if len(parts) < 3:
        return (major, minor, 0)
    if parts[2] == "x":
        return (major, minor, INF_PATCH if upper else 0)
    return (major, minor, int(parts[2]))


@dataclass
class ParsedRanges:
    ranges: list[AffectedRange] = field(default_factory=list)
    earlier_unsupported: bool = False
    unparsed: list[str] = field(default_factory=list)
    excluded: list[AffectedRange] = field(default_factory=list)


def parse_affected(text: str) -> ParsedRanges:
    """Parse the "Versions affected" field of an advisory.

    Anything that is not a version, a range, or an "earlier unsupported
    versions" clause is reported in ``unparsed`` so the data update can flag
    the advisory instead of silently matching it wrongly.
    """
    result = ParsedRanges()
    norm = text.lower().replace("\u2013", "-").replace("\u2014", "-").replace("\xa0", " ")
    # Exclusions must survive parsing and serialization. Unknown parenthetical
    # qualifications make the result partial instead of silently disappearing.
    earlier_unaffected = False
    for note in _PAREN_RE.findall(norm):
        content = note[1:-1].strip()
        if re.fullmatch(r"(?:earlier|older|previous) versions? (?:unaffected|not affected)", content):
            earlier_unaffected = True
        elif _EXCLUSION_RE.search(content):
            excluded = parse_affected(_EXCLUSION_RE.sub(" ", content))
            result.excluded.extend(excluded.ranges)
            result.unparsed.extend(excluded.unparsed)
            if not excluded.ranges:
                result.unparsed.append(content)
        else:
            result.unparsed.append(content)
    norm = _PAREN_RE.sub(" ", norm)
    # The same explicit exclusion syntax is also used outside parentheses.
    exclusion = _EXCLUSION_RE.search(norm)
    if exclusion:
        excluded = parse_affected(norm[exclusion.end() :])
        result.excluded.extend(excluded.ranges)
        result.unparsed.extend(excluded.unparsed)
        if not excluded.ranges:
            result.unparsed.append(norm[exclusion.start() :].strip())
        norm = norm[: exclusion.start()]
    if _EARLIER_RE.search(norm):
        result.earlier_unsupported = True
        norm = _EARLIER_RE.sub(" ", norm)
    leftover = norm
    for m in _TOKEN_RE.finditer(norm):
        if m["lo"]:
            lo, hi = _release(m["lo"], upper=False), _release(m["hi"], upper=True)
            if lo > hi:
                continue
            result.ranges.append(AffectedRange(lo, hi))
        elif m["upto"]:
            hi = _release(m["upto"], upper=True)
            result.ranges.append(AffectedRange((hi[0], hi[1], 0), hi))
            result.earlier_unsupported = True
        elif m["below"]:
            hi = _release(m["below"], upper=False)
            if hi[2] == 0:
                # No release of this branch is below its initial release.
                # Preserve older-version candidates without inventing a known
                # affected lower bound from the bundled release list.
                if hi[1] > 0:
                    previous = (hi[0], hi[1] - 1, INF_PATCH)
                elif hi[0] > 0:
                    previous = (hi[0] - 1, INF_PATCH, INF_PATCH)
                else:
                    leftover = leftover.replace(m.group(0), " ", 1)
                    continue
                result.ranges.append(AffectedRange((0, 0, 0), previous))
                result.unparsed.append("exclusive branch bound has no specified affected lower bound")
            else:
                result.ranges.append(AffectedRange((hi[0], hi[1], 0), (hi[0], hi[1], hi[2] - 1)))
                result.earlier_unsupported = True
        else:
            raw = m["single"]
            result.ranges.append(AffectedRange(_release(raw, upper=False), _release(raw, upper=True)))
        leftover = leftover.replace(m.group(0), " ", 1)
    leftover = _FILLER_RE.sub(" ", leftover).strip()
    if leftover:
        result.unparsed.append(" ".join(leftover.split()))
    if earlier_unaffected:
        result.earlier_unsupported = False
    return result


def parse_fixed(text: str) -> list[str]:
    """Versions listed in the "Versions fixed" field, normalised, newest first."""
    found = {MoodleVersion.parse(v) for v in re.findall(r"\d+\.\d+(?:\.\d+)?", text)}
    return [str(v) for v in sorted(found, reverse=True)]


@dataclass(frozen=True)
class Advisory:
    id: str
    title: str
    published: str
    severity: str
    cves: tuple[str, ...]
    trackers: tuple[str, ...]
    url: str
    affected_text: str
    fixed_text: str
    ranges: tuple[AffectedRange, ...]
    earlier_unsupported: bool
    fixed: tuple[str, ...]
    parse_status: str
    excluded: tuple[AffectedRange, ...] = ()

    @classmethod
    def from_json(cls, data: dict) -> Advisory:
        # Stored ranges are a cache of parser output, not authoritative facts.
        # Custom data directories may have been generated by an older parser.
        parsed = parse_affected(data["affected_text"])
        status = "unparsed" if not parsed.ranges else "partial" if parsed.unparsed else "ok"
        return cls(
            id=data["id"],
            title=data["title"],
            published=data["published"],
            severity=data["severity"],
            cves=tuple(data["cves"]),
            trackers=tuple(data["trackers"]),
            url=data["url"],
            affected_text=data["affected_text"],
            fixed_text=data["fixed_text"],
            ranges=tuple(parsed.ranges),
            earlier_unsupported=parsed.earlier_unsupported,
            fixed=tuple(parse_fixed(data["fixed_text"])),
            parse_status=status,
            excluded=tuple(parsed.excluded),
        )

    @property
    def listed_branches(self) -> set[tuple[int, int]]:
        branches: set[tuple[int, int]] = set()
        for r in self.ranges:
            branches |= r.branches
        return branches

    @property
    def severity_level(self) -> str:
        return severity_level(self.severity)

    def fixed_in_branch(self, branch: tuple[int, int]) -> MoodleVersion | None:
        versions = [v for v in (MoodleVersion.parse(f) for f in self.fixed) if v.branch == branch]
        return min(versions) if versions else None


def severity_level(severity: str) -> str:
    """Normalise moodle.org severity wording to critical/high/medium/low/unknown.

    moodle.org uses Critical, Serious and Major (historically interchangeable
    for high impact), Minor, and occasionally Low/Very low.
    """
    text = severity.lower()
    if "critical" in text and "non critical" not in text:
        return "critical"
    if any(word in text for word in ("serious", "major", "high")):
        return "high"
    if any(word in text for word in ("minor", "non critical", "potential")):
        return "medium"
    if "low" in text:
        return "low"
    return "unknown"


@dataclass(frozen=True)
class Assessment:
    status: str  # "affected" | "possibly_affected"
    reason: str


def assess(advisory: Advisory, version: MoodleVersion) -> Assessment | None:
    """Decide whether ``version`` is affected by ``advisory``.

    Pre-releases of x.y.z are correlated with x.y.z, but only as possible
    matches. Weekly builds at the upper bound and imprecise or partially parsed
    historical qualifications are also possible matches, not definite ones.
    """
    if advisory.parse_status == "unparsed":
        return None
    fixed = advisory.fixed_in_branch(version.branch)
    if fixed is not None and version.release >= fixed.release and not version.is_prerelease:
        return None
    release = version.release
    if any(r.lo <= version.release <= r.hi for r in advisory.excluded):
        return None
    for rng in advisory.ranges:
        if not (rng.lo <= release <= rng.hi):
            continue
        if advisory.parse_status != "ok":
            return Assessment(
                "possibly_affected", f"{version} matches {rng}, but advisory qualifications were not fully parsed"
            )
        if version.is_prerelease:
            return Assessment(
                "possibly_affected", f"{version} is a pre-release of a release within {rng}" + _fixed_note(fixed)
            )
        if release == rng.hi and version.weekly:
            return Assessment("possibly_affected", f"{version} is a weekly build after {rng}; the fix may be included")
        return Assessment("affected", f"{version} is within affected range {rng}" + _fixed_note(fixed))
    if advisory.earlier_unsupported and advisory.ranges:
        listed = advisory.listed_branches
        oldest = min(listed)
        if version.branch < oldest:
            return Assessment(
                "possibly_affected",
                f"branch {version.branch_str} predates the oldest explicitly listed branch {oldest[0]}.{oldest[1]}; "
                "earlier unsupported versions are mentioned without an exact affected lower bound",
            )
    return None


def _fixed_note(fixed: MoodleVersion | None) -> str:
    return f" (fixed in {fixed})" if fixed else ""


def assess_candidates(advisory: Advisory, candidates: list[MoodleVersion]) -> Assessment | None:
    """Combine per-candidate assessments when the exact version is ambiguous."""
    results = [assess(advisory, v) for v in candidates]
    hits = [r for r in results if r is not None]
    if not hits:
        return None
    if len(hits) == len(results) and all(r.status == "affected" for r in hits):
        return (
            hits[0]
            if len(candidates) == 1
            else Assessment("affected", f"all candidate versions affected: {hits[0].reason}")
        )
    return Assessment(
        "possibly_affected",
        f"{len(hits)} of {len(candidates)} candidate versions affected: {hits[0].reason}",
    )


def load_advisories(path: Path) -> list[Advisory]:
    data = json.loads(path.read_text(encoding="utf-8"))
    return [Advisory.from_json(item) for item in data["advisories"]]
