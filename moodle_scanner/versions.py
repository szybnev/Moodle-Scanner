"""Moodle version parsing and ordering.

Moodle release identifiers come in several shapes:

* git tags: ``v4.5.0``, ``v5.1.0-beta``, ``v5.3.0-rc2``, ``v2.0`` (early tags);
* advisory text: ``4.5``, ``4.5.2``, ``3.10.x``;
* release strings: ``4.5.2+ (Build: 20250221)`` where ``+`` marks a weekly build
  newer than the release it follows.

Ordering is numeric and pre-release aware::

    4.5.0-beta < 4.5.0-rc1 < 4.5.0-rc2 < 4.5.0 < 4.5.0+ < 4.5.1

Plain string comparison gets this wrong (``"v5.10.0" < "v5.9.0"``), which is the
upstream defect this module replaces.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import total_ordering

_STAGE_BETA = 1
_STAGE_RC = 2
_STAGE_FINAL = 3

_VERSION_RE = re.compile(
    r"""
    ^\s*v?
    (?P<major>\d+)\.(?P<minor>\d+)(?:\.(?P<patch>\d+|x))?
    (?:[-\s]?(?P<stage>beta|rc)(?P<stagenum>\d*))?
    (?P<plus>\+)?
    (?:\s*\(.*\))?
    \s*$
    """,
    re.IGNORECASE | re.VERBOSE,
)


class InvalidVersion(ValueError):
    """Raised when a string is not a recognisable Moodle version."""


@total_ordering
@dataclass(frozen=True)
class MoodleVersion:
    major: int
    minor: int
    patch: int = 0
    stage: int = _STAGE_FINAL
    stage_num: int = 0
    weekly: bool = False

    @classmethod
    def parse(cls, text: str) -> MoodleVersion:
        match = _VERSION_RE.match(text)
        if not match:
            raise InvalidVersion(f"not a Moodle version: {text!r}")
        patch = match["patch"]
        stage_name = (match["stage"] or "").lower()
        stage = {"beta": _STAGE_BETA, "rc": _STAGE_RC}.get(stage_name, _STAGE_FINAL)
        return cls(
            major=int(match["major"]),
            minor=int(match["minor"]),
            patch=0 if patch in (None, "x", "X") else int(patch),
            stage=stage,
            stage_num=int(match["stagenum"] or 0),
            weekly=bool(match["plus"]),
        )

    @classmethod
    def try_parse(cls, text: str) -> MoodleVersion | None:
        try:
            return cls.parse(text)
        except InvalidVersion:
            return None

    @property
    def branch(self) -> tuple[int, int]:
        return (self.major, self.minor)

    @property
    def branch_str(self) -> str:
        return f"{self.major}.{self.minor}"

    @property
    def release(self) -> tuple[int, int, int]:
        return (self.major, self.minor, self.patch)

    @property
    def is_prerelease(self) -> bool:
        return self.stage != _STAGE_FINAL

    def _key(self) -> tuple[int, int, int, int, int, int]:
        return (self.major, self.minor, self.patch, self.stage, self.stage_num, int(self.weekly))

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, MoodleVersion):
            return NotImplemented
        return self._key() < other._key()

    def __str__(self) -> str:
        text = f"{self.major}.{self.minor}.{self.patch}"
        if self.stage == _STAGE_BETA:
            text += f"-beta{self.stage_num or ''}"
        elif self.stage == _STAGE_RC:
            text += f"-rc{self.stage_num or ''}"
        if self.weekly:
            text += "+"
        return text


def tag_sort_key(tag: str) -> tuple[int, ...]:
    """Sort key for git tag names; unparsable tags sort first."""
    version = MoodleVersion.try_parse(tag)
    return (1, *version._key()) if version else (0,)


def is_release_tag(tag: str) -> bool:
    """True for tags that name a Moodle release or pre-release (``v4.5.0``, ``v5.1.0-rc1``)."""
    return tag.startswith("v") and MoodleVersion.try_parse(tag) is not None and "+" not in tag
