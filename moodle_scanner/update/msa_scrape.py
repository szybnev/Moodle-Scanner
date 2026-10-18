"""Extract structured facts from moodle.org security announcement pages.

Only facts are kept: advisory id, short title, publication date, severity,
affected/fixed version lists, CVE ids, tracker id and the announcement URL.
Advisory prose is deliberately not stored.
"""

from __future__ import annotations

import html
import re
from dataclasses import dataclass, field
from html.parser import HTMLParser

SECURITY_INDEX = "https://moodle.org/security/index.php"
DISCUSS_URL = "https://moodle.org/mod/forum/discuss.php?d={}"

_ARTICLE_SPLIT = re.compile(r"<article\b", re.IGNORECASE)
_SUBJECT_RE = re.compile(r'data-region-content="forum-post-core-subject"[^>]*>(.*?)</h3>', re.S | re.I)
_TIME_RE = re.compile(r'<time datetime="([^"]+)"')
_DISCUSS_RE = re.compile(r"discuss\.php\?d=(\d+)")
_MSA_RE = re.compile(r"\bMSA-\d{2}-\d{4}\b")
_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b")
_MDL_RE = re.compile(r"\bMDL-\d+\b")
_LAST_PAGE_RE = re.compile(r'data-page-number="(\d+)"')


@dataclass
class RawAdvisory:
    msa_id: str
    title: str
    published: str
    url: str
    fields: dict[str, str] = field(default_factory=dict)


class _TableParser(HTMLParser):
    """Collect two-column <tr><td>label</td><td>value</td></tr> rows."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.rows: list[list[str]] = []
        self._cell: list[str] | None = None
        self._row: list[str] | None = None

    def handle_starttag(self, tag: str, attrs) -> None:  # noqa: ANN001 - stdlib signature
        if tag == "tr":
            self._row = []
        elif tag in ("td", "th") and self._row is not None:
            self._cell = []
        elif tag == "br" and self._cell is not None:
            self._cell.append(" ")

    def handle_endtag(self, tag: str) -> None:
        if tag in ("td", "th") and self._cell is not None and self._row is not None:
            self._row.append(" ".join("".join(self._cell).split()))
            self._cell = None
        elif tag == "tr" and self._row is not None:
            self.rows.append(self._row)
            self._row = None

    def handle_data(self, data: str) -> None:
        if self._cell is not None:
            self._cell.append(data)


def _field_name(label: str) -> str | None:
    label = label.lower().rstrip(":").strip()
    if label.startswith("severity"):
        return "severity"
    if label.startswith("versions affected"):
        return "affected"
    if label.startswith("versions fixed"):
        return "fixed"
    if label.startswith("cve"):
        return "cve"
    if label.startswith("tracker"):
        return "tracker"
    return None


def parse_page(page_html: str) -> list[RawAdvisory]:
    """Parse one security index page into raw advisories (only MSA posts)."""
    advisories = []
    for chunk in _ARTICLE_SPLIT.split(page_html)[1:]:
        subject_match = _SUBJECT_RE.search(chunk)
        if not subject_match:
            continue
        subject = " ".join(html.unescape(re.sub(r"<[^>]+>", "", subject_match.group(1))).split())
        msa = _MSA_RE.search(subject)
        if not msa:
            continue
        title = subject[msa.end() :].lstrip(" :–-").strip()
        time_match = _TIME_RE.search(chunk)
        discuss = _DISCUSS_RE.search(chunk)
        table = _TableParser()
        table.feed(chunk)
        fields: dict[str, str] = {}
        for row in table.rows:
            if len(row) >= 2:
                name = _field_name(row[0])
                if name and name not in fields:
                    fields[name] = row[1]
        advisories.append(
            RawAdvisory(
                msa_id=msa.group(0),
                title=title,
                published=time_match.group(1)[:10] if time_match else "",
                url=DISCUSS_URL.format(discuss.group(1)) if discuss else SECURITY_INDEX,
                fields=fields,
            )
        )
    return advisories


def last_page_index(page_html: str) -> int:
    """Zero-based index of the last pagination page (0 when no pager)."""
    numbers = [int(n) for n in _LAST_PAGE_RE.findall(page_html)]
    return max(numbers) - 1 if numbers else 0


def page_url(page: int) -> str:
    return f"{SECURITY_INDEX}?o=3&s=10&p={page}"


def extract_ids(text: str, pattern: re.Pattern[str]) -> list[str]:
    return sorted(
        set(pattern.findall(text)), key=lambda s: [int(p) if p.isdigit() else p for p in re.split(r"(\d+)", s)]
    )


def cves(text: str) -> list[str]:
    return extract_ids(text, _CVE_RE)


def tracker_ids(text: str) -> list[str]:
    return extract_ids(text, _MDL_RE)
