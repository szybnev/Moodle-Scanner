"""Build or incrementally refresh ``advisories.json`` from moodle.org.

Incremental mode walks the security index newest-first and stops at the first
page whose advisories are all already known. ``full=True`` re-reads every page.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

from ..advisories import parse_affected, parse_fixed
from ..httpclient import HttpClient
from . import msa_scrape

SCHEMA_VERSION = 1


def advisory_record(raw: msa_scrape.RawAdvisory) -> dict:
    affected_text = raw.fields.get("affected", "")
    fixed_text = raw.fields.get("fixed", "")
    parsed = parse_affected(affected_text)
    if not parsed.ranges:
        status = "unparsed"
    elif parsed.unparsed:
        status = "partial"
    else:
        status = "ok"
    return {
        "id": raw.msa_id,
        "title": raw.title,
        "published": raw.published,
        "severity": raw.fields.get("severity", ""),
        "cves": msa_scrape.cves(raw.fields.get("cve", "")),
        "trackers": msa_scrape.tracker_ids(raw.fields.get("tracker", "")),
        "url": raw.url,
        "affected_text": affected_text,
        "fixed_text": fixed_text,
        "affected": [r.to_json() for r in parsed.ranges],
        "earlier_unsupported": parsed.earlier_unsupported,
        "fixed": parse_fixed(fixed_text),
        "parse_status": status,
    }


def _sort_key(record: dict) -> tuple[str, int, int]:
    _, year, num = record["id"].split("-")
    return (record["published"], int(year), int(num))


def write_db(path: Path, records: dict[str, dict]) -> None:
    ordered = sorted(records.values(), key=_sort_key, reverse=True)
    data = {
        "schema_version": SCHEMA_VERSION,
        "source": msa_scrape.SECURITY_INDEX,
        "latest_published": ordered[0]["published"] if ordered else "",
        "count": len(ordered),
        "advisories": ordered,
    }
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    tmp.replace(path)


def load_existing(path: Path) -> dict[str, dict]:
    if not path.exists():
        return {}
    data = json.loads(path.read_text(encoding="utf-8"))
    return {item["id"]: item for item in data.get("advisories", [])}


def update_advisories(
    path: Path,
    client: HttpClient,
    *,
    full: bool = False,
    log: Callable[[str], None] = print,
) -> dict[str, int]:
    """Refresh the advisory DB at ``path``. Returns counters for reporting."""
    existing = load_existing(path)
    records = dict(existing)
    first = client.get(msa_scrape.page_url(0))
    if not first.ok:
        raise RuntimeError(f"moodle.org security index: HTTP {first.status} {first.error or ''}".strip())
    last = msa_scrape.last_page_index(first.text)
    added = 0
    pages = 0
    for page in range(0, last + 1):
        resp = first if page == 0 else client.get(msa_scrape.page_url(page))
        if not resp.ok:
            raise RuntimeError(f"moodle.org security page {page}: HTTP {resp.status} {resp.error or ''}".strip())
        pages += 1
        raws = msa_scrape.parse_page(resp.text)
        if not raws:
            break
        new_on_page = 0
        for raw in raws:
            if raw.msa_id not in records:
                new_on_page += 1
            records[raw.msa_id] = advisory_record(raw)
        added += new_on_page
        log(f"page {page + 1}/{last + 1}: {len(raws)} advisories, {new_on_page} new")
        if not full and existing and new_on_page == 0:
            break
    write_db(path, records)
    return {"pages": pages, "added": added, "total": len(records)}
