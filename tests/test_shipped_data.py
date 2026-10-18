"""Checks on the committed data files (regression for the stale upstream data)."""

import json

from moodle_scanner.advisories import load_advisories
from moodle_scanner.fingerprints import FingerprintDB
from moodle_scanner.scan import DATA_DIR
from moodle_scanner.versions import MoodleVersion, tag_sort_key


def test_regression_fingerprints_cover_5x_releases():
    # Upstream moodle_hashes.txt stopped at v4.5.0 (2024-11).
    db = FingerprintDB.load(DATA_DIR / "fingerprints.json")
    assert MoodleVersion.parse(db.latest_tag) >= MoodleVersion.parse("v5.3.0")
    for tag in ("v3.11.8", "v4.1.2", "v4.5.1", "v5.0.2", "v5.1.0", "v5.3.0"):
        assert tag in db.tags
    assert db.tags == sorted(db.tags, key=tag_sort_key)
    assert len(db.files) >= 100


def test_regression_advisories_are_structured_and_current():
    advisories = {a.id: a for a in load_advisories(DATA_DIR / "advisories.json")}
    assert len(advisories) >= 700
    cve_2025_32044 = advisories["MSA-25-0011"]
    assert [str(r) for r in cve_2025_32044.ranges] == ["4.5.0 to 4.5.2"]
    assert max(a.published for a in advisories.values()) >= "2026-01-01"


def test_advisory_data_stores_facts_not_prose():
    data = json.loads((DATA_DIR / "advisories.json").read_text())
    allowed = {
        "id",
        "title",
        "published",
        "severity",
        "cves",
        "trackers",
        "url",
        "affected_text",
        "fixed_text",
        "affected",
        "earlier_unsupported",
        "fixed",
        "parse_status",
    }
    assert all(set(item) == allowed for item in data["advisories"])


def test_plugin_data_stores_slugs_and_versions_only():
    data = json.loads((DATA_DIR / "plugins.json").read_text())
    assert set(data) == {"schema_version", "source", "types", "plugins"}
    assert all(set(p) <= {"component", "last_released", "versions", "core_in"} for p in data["plugins"])
    assert all(set(v) == {"version", "release", "moodle"} for p in data["plugins"] for v in p["versions"])
    assert data["types"]["mod"] == "mod" and data["types"]["block"] == "blocks"
