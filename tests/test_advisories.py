import pytest

from moodle_scanner.advisories import Advisory, assess, assess_candidates, parse_affected, severity_level
from moodle_scanner.versions import MoodleVersion

from .support import advisory

V = MoodleVersion.parse


def ranges(text):
    return [str(r) for r in parse_affected(text).ranges]


def test_parse_simple_range():
    assert ranges("4.5 to 4.5.2") == ["4.5.0 to 4.5.2"]


def test_parse_multi_branch_with_earlier_unsupported():
    parsed = parse_affected("4.4 to 4.4.3, 4.3 to 4.3.7, 4.2 to 4.2.10, 4.1 to 4.1.13 and earlier unsupported versions")
    assert [str(r) for r in parsed.ranges] == ["4.4.0 to 4.4.3", "4.3.0 to 4.3.7", "4.2.0 to 4.2.10", "4.1.0 to 4.1.13"]
    assert parsed.earlier_unsupported and not parsed.unparsed


def test_parse_5x_and_single_versions():
    assert ranges("5.0 to 5.0.1, 4.5 to 4.5.5") == ["5.0.0 to 5.0.1", "4.5.0 to 4.5.5"]
    assert ranges("5.0.1, 4.5.5, 4.4.9 and 4.1.19") == ["5.0.1", "4.5.5", "4.4.9", "4.1.19"]


def test_parse_parenthetical_notes_do_not_mark_earlier_versions():
    parsed = parse_affected("2.2, 2.1 to 2.1.3+ (earlier versions unaffected)")
    assert not parsed.earlier_unsupported
    assert [str(r) for r in parsed.ranges] == ["2.2.0 to 2.2.x", "2.1.0 to 2.1.3"]


def test_parse_missing_comma_and_other_unsupported():
    assert ranges("2.1 to 2.1.9+ 1.9 to 1.9.19") == ["2.1.0 to 2.1.9", "1.9.0 to 1.9.19"]
    assert parse_affected("3.2 to 3.2.2, 2.7 to 2.7.19 and other unsupported versions").earlier_unsupported


def test_parse_flags_free_text():
    assert parse_affected("all").unparsed == ["all"]


def adv(*args, **kw) -> Advisory:
    return Advisory.from_json(advisory(*args, **kw))


CVE_2025_32044 = adv("MSA-25-0011", "4.5 to 4.5.2", "4.5.3")
EARLIER = adv(
    "MSA-24-0040",
    "4.4 to 4.4.3, 4.3 to 4.3.7, 4.2 to 4.2.10, 4.1 to 4.1.13 and earlier unsupported versions",
    "4.4.4, 4.3.8, 4.2.11 and 4.1.14",
)


@pytest.mark.parametrize(
    "version,affected", [("4.5.0", True), ("4.5.2", True), ("4.5.3", False), ("4.4.3", False), ("5.0.0", False)]
)
def test_cve_2025_32044_range(version, affected):
    assert (assess(CVE_2025_32044, V(version)) is not None) == affected


def test_regression_earlier_unsupported_versions_are_affected():
    # Upstream dropped "earlier unsupported versions" and missed 3.x/4.0 sites.
    hit = assess(EARLIER, V("3.9.0"))
    assert hit is not None and hit.status == "affected" and "earlier unsupported" in hit.reason
    assert assess(EARLIER, V("4.0.10")) is not None
    assert assess(EARLIER, V("4.1.14")) is None  # fixed
    assert assess(EARLIER, V("4.5.0")) is None  # newer branch, not listed


def test_regression_prerelease_does_not_compare_equal_to_everything():
    # Upstream returned 0 ("equal") when int() failed on "rc2", matching arbitrary ranges.
    assert assess(CVE_2025_32044, V("5.3.0-rc2")) is None
    assert assess(CVE_2025_32044, V("4.5.0-rc1")) is not None


def test_regression_and_joined_fixed_list():
    # "4.2.11 and 4.1.14" was a single unparsable token upstream.
    assert assess(EARLIER, V("4.1.13")) is not None
    assert assess(EARLIER, V("4.1.14")) is None


def test_weekly_build_at_range_end_is_possible_only():
    hit = assess(CVE_2025_32044, V("4.5.2+"))
    assert hit is not None and hit.status == "possibly_affected"


def test_regression_only_listed_release_affected():
    regression = adv("MSA-25-0037", "5.0.1, 4.5.5, 4.4.9 and 4.1.19", "5.0.2, 4.5.6, 4.4.10 and 4.1.20")
    assert assess(regression, V("4.5.5")) is not None
    assert assess(regression, V("4.5.1")) is None


def test_candidates_combination():
    assert assess_candidates(CVE_2025_32044, [V("4.5.1"), V("4.5.2")]).status == "affected"
    assert assess_candidates(CVE_2025_32044, [V("4.5.2"), V("4.5.3")]).status == "possibly_affected"
    assert assess_candidates(CVE_2025_32044, [V("4.5.3")]) is None


@pytest.mark.parametrize(
    "text,level",
    [
        ("Serious", "high"),
        ("Minor", "medium"),
        ("Critical - exploit publicly available", "critical"),
        ("Non critical", "medium"),
        ("Very low", "low"),
        ("", "unknown"),
    ],
)
def test_severity_levels(text, level):
    assert severity_level(text) == level
