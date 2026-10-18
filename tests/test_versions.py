import pytest

from moodle_scanner.versions import InvalidVersion, MoodleVersion, is_release_tag, tag_sort_key

V = MoodleVersion.parse


def test_regression_double_digit_minor_sorts_numerically():
    # Upstream compared tags as strings: "v5.10.0" < "v5.9.0".
    assert "v5.10.0" < "v5.9.0"
    assert V("v5.10.0") > V("v5.9.0")
    assert V("v3.10.0") > V("v3.9.25")
    assert sorted(["v5.10.0", "v5.9.0", "v5.1.0"], key=tag_sort_key) == ["v5.1.0", "v5.9.0", "v5.10.0"]


@pytest.mark.parametrize(
    "tag",
    ["v5.3.0-rc2", "v4.1.0-beta", "v5.1.0-rc1", "v2.0", "4.5.2+ (Build: 20250221)", "3.10.x"],
)
def test_regression_prerelease_and_odd_tags_parse(tag):
    # Upstream did int() on every dot-separated part and raised ValueError here.
    assert isinstance(V(tag), MoodleVersion)


def test_prerelease_ordering():
    ordered = ["4.5.0-beta", "4.5.0-rc1", "4.5.0-rc2", "4.5.0", "4.5.0+", "4.5.1"]
    assert sorted(V(v) for v in reversed(ordered)) == [V(v) for v in ordered]


def test_str_round_trip():
    for text in ["4.5.0", "5.3.0-rc2", "4.1.0-beta", "4.5.2+"]:
        assert str(V(text)) == text


def test_invalid_version_raises_specific_error():
    with pytest.raises(InvalidVersion):
        V("list")
    assert MoodleVersion.try_parse("main") is None


def test_release_tag_filter():
    assert is_release_tag("v4.5.0") and is_release_tag("v5.3.0-rc2")
    assert not is_release_tag("list") and not is_release_tag("MOODLE_405_STABLE")
