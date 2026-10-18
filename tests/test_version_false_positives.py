"""Version evidence and advisory boundaries must not overstate target exposure."""

import pytest

from moodle_scanner.advisories import Advisory, assess, assess_candidates, parse_affected
from moodle_scanner.fingerprints import (
    Detector,
    FingerprintDB,
    VersionResult,
    apply_signals,
    branch_signals,
    git_blob_sha1,
)
from moodle_scanner.httpclient import HttpClient
from moodle_scanner.versions import MoodleVersion

from .support import Reply, advisory

V = MoodleVersion.parse


def make_advisory(affected, fixed=""):
    return Advisory.from_json(advisory("MSA-25-0001", affected, fixed))


@pytest.mark.parametrize("bound", ["before", "prior to", "<"])
def test_exclusive_upper_bound_does_not_include_fixed_release(bound):
    item = make_advisory(f"{bound} 4.5.3")
    assert assess(item, V("4.5.2")).status == "affected"
    assert assess(item, V("4.5.3")) is None
    assert assess(item, V("4.5.4")) is None


@pytest.mark.parametrize("bound", ["before 4.5", "prior to 4.5.0", "<4.5.x"])
def test_exclusive_branch_bound_keeps_only_possible_older_versions(bound):
    item = make_advisory(bound)
    assert assess(item, V("4.4.9")).status == "possibly_affected"
    assert assess(item, V("4.5.0")) is None
    assert assess(item, V("4.5.1")) is None


@pytest.mark.parametrize("bound", ["up to", "<=", "upto"])
def test_inclusive_upper_bound_remains_inclusive(bound):
    item = make_advisory(f"{bound} 4.5.3")
    assert assess(item, V("4.5.3")).status == "affected"
    assert assess(item, V("4.5.4")) is None


def test_bare_major_minor_means_initial_release_not_entire_branch():
    item = make_advisory("4.5")
    assert assess(item, V("4.5.0")).status == "affected"
    assert assess(item, V("4.5.1")) is None
    assert [str(r) for r in parse_affected("4.5.x").ranges] == ["4.5.0 to 4.5.x"]


@pytest.mark.parametrize("qualification", ["(except 4.5.2)", "(4.5.2 not affected)", "excluding 4.5.2"])
def test_explicit_exclusion_survives_data_builder_and_loading(qualification):
    item = make_advisory(f"4.5 to 4.5.4 {qualification}", "4.5.5")
    assert item.excluded
    assert assess(item, V("4.5.1")).status == "affected"
    assert assess(item, V("4.5.2")) is None
    assert assess(item, V("4.5.3")).status == "affected"
    assert assess(item, V("4.5.5")) is None


def test_parenthesized_earlier_unaffected_does_not_expand_versions():
    item = make_advisory("4.5 (earlier versions unaffected)")
    assert not item.earlier_unsupported
    assert item.parse_status == "ok"
    assert assess(item, V("4.4.0")) is None
    assert assess(item, V("4.5.1")) is None


def test_unparsed_qualification_does_not_become_definite_match():
    item = make_advisory("4.5 to 4.5.2 (only with optional integration enabled)")
    assert item.parse_status == "partial"
    assert assess(item, V("4.5.1")).status == "possibly_affected"


def test_unsupported_history_is_possible_and_does_not_fill_branch_gaps():
    item = make_advisory("4.5 to 4.5.2, 4.1 to 4.1.14 and earlier unsupported versions")
    assert assess(item, V("3.9.0")).status == "possibly_affected"
    assert assess(item, V("4.3.0")) is None
    assert assess(item, V("4.5.2")).status == "affected"
    assert assess(item, V("4.5.3")) is None
    assert assess(item, V("9.9.0")) is None


def test_fixed_release_and_newer_release_are_not_affected():
    item = make_advisory("4.5 to 4.5.2", "4.5.3")
    assert assess(item, V("4.5.2")).status == "affected"
    assert assess(item, V("4.5.2+")).status == "possibly_affected"
    assert assess(item, V("4.5.3")) is None
    assert assess(item, V("4.5.99")) is None
    assert assess(item, V("9.9.0")) is None


def test_prerelease_and_final_candidates_remain_possible():
    item = make_advisory("4.5", "4.5.1")
    assert assess_candidates(item, [V("4.5.0-rc1"), V("4.5.0")]).status == "possibly_affected"
    assert assess_candidates(item, [V("4.5.1")]) is None
    assert assess_candidates(item, []) is None


def detect(site, files, served, tags=("v4.5.1", "v4.5.2")):
    groups = {}
    for path, bodies in files.items():
        groups[path] = {}
        for index, body in enumerate(bodies):
            sha = git_blob_sha1(body)
            groups[path][sha] = groups[path].get(sha, frozenset()) | {index}
    for path, body in served.items():
        site.add(path, Reply(200, body))
    db = FingerprintDB(list(tags), groups, tags[-1])
    return Detector(HttpClient(site.url), db).run()


def test_independent_consistent_files_keep_exact_detection(site):
    files = {
        "/lib/javascript-static.js": (b"core-old", b"core-new"),
        "/theme/boost/style/moodle.css": (b"theme-old", b"theme-new"),
        "/lib/amd/build/editor.min.js": (b"editor-old", b"editor-new"),
    }
    result = detect(site, files, {path: bodies[1] for path, bodies in files.items()})
    assert result.status == "exact"
    assert result.confidence == "high"
    assert result.version == "4.5.2"


def test_conflicting_hashes_do_not_select_majority_release(site):
    files = {
        "/lib/javascript-static.js": (b"core-old", b"core-new"),
        "/theme/boost/style/moodle.css": (b"theme-old", b"theme-new"),
        "/lib/amd/build/editor.min.js": (b"editor-old", b"editor-new"),
    }
    served = {path: bodies[0] for path, bodies in files.items()}
    served["/lib/amd/build/editor.min.js"] = b"editor-new"
    result = detect(site, files, served)
    assert result.status == "ambiguous"
    assert result.confidence == "low"
    assert result.version is None
    assert result.candidates == ["4.5.1", "4.5.2"]
    assert any(e.outcome == "conflict" for e in result.evidence)


def test_rc_final_twin_does_not_assume_production_uses_final(site):
    files = {
        "/lib/javascript-static.js": (b"core-twin", b"core-twin"),
        "/theme/boost/style/moodle.css": (b"theme-twin", b"theme-twin"),
    }
    result = detect(site, files, {p: values[0] for p, values in files.items()}, ("v4.5.0-rc1", "v4.5.0"))
    assert result.status == "ambiguous"
    assert result.version is None
    assert result.candidates == ["4.5.0-rc1", "4.5.0"]


def test_one_specific_file_does_not_claim_exact_release(site):
    path = "/lib/javascript-static.js"
    result = detect(site, {path: (b"core-old", b"core-new")}, {path: b"core-new"})
    assert result.status == "ambiguous"
    assert result.confidence == "low"
    assert result.version is None


@pytest.mark.parametrize(
    "paths,body",
    [
        (("/lib/one.js", "/lib/two.js"), b""),
        (("/lib/one.js", "/lib/two.js"), b"  \n"),
        (("/lib/one.json", "/lib/two.json"), b"{}"),
        (("/lib/jquery/jquery.js", "/lib/requirejs/require.js"), b"third-party-library"),
        (("/pix/logo.svg", "/pix/icon.svg"), b"generic-image"),
        (("/lib/tests/fixtures/empty.txt", "/lib/tests/fixtures/test.txt"), b"generic-fixture"),
    ],
)
def test_generic_and_empty_files_do_not_identify_moodle_or_version(site, paths, body):
    result = detect(site, {p: (body, b"other") for p in paths}, dict.fromkeys(paths, body))
    assert result.status == "unknown"
    assert result.candidates == []
    assert all(e.outcome == "low_specificity" for e in result.evidence)


def test_copies_of_same_hash_do_not_supply_independent_confirmation(site):
    paths = ("/lib/one.js", "/lib/two.js")
    result = detect(site, {p: (b"same-old", b"same-new") for p in paths}, dict.fromkeys(paths, b"same-new"))
    assert result.status == "ambiguous"
    assert result.confidence == "low"


def test_source_and_minified_variant_do_not_supply_independent_confirmation(site):
    files = {
        "/lib/amd/src/editor.js": (b"old-source", b"new-source"),
        "/lib/amd/build/editor.min.js": (b"old-minified", b"new-minified"),
    }
    result = detect(site, files, {p: values[1] for p, values in files.items()})
    assert result.status == "ambiguous"
    assert result.version is None


def test_unindexed_new_build_is_not_forced_into_known_release(site):
    files = {
        "/lib/javascript-static.js": (b"core-old", b"core-new"),
        "/theme/boost/style/moodle.css": (b"theme-old", b"theme-new"),
        "/lib/amd/build/editor.min.js": (b"editor-old", b"editor-new"),
    }
    served = {path: bodies[1] for path, bodies in files.items()}
    served["/lib/amd/build/editor.min.js"] = b"unindexed-newer-editor"
    result = detect(site, files, served)
    assert result.status == "ambiguous"
    assert result.confidence == "low"
    assert result.version is None
    assert any(e.outcome == "unknown_hash" for e in result.evidence)


def test_all_unknown_hashes_leave_version_unknown(site):
    path = "/lib/javascript-static.js"
    result = detect(site, {path: (b"core-old", b"core-new")}, {path: b"not-in-the-database"})
    assert result.status == "unknown"
    assert result.candidates == []


def test_contradictory_public_signals_do_not_choose_newest_branch():
    result = VersionResult(status="unknown", confidence="none", method="none")
    signals = [
        {"source": "/", "kind": "docs-link", "branch": "4.5"},
        {"source": "/lib/upgrade.txt", "kind": "upgrade-notes", "branch": "5.0"},
    ]
    apply_signals(result, signals)
    assert result.status == "unknown"
    assert result.branch is None
    assert result.candidates == []
    assert result.signals == signals


def test_single_public_branch_does_not_enumerate_bundled_tags():
    result = VersionResult(status="unknown", confidence="none", method="none")
    apply_signals(result, [{"source": "/", "kind": "docs-link", "branch": "9.9"}])
    assert result.status == "branch"
    assert result.branch == "9.9"
    assert result.confidence == "low"
    assert result.candidates == []


def test_conflicting_docs_links_on_one_page_are_both_retained(site):
    site.add("/", Reply(200, "https://docs.moodle.org/405/ https://docs.moodle.org/500/"))
    client = HttpClient(site.url)
    signals = branch_signals(client, [client.get("/")])
    assert {signal["branch"] for signal in signals} == {"4.5", "5.0"}


def test_loading_old_record_reparses_stale_full_branch_range():
    record = advisory("MSA-25-0001", "4.5", "4.5.2")
    record["affected"] = [{"from": "4.5.0", "to": "4.5.x"}]
    record["earlier_unsupported"] = True
    record["fixed"] = []
    record["parse_status"] = "unparsed"
    item = Advisory.from_json(record)
    assert [str(r) for r in item.ranges] == ["4.5.0"]
    assert item.parse_status == "ok"
    assert not item.earlier_unsupported
    assert item.fixed == ("4.5.2",)
    assert assess(item, V("4.5.0")).status == "affected"
    assert assess(item, V("4.5.1")) is None
    assert assess(item, V("4.4.0")) is None


def test_loading_old_record_recovers_discarded_exclusion_and_exclusive_bound():
    record = advisory("MSA-25-0001", "before 4.5.3 (4.5.1 not affected)", "")
    record["affected"] = [{"from": "4.5.0", "to": "4.5.3"}]
    record.pop("excluded", None)
    record["parse_status"] = "ok"
    item = Advisory.from_json(record)
    assert [str(r) for r in item.excluded] == ["4.5.1"]
    assert assess(item, V("4.5.0")).status == "affected"
    assert assess(item, V("4.5.1")) is None
    assert assess(item, V("4.5.2")).status == "affected"
    assert assess(item, V("4.5.3")) is None
