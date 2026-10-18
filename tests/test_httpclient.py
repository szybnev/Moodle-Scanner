import time

import pytest

from moodle_scanner.httpclient import HttpClient, normalize_base_url

from .support import Reply


def test_follows_same_origin_redirects_only(site):
    site.add("/a", Reply(302, "", {"Location": "/b"}))
    site.add("/b", Reply(200, "landed"))
    site.add("/away", Reply(302, "", {"Location": "https://example.invalid/x"}))
    client = HttpClient(site.url)
    resp = client.get("/a", follow_redirects=True)
    assert resp.status == 200 and resp.text == "landed" and resp.redirect_chain
    off = client.get("/away", follow_redirects=True)
    assert off.status == 302  # never leaves the target origin
    assert all(not p.startswith("https://example.invalid") for _, p, _ in site.requests)


def test_timeout_returns_error_instead_of_hanging(site):
    site.add("/slow", Reply(200, "late", delay=2))
    start = time.monotonic()
    resp = HttpClient(site.url, timeout=0.3).get("/slow")
    assert resp.status is None and "timed out" in resp.error.lower()
    assert time.monotonic() - start < 1.5


def test_rate_limit_spaces_requests(site):
    client = HttpClient(site.url, rate=10, concurrency=4)
    start = time.monotonic()
    client.get_many([f"/r{i}" for i in range(6)])
    assert time.monotonic() - start >= 0.45  # 6 requests at 10/s -> >= 0.5 s minus scheduling slack


def test_budget_exhausted_stops_sending(site):
    now = [0.0]
    client = HttpClient(site.url, max_time=5, clock=lambda: now[0])
    assert client.get("/one").status == 404
    now[0] = 6.0
    resp = client.get("/two")
    assert resp.status is None and resp.error == "time budget exhausted" and client.budget_exhausted
    assert [p for _, p, _ in site.requests] == ["/one"]


def test_body_cap_marks_truncation(site):
    site.add("/big", Reply(200, b"x" * 2048))
    client = HttpClient(site.url, max_body=1024)
    resp = client.get("/big")
    assert resp.truncated and len(resp.body) == 1024


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("moodle.example.org", "https://moodle.example.org/"),
        ("http://h/moodle", "http://h/moodle/"),
        ("http://h:8080/m/?x=1", "http://h:8080/m/"),
        ("https://h:8443/campus%20one/login/index.php/?loginredirect=1#form", "https://h:8443/campus%20one/"),
        ("https://h/catalog/index.php-files/", "https://h/catalog/index.php-files/"),
        ("https://h/moodle/login/", "https://h/moodle/login/"),
    ],
)
def test_normalize_base_url(raw, expected):
    assert normalize_base_url(raw) == expected


def test_subdirectory_install_paths_resolve(site):
    client = HttpClient(site.url + "moodle")
    client.get("/lib/x.js")
    assert site.requests[-1][1] == "/moodle/lib/x.js"
