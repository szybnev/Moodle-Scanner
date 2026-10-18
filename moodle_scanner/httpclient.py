"""Bounded, read-only HTTP client used for scanning.

Only GET and HEAD are ever issued against the target. Every request has a
timeout; a global rate limit, a concurrency cap and an overall time budget are
enforced here so scan modules never need to think about them. Redirects are
followed only within the target origin, so the scanner never touches a host it
was not pointed at.
"""

from __future__ import annotations

import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import zlib
from collections.abc import Callable, Iterable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

from . import __version__

DEFAULT_USER_AGENT = f"moodle-scanner/{__version__} (+https://github.com/szybnev/Moodle-Scanner)"
DEFAULT_TIMEOUT = 10.0
DEFAULT_MAX_BODY = 4 * 1024 * 1024
MAX_REDIRECTS = 5


@dataclass(frozen=True)
class Request:
    method: str
    url: str
    headers: dict[str, str]
    timeout: float


@dataclass
class Response:
    url: str
    status: int | None
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    error: str | None = None
    truncated: bool = False
    redirect_chain: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.status is not None and 200 <= self.status < 300

    @property
    def location(self) -> str | None:
        return self.headers.get("location")

    @property
    def text(self) -> str:
        charset = "utf-8"
        ctype = self.headers.get("content-type", "")
        if "charset=" in ctype:
            charset = ctype.split("charset=", 1)[1].split(";", 1)[0].strip() or "utf-8"
        try:
            return self.body.decode(charset, errors="replace")
        except LookupError:
            return self.body.decode("utf-8", errors="replace")


Transport = Callable[[Request], Response]


class BudgetExhausted(Exception):
    """The overall scan time budget ran out."""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001 - stdlib signature
        return None


def build_ssl_context(insecure: bool) -> ssl.SSLContext:
    if insecure:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx
    try:
        import truststore  # noqa: PLC0415 - optional at import time, pinned in pyproject

        return truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    except ImportError:
        return ssl.create_default_context()


def urllib_transport(insecure: bool = False, proxy: str | None = None, max_body: int = DEFAULT_MAX_BODY) -> Transport:
    """Transport backed by the standard library (no third-party HTTP stack)."""
    handlers: list[urllib.request.BaseHandler] = [
        urllib.request.HTTPSHandler(context=build_ssl_context(insecure)),
        _NoRedirect(),
    ]
    if proxy:
        handlers.append(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
    else:
        handlers.append(urllib.request.ProxyHandler({}))
    opener = urllib.request.build_opener(*handlers)

    def send(request: Request) -> Response:
        req = urllib.request.Request(request.url, method=request.method, headers=request.headers)
        try:
            resp = opener.open(req, timeout=request.timeout)
        except urllib.error.HTTPError as exc:
            resp = exc
        except (urllib.error.URLError, OSError, ValueError) as exc:
            reason = getattr(exc, "reason", exc)
            return Response(url=request.url, status=None, error=f"{type(exc).__name__}: {reason}")
        try:
            with resp:
                body = b"" if request.method == "HEAD" else resp.read(max_body + 1)
                status = resp.status if hasattr(resp, "status") else resp.code
                headers = {k.lower(): v for k, v in resp.headers.items()}
        except (OSError, ValueError) as exc:
            return Response(url=request.url, status=None, error=f"{type(exc).__name__}: {exc}")
        truncated = len(body) > max_body
        body = body[:max_body]
        encoding = headers.get("content-encoding", "").lower()
        if encoding in ("gzip", "x-gzip", "deflate") and body and not truncated:
            # We never send Accept-Encoding, but some CDNs compress anyway; hashes need raw bytes.
            try:
                body = zlib.decompress(body, 16 + zlib.MAX_WBITS if "gzip" in encoding else zlib.MAX_WBITS)
            except zlib.error:
                pass
        return Response(url=request.url, status=status, headers=headers, body=body, truncated=truncated)

    return send


class HttpClient:
    """Rate-limited, time-budgeted GET/HEAD client bound to one target origin."""

    def __init__(
        self,
        base_url: str,
        *,
        timeout: float = DEFAULT_TIMEOUT,
        user_agent: str = DEFAULT_USER_AGENT,
        headers: dict[str, str] | None = None,
        rate: float | None = None,
        concurrency: int = 4,
        max_time: float | None = None,
        transport: Transport | None = None,
        insecure: bool = False,
        proxy: str | None = None,
        max_body: int = DEFAULT_MAX_BODY,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.base_url = normalize_base_url(base_url)
        parts = urllib.parse.urlsplit(self.base_url)
        self._origin = (parts.scheme, parts.netloc.lower())
        self.timeout = timeout
        self.concurrency = max(1, concurrency)
        self._headers = {"User-Agent": user_agent, "Accept": "*/*"}
        self._headers.update(headers or {})
        self._transport = transport or urllib_transport(insecure=insecure, proxy=proxy, max_body=max_body)
        self._interval = (1.0 / rate) if rate else 0.0
        self._clock = clock
        self._deadline = (clock() + max_time) if max_time else None
        self._lock = threading.Lock()
        self._next_slot = 0.0
        self._cache: dict[tuple[str, str, bool], Response] = {}
        self.request_count = 0
        self.budget_exhausted = False

    def url_for(self, path: str) -> str:
        return urllib.parse.urljoin(self.base_url, path.lstrip("/"))

    def same_origin(self, url: str) -> bool:
        parts = urllib.parse.urlsplit(url)
        return (parts.scheme, parts.netloc.lower()) == self._origin

    def _remaining(self) -> float | None:
        if self._deadline is None:
            return None
        return self._deadline - self._clock()

    def _acquire_slot(self) -> None:
        remaining = self._remaining()
        if remaining is not None and remaining <= 0:
            self.budget_exhausted = True
            raise BudgetExhausted
        if not self._interval:
            return
        with self._lock:
            now = self._clock()
            slot = max(now, self._next_slot)
            self._next_slot = slot + self._interval
        delay = slot - now
        if delay > 0:
            time.sleep(delay)

    def _send(self, method: str, url: str) -> Response:
        try:
            self._acquire_slot()
        except BudgetExhausted:
            return Response(url=url, status=None, error="time budget exhausted")
        timeout = self.timeout
        remaining = self._remaining()
        if remaining is not None:
            timeout = max(0.1, min(timeout, remaining))
        with self._lock:
            self.request_count += 1
        return self._transport(Request(method=method, url=url, headers=dict(self._headers), timeout=timeout))

    def get(self, path: str, *, follow_redirects: bool = False, method: str = "GET") -> Response:
        """Fetch ``path`` (relative to the base URL). Results are cached per scan."""
        key = (method, path, follow_redirects)
        with self._lock:
            cached = self._cache.get(key)
        if cached is not None:
            return cached
        url = self.url_for(path)
        chain: list[str] = []
        response = self._send(method, url)
        while follow_redirects and response.status in (301, 302, 303, 307, 308) and response.location:
            target = urllib.parse.urljoin(response.url, response.location)
            if not self.same_origin(target) or len(chain) >= MAX_REDIRECTS:
                break
            chain.append(response.url)
            response = self._send(method, target)
        response.redirect_chain = chain
        with self._lock:
            self._cache[key] = response
        return response

    def head(self, path: str) -> Response:
        return self.get(path, method="HEAD")

    def get_many(self, paths: Iterable[str], *, follow_redirects: bool = False) -> dict[str, Response]:
        paths = list(dict.fromkeys(paths))
        with ThreadPoolExecutor(max_workers=self.concurrency) as pool:
            results = pool.map(lambda p: self.get(p, follow_redirects=follow_redirects), paths)
            return dict(zip(paths, results, strict=False))


def normalize_base_url(url: str) -> str:
    url = url.strip()
    if "://" not in url:
        url = "https://" + url
    parts = urllib.parse.urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.netloc:
        raise ValueError(f"unsupported target URL: {url!r}")
    path = parts.path
    if not path.endswith("/"):
        path += "/"
    return urllib.parse.urlunsplit((parts.scheme, parts.netloc, path, "", ""))
