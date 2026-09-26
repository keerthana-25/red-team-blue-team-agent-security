"""The single choke point for any network call this platform makes.

Safety boundary: real model adapters (local Ollama-style attacker/target, an HTTP
classifier) are opt-in and only ever reach hosts on an explicit allowlist. Nothing else
in this package imports ``urllib``, ``http.client``, or ``socket`` — a test enforces that.
"""
from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from urllib.parse import urlparse

DEFAULT_ALLOWLIST = ("127.0.0.1", "localhost", "::1")
MAX_RESPONSE_BYTES = 8 * 1024 * 1024
ENV_ALLOWLIST_VAR = "RTBT_NETWORK_ALLOWLIST"


class NetError(Exception):
    pass


class NetPolicyError(NetError):
    """The URL is outside the allowlist or uses a disallowed scheme."""


class NetTimeout(NetError):
    pass


class NetHTTPError(NetError):
    def __init__(self, status: int, body: str) -> None:
        super().__init__(f"HTTP {status}: {body[:200]}")
        self.status = status
        self.body = body


def allowlist_from_env() -> tuple[str, ...]:
    raw = os.environ.get(ENV_ALLOWLIST_VAR, "")
    hosts = tuple(h.strip() for h in raw.split(",") if h.strip())
    return hosts or DEFAULT_ALLOWLIST


def check_url(url: str, allowlist: tuple[str, ...]) -> None:
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise NetPolicyError(f"Scheme '{parsed.scheme}' is not permitted; use http or https.")
    host = parsed.hostname or ""
    if host not in allowlist:
        raise NetPolicyError(f"Host '{host}' is not on the network allowlist {allowlist}.")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):  # type: ignore[override]
        raise NetPolicyError("Redirects are not permitted.")


def post_json(url: str, payload: dict, *, timeout_s: float = 60.0,
              allowlist: tuple[str, ...] | None = None) -> tuple[dict, float]:
    """POST JSON, return (parsed_response, latency_ms). Raises a typed NetError subclass."""
    allowlist = allowlist or allowlist_from_env()
    check_url(url, allowlist)
    body = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"}, method="POST")
    opener = urllib.request.build_opener(_NoRedirect())
    start = time.perf_counter()
    try:
        with opener.open(request, timeout=timeout_s) as response:
            raw = response.read(MAX_RESPONSE_BYTES + 1)
    except urllib.error.HTTPError as exc:
        raise NetHTTPError(exc.code, exc.read().decode("utf-8", "replace")) from exc
    except TimeoutError as exc:
        raise NetTimeout(f"Timed out after {timeout_s}s calling {url}") from exc
    except urllib.error.URLError as exc:
        raise NetError(f"Could not reach {url}: {exc.reason}") from exc
    latency_ms = (time.perf_counter() - start) * 1000.0
    if len(raw) > MAX_RESPONSE_BYTES:
        raise NetError(f"Response from {url} exceeded {MAX_RESPONSE_BYTES} bytes.")
    try:
        return json.loads(raw.decode("utf-8")), latency_ms
    except json.JSONDecodeError as exc:
        raise NetError(f"Non-JSON response from {url}") from exc
