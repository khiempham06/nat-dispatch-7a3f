"""Shared, pure-stdlib helpers for exploit modules.

Every exploit module in this directory follows the same contract so the farm can
dispatch it without knowing anything about the service:

    NAME    = "vegas"          # service name, matches the audit file
    PORT    = 7770             # default port from service.yaml
    VECTORS = [v1, v2, ...]    # callables, cheapest and most reliable first

    def run(host, port=PORT, timeout=8.0) -> list[str]:
        '''Return every recovered secret string. MUST NOT raise.'''

Each vector is `f(host, port, timeout) -> list[str]` and returns the raw
*secrets* it recovered, not flags: the farm applies the flag regex itself. That
way a wrong regex costs us a log line instead of a whole service, and the farm's
--discover mode can show what a real flag actually looks like.

Run a module directly to test one target by hand:

    python3 exploits/vegas.py 10.100.1.1
"""

from __future__ import annotations

import json
import os
import random
import re
import socket
import string
import sys
import urllib.error
import urllib.parse
import urllib.request

DEFAULT_TIMEOUT = float(os.environ.get("FARM_TIMEOUT", "8"))

#: Set FARM_UA once the defend lane has counted the checker's user agents. An
#: empty value sends no User-Agent override.
USER_AGENT = os.environ.get("FARM_UA", "")


# --------------------------------------------------------------------- random


def rand_name(prefix: str = "u", length: int = 10) -> str:
    """A fresh identifier per run: never reuse credentials across sweeps."""
    body = "".join(random.choices(string.ascii_lowercase + string.digits, k=length))
    return f"{prefix}{body}"


def rand_pass(length: int = 16) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(random.choices(alphabet, k=length))


# ------------------------------------------------------------------------ tcp


class Conn:
    """A line/chunk oriented socket wrapper that never blocks past the deadline."""

    def __init__(self, host: str, port: int, timeout: float = DEFAULT_TIMEOUT) -> None:
        self.timeout = timeout
        self.buffer = b""
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.sock.settimeout(timeout)

    def __enter__(self) -> "Conn":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass

    def send(self, data: bytes | str) -> None:
        if isinstance(data, str):
            data = data.encode()
        self.sock.sendall(data)

    def sendline(self, data: bytes | str, newline: bytes = b"\n") -> None:
        if isinstance(data, str):
            data = data.encode()
        self.sock.sendall(data + newline)

    def recv_some(self) -> bytes:
        try:
            chunk = self.sock.recv(65536)
        except (socket.timeout, TimeoutError, OSError):
            return b""
        self.buffer += chunk
        return chunk

    def recv_until(self, needle: bytes, max_bytes: int = 1 << 20) -> bytes:
        """Read until `needle` appears; returns what was read (may lack needle)."""
        while needle not in self.buffer and len(self.buffer) < max_bytes:
            if not self.recv_some():
                break
        if needle in self.buffer:
            head, _, self.buffer = self.buffer.partition(needle)
            return head + needle
        head, self.buffer = self.buffer, b""
        return head

    def recv_line(self) -> bytes:
        return self.recv_until(b"\n")

    def drain(self, max_bytes: int = 1 << 20) -> bytes:
        """Read whatever arrives until the peer goes quiet or closes."""
        while len(self.buffer) < max_bytes:
            if not self.recv_some():
                break
        out, self.buffer = self.buffer, b""
        return out


def tcp_exchange(host: str, port: int, payload: bytes,
                 timeout: float = DEFAULT_TIMEOUT, read_bytes: int = 1 << 20) -> bytes:
    """One-shot: connect, send, read until quiet. Returns b"" on any failure."""
    try:
        with Conn(host, port, timeout) as conn:
            if payload:
                conn.send(payload)
            return conn.drain(read_bytes)
    except OSError:
        return b""


# ----------------------------------------------------------------------- http


def http(host: str, port: int, path: str, method: str = "GET",
         body: bytes | str | None = None, headers: dict[str, str] | None = None,
         timeout: float = DEFAULT_TIMEOUT, scheme: str = "http") -> tuple[int, dict[str, str], bytes]:
    """Return (status, headers, body). Never raises; status 0 means transport error."""
    url = f"{scheme}://{host}:{port}{path}"
    data = body.encode() if isinstance(body, str) else body
    request_headers = dict(headers or {})
    if USER_AGENT and "User-Agent" not in request_headers:
        request_headers["User-Agent"] = USER_AGENT
    request = urllib.request.Request(url, data=data, method=method, headers=request_headers)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, dict(response.headers), response.read()
    except urllib.error.HTTPError as error:
        return error.code, dict(error.headers or {}), error.read()
    except (urllib.error.URLError, OSError, ValueError):
        return 0, {}, b""


def http_json(host: str, port: int, path: str, method: str = "GET",
              payload=None, headers: dict[str, str] | None = None,
              timeout: float = DEFAULT_TIMEOUT):
    """GET/POST JSON. Returns (status, parsed_or_None)."""
    request_headers = {"Accept": "application/json", **(headers or {})}
    body = None
    if payload is not None:
        body = json.dumps(payload).encode()
        request_headers.setdefault("Content-Type", "application/json")
    status, _, raw = http(host, port, path, method, body, request_headers, timeout)
    try:
        return status, json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return status, None


def urlencode(**params) -> str:
    return urllib.parse.urlencode(params)


# ------------------------------------------------------------------ harvesting

#: Deliberately wide: the farm, not the exploit, decides what a flag is. Used
#: only by the module self-test output and by --discover.
CANDIDATE_RE = re.compile(
    rb"(?:[A-Z][A-Z0-9_]{2,15}\{[^}\r\n]{6,80}\})"      # NAME{...} families
    rb"|(?<![A-Za-z0-9])[A-Z0-9]{31}=(?![A-Za-z0-9=])"  # flower/tulip style
    rb"|(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{32}={0,2}(?![A-Za-z0-9+/=])"
)


def candidates(blob: bytes | str) -> list[str]:
    """Flag-shaped substrings, for self-tests and regex discovery."""
    if isinstance(blob, str):
        blob = blob.encode("utf-8", "replace")
    out: list[str] = []
    for match in CANDIDATE_RE.findall(blob):
        text = match.decode("utf-8", "replace")
        if text not in out:
            out.append(text)
    return out


def dedup(values) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        if value and value not in seen:
            seen.add(value)
            out.append(value)
    return out


def safe(vector):
    """Decorator: a vector must never raise and never stall the sweep."""

    def wrapper(host: str, port: int, timeout: float = DEFAULT_TIMEOUT) -> list[str]:
        try:
            result = vector(host, port, timeout)
        except Exception as error:  # noqa: BLE001 - a vector must not kill the sweep
            if os.environ.get("FARM_DEBUG"):
                print(f"[{vector.__name__}] {type(error).__name__}: {error}", file=sys.stderr)
            return []
        if result is None:
            return []
        if isinstance(result, (str, bytes)):
            result = [result]
        return [r.decode("utf-8", "replace") if isinstance(r, bytes) else str(r) for r in result]

    wrapper.__name__ = vector.__name__
    wrapper.__doc__ = vector.__doc__
    return wrapper


def run_vectors(vectors, host: str, port: int, timeout: float = DEFAULT_TIMEOUT,
                stop_on_first: bool = False) -> list[str]:
    """Run vectors in order, collecting secrets. Used by each module's run()."""
    found: list[str] = []
    for vector in vectors:
        found.extend(vector(host, port, timeout))
        if found and stop_on_first:
            break
    return dedup(found)


def main(module_run, default_port: int) -> int:
    """Standard CLI for a module: `module.py <host> [flagid]`, prints one per line.

    The gameserver invokes exploits as `python3 <module>.py <host> <flagid>`, so
    argv[2] is a FLAG ID and never a port. Parsing it as one is actively unsafe:
    noise's flagids are small integers, so `int(argv[2])` succeeds and quietly
    dials port 23 instead of 6426. Every vector here bulk-dumps rather than
    renting one flag id, so the id is simply unused; override the port with
    FARM_PORT when testing by hand.
    """
    if len(sys.argv) < 2:
        print(f"usage: {sys.argv[0]} <host> [flagid]", file=sys.stderr)
        return 2
    host = sys.argv[1]
    port = int(os.environ.get("FARM_PORT", default_port))
    secrets = module_run(host, port)
    for secret in secrets:
        print(secret)
    if not secrets:
        print("NO SECRETS RECOVERED (target patched, down, or vector broken)",
              file=sys.stderr)
        return 1
    return 0
