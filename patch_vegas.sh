#!/bin/sh
# patch_vegas.sh - close BOTH anonymous flag leaks in the vegas proof panels.
#
#   usage: sh patch_vegas.sh [service_root]      (default: /services/vegas)
#
# The flag is stored three times per slip.  vault_data_b64 is already gated on
# ownership; signature_event.code_hex and rsa_event.code_hex were both emitted to
# anonymous callers and are independent, so both have to be closed:
#
#   1. database.py - at slip BUILD time, also compute a shape-identical decoy
#                    code_hex for the signature event (xor of same-length random
#                    ASCII under the same mask -> same hex length) and for the rsa
#                    event (encrypt_rsa_secret of same-length random ASCII under
#                    the same modulus -> same colon count).  Built once and stored,
#                    so repeated reads of a slip are stable.  Also stops reusing
#                    the fixed 6-element nonce ring, which leaked the house signing
#                    key by one subtraction.
#   2. views.py    - signature_view/rsa_view take `own`; the real code_hex goes to
#                    the owner only, everyone else gets the stored decoy.  `own`
#                    defaults to False so a caller that forgets fails CLOSED.
#   3. commands.py - cmd_show passes `own` through to both proof views.
#                    cmd_sigs/cmd_rsa scope every row to the caller, and treat a
#                    blank slip_id as "no filter", so `sigs ""` can no longer skip
#                    the 30-row cap.
#
# Deliberately NOT touched: put/get round trip, verify-sig, verify-rsa, field
# names, field order, hex length, colon count, the `count=` header.  No literal
# "hidden" is ever served for code_hex.
#
# Idempotent: every edit is guarded, a second run is a no-op.  Does NOT restart
# the service - do that separately.

# Note: errexit is deliberately NOT set.  If one file's edits cannot be applied we
# still want the remaining files attempted and, above all, the verification block
# at the bottom to run, so a partial apply is reported instead of dying silently.
set -u

ROOT="${1:-/services/vegas}"
rc=0

say() { echo "[vegas-patch] $1"; }

if ! command -v python3 >/dev/null 2>&1; then
    say "FATAL: python3 not found on PATH"
    exit 1
fi

if [ -f "$ROOT/vegas/commands.py" ]; then
    PKG="$ROOT/vegas"
elif [ -f "$ROOT/commands.py" ]; then
    PKG="$ROOT"
else
    say "FATAL: no vegas package under '$ROOT' (looked for \$ROOT/vegas/commands.py and \$ROOT/commands.py)"
    exit 1
fi

for f in database.py views.py commands.py; do
    if [ ! -f "$PKG/$f" ]; then
        say "FATAL: missing $PKG/$f"
        exit 1
    fi
done

say "root=$ROOT pkg=$PKG"

# ---------------------------------------------------------------- database.py
# guard: the patcher appends the DONE marker only once every edit is in place,
# so a partial apply has no marker and is retried on the next run.
if grep -q "VEGAS_PATCH_DB_DONE" "$PKG/database.py"; then
    say "database.py: already patched, no-op"
else
    python3 - "$PKG/database.py" <<'PY_DB' || { say "database.py: patcher reported a problem (see MISSING lines above)"; rc=1; }
import sys

MARKER = "VEGAS_PATCH_DB_DONE"

EDITS = [
    (
        "db:import-string",
        r'''import threading
import uuid
''',
        r'''import string
import threading
import uuid
''',
    ),
    (
        "db:decoy-helper",
        r'''from .util import now, short_id


class Database:
''',
        r'''from .util import RNG, now, short_id

# VEGAS_PATCH_DB: build-time decoy plaintext with the same byte length as the real
# secret.  The public proof panels serve a code_hex derived from this instead of
# from the secret, which keeps their exact shape while carrying nothing useful.
_DECOY_ALPHABET = string.ascii_letters + string.digits


def decoy_plaintext(length):
    return "".join(RNG.choice(_DECOY_ALPHABET) for _ in range(length))


class Database:
''',
    ),
    (
        "db:drop-fixed-nonce-ring",
        r'''        nonce = self.nonces.pop(0) % GROUP_Q
        self.nonces.append(nonce)
''',
        r'''        # VEGAS_PATCH_DB: a fresh nonce per event.  The old 6-element ring repeated,
        # and two events sharing a commitment leak the signing key by subtraction.
        nonce = RNG.randrange(1, GROUP_Q)
''',
    ),
    (
        "db:signature-decoy",
        r'''        code_hex = crypto.xor_bytes(secret.encode(), mask).hex()
        return {
''',
        r'''        code_hex = crypto.xor_bytes(secret.encode(), mask).hex()
        decoy_hex = crypto.xor_bytes(
            decoy_plaintext(len(secret.encode())).encode(), mask
        ).hex()
        return {
''',
    ),
    (
        "db:signature-decoy-field",
        r'''            "code_hex": code_hex,
            "note": "Weekly provably fair proof",
''',
        r'''            "code_hex": code_hex,
            "code_hex_public": decoy_hex,
            "note": "Weekly provably fair proof",
''',
    ),
    (
        "db:rsa-decoy-field",
        r'''            "code_hex": crypto.encrypt_rsa_secret(secret, modulus),
            "jackpot_name": f"{slip_id[:8]} Grand Jackpot",
''',
        r'''            "code_hex": crypto.encrypt_rsa_secret(secret, modulus),
            "code_hex_public": crypto.encrypt_rsa_secret(
                decoy_plaintext(len(secret.encode())), modulus
            ),
            "jackpot_name": f"{slip_id[:8]} Grand Jackpot",
''',
    ),
]


def main():
    path = sys.argv[1]
    with open(path, "rb") as fh:
        raw = fh.read()
    newline = "\r\n" if b"\r\n" in raw else "\n"
    src = raw.decode("utf-8").replace("\r\n", "\n")
    failed = 0
    for name, old, new in EDITS:
        if new in src:
            print("[vegas-patch] present: " + name)
            continue
        count = src.count(old)
        if count != 1:
            print("[vegas-patch] MISSING: %s (anchor found %d times)" % (name, count))
            failed += 1
            continue
        src = src.replace(old, new, 1)
        print("[vegas-patch] applied: " + name)
    if not failed and MARKER not in src:
        src = src.rstrip("\n") + "\n\n# " + MARKER + "\n"
        print("[vegas-patch] applied: db:done-marker")
    out = src.replace("\n", newline).encode("utf-8")
    if out != raw:
        with open(path, "wb") as fh:
            fh.write(out)
        print("[vegas-patch] wrote: " + path)
    else:
        print("[vegas-patch] unchanged: " + path)
    sys.exit(1 if failed else 0)


main()
PY_DB
fi

# ------------------------------------------------------------------- views.py
if grep -q "VEGAS_PATCH_VIEWS_DONE" "$PKG/views.py"; then
    say "views.py: already patched, no-op"
else
    python3 - "$PKG/views.py" <<'PY_VIEWS' || { say "views.py: patcher reported a problem (see MISSING lines above)"; rc=1; }
import sys

MARKER = "VEGAS_PATCH_VIEWS_DONE"

EDITS = [
    (
        "views:public-code-hex-helper",
        r'''from .util import fields, stamp


def slip_view(slip, own):
''',
        r'''from .util import fields, stamp


# VEGAS_PATCH_VIEWS: the real code_hex goes to the owner only.  Everyone else gets
# the decoy that was built with the slip - same hex length, same colon count, same
# character class - so a shape-checking client still parses the panel.  `own`
# defaults to False at every call site below: a caller that forgets fails closed.
def public_code_hex(event, own):
    if own:
        return event["code_hex"]
    decoy = event.get("code_hex_public")
    if decoy:
        return decoy
    # slip built before this patch: keep the shape, drop the content.
    return "".join(":" if char == ":" else "0" for char in event.get("code_hex", ""))


def slip_view(slip, own):
''',
    ),
    (
        "views:signature-signature",
        r'''def signature_view(slip_id, event):
''',
        r'''def signature_view(slip_id, event, own=False):
''',
    ),
    (
        "views:signature-code-hex",
        r'''        ("public_key", event["public_key"]),
        ("code_hex", event["code_hex"]),
''',
        r'''        ("public_key", event["public_key"]),
        ("code_hex", public_code_hex(event, own)),
''',
    ),
    (
        "views:rsa-signature",
        r'''def rsa_view(slip_id, event):
''',
        r'''def rsa_view(slip_id, event, own=False):
''',
    ),
    (
        "views:rsa-code-hex",
        r'''        ("exponent", event["exponent"]),
        ("code_hex", event["code_hex"]),
''',
        r'''        ("exponent", event["exponent"]),
        ("code_hex", public_code_hex(event, own)),
''',
    ),
]


def main():
    path = sys.argv[1]
    with open(path, "rb") as fh:
        raw = fh.read()
    newline = "\r\n" if b"\r\n" in raw else "\n"
    src = raw.decode("utf-8").replace("\r\n", "\n")
    failed = 0
    for name, old, new in EDITS:
        if new in src:
            print("[vegas-patch] present: " + name)
            continue
        count = src.count(old)
        if count != 1:
            print("[vegas-patch] MISSING: %s (anchor found %d times)" % (name, count))
            failed += 1
            continue
        src = src.replace(old, new, 1)
        print("[vegas-patch] applied: " + name)
    if not failed and MARKER not in src:
        src = src.rstrip("\n") + "\n\n# " + MARKER + "\n"
        print("[vegas-patch] applied: views:done-marker")
    out = src.replace("\n", newline).encode("utf-8")
    if out != raw:
        with open(path, "wb") as fh:
            fh.write(out)
        print("[vegas-patch] wrote: " + path)
    else:
        print("[vegas-patch] unchanged: " + path)
    sys.exit(1 if failed else 0)


main()
PY_VIEWS
fi

# ---------------------------------------------------------------- commands.py
if grep -q "VEGAS_PATCH_CMDS_DONE" "$PKG/commands.py"; then
    say "commands.py: already patched, no-op"
else
    python3 - "$PKG/commands.py" <<'PY_CMDS' || { say "commands.py: patcher reported a problem (see MISSING lines above)"; rc=1; }
import sys

MARKER = "VEGAS_PATCH_CMDS_DONE"

EDITS = [
    (
        "cmds:show-passes-own",
        r'''            views.signature_view(slip["slip_id"], slip["signature_event"]),
            views.rsa_view(slip["slip_id"], slip["rsa_event"]),
''',
        r'''            views.signature_view(slip["slip_id"], slip["signature_event"], own),
            views.rsa_view(slip["slip_id"], slip["rsa_event"], own),
''',
    ),
    (
        "cmds:sigs-scope-and-cap",
        r'''def cmd_sigs(session, database, args):
    with database.lock:
        slips = database.select_slips(args[0] if args else None)
    if not args:
        slips = sorted(slips, key=lambda s: s["created_at"], reverse=True)[:30]
    rows = [views.signature_view(slip["slip_id"], slip["signature_event"]) for slip in slips]
    return "\n".join([f"count={len(rows)}"] + rows)
''',
        r'''def cmd_sigs(session, database, args):
    # VEGAS_PATCH_CMDS: a blank slip_id is no filter at all (select_slips treats it
    # as "everything"), so it must not skip the row cap either.  Every row is
    # scoped to the caller: non-owners get the decoy code_hex.
    target = args[0] if args and args[0].strip() else None
    username = username_of(session, database)
    with database.lock:
        slips = database.select_slips(target)
    if not target:
        slips = sorted(slips, key=lambda s: s["created_at"], reverse=True)[:30]
    rows = [
        views.signature_view(
            slip["slip_id"], slip["signature_event"], username == slip["owner"]
        )
        for slip in slips
    ]
    return "\n".join([f"count={len(rows)}"] + rows)
''',
    ),
    (
        "cmds:rsa-scope-and-cap",
        r'''def cmd_rsa(session, database, args):
    with database.lock:
        slips = database.select_slips(args[0] if args else None)
    if not args:
        slips = sorted(slips, key=lambda s: s["created_at"], reverse=True)[:30]
    rows = [views.rsa_view(slip["slip_id"], slip["rsa_event"]) for slip in slips]
    return "\n".join([f"count={len(rows)}"] + rows)
''',
        r'''def cmd_rsa(session, database, args):
    # VEGAS_PATCH_CMDS: same two fixes as cmd_sigs - blank slip_id keeps the row
    # cap, and the real code_hex is owner-only.
    target = args[0] if args and args[0].strip() else None
    username = username_of(session, database)
    with database.lock:
        slips = database.select_slips(target)
    if not target:
        slips = sorted(slips, key=lambda s: s["created_at"], reverse=True)[:30]
    rows = [
        views.rsa_view(slip["slip_id"], slip["rsa_event"], username == slip["owner"])
        for slip in slips
    ]
    return "\n".join([f"count={len(rows)}"] + rows)
''',
    ),
]


def main():
    path = sys.argv[1]
    with open(path, "rb") as fh:
        raw = fh.read()
    newline = "\r\n" if b"\r\n" in raw else "\n"
    src = raw.decode("utf-8").replace("\r\n", "\n")
    failed = 0
    for name, old, new in EDITS:
        if new in src:
            print("[vegas-patch] present: " + name)
            continue
        count = src.count(old)
        if count != 1:
            print("[vegas-patch] MISSING: %s (anchor found %d times)" % (name, count))
            failed += 1
            continue
        src = src.replace(old, new, 1)
        print("[vegas-patch] applied: " + name)
    if not failed and MARKER not in src:
        src = src.rstrip("\n") + "\n\n# " + MARKER + "\n"
        print("[vegas-patch] applied: cmds:done-marker")
    out = src.replace("\n", newline).encode("utf-8")
    if out != raw:
        with open(path, "wb") as fh:
            fh.write(out)
        print("[vegas-patch] wrote: " + path)
    else:
        print("[vegas-patch] unchanged: " + path)
    sys.exit(1 if failed else 0)


main()
PY_CMDS
fi

# ----------------------------------------------------------------- verify
for f in database.py views.py commands.py; do
    if python3 -c "import ast, sys; ast.parse(open(sys.argv[1], encoding='utf-8').read(), sys.argv[1])" "$PKG/$f"; then
        say "syntax ok: $PKG/$f"
    else
        say "SYNTAX FAIL: $PKG/$f"
        rc=1
    fi
done

for pair in "database.py:VEGAS_PATCH_DB_DONE" "views.py:VEGAS_PATCH_VIEWS_DONE" "commands.py:VEGAS_PATCH_CMDS_DONE"; do
    f=$(echo "$pair" | cut -d: -f1)
    m=$(echo "$pair" | cut -d: -f2)
    if grep -q "$m" "$PKG/$f"; then
        say "marker ok: $f ($m)"
    else
        say "MARKER MISSING: $f ($m) - partial apply, re-run this script"
        rc=1
    fi
done

# both proof views must route code_hex through the ownership gate
gated=$(grep -c 'code_hex", public_code_hex(event, own)' "$PKG/views.py" || true)
if [ "$gated" -eq 2 ]; then
    say "leak check ok: $gated/2 proof views serve code_hex through public_code_hex()"
else
    say "LEAK CHECK FAILED: only $gated/2 proof views gated (expected 2)"
    rc=1
fi

# both decoys must be built and stored with the slip
built=$(grep -c '"code_hex_public"' "$PKG/database.py" || true)
if [ "$built" -eq 2 ]; then
    say "leak check ok: $built/2 build-time decoys stored (signature + rsa)"
else
    say "LEAK CHECK FAILED: only $built/2 build-time decoys stored (expected 2)"
    rc=1
fi

# cmd_show must forward ownership to both panels, and the blank-slip_id lever closed
fwd=$(grep -c 'slip\["signature_event"\], own)\|slip\["rsa_event"\], own)' "$PKG/commands.py" || true)
lever=$(grep -c 'target = args\[0\] if args and args\[0\].strip() else None' "$PKG/commands.py" || true)
if [ "$fwd" -eq 2 ] && [ "$lever" -eq 2 ]; then
    say "leak check ok: cmd_show forwards own ($fwd/2), blank slip_id gated in sigs+rsa ($lever/2)"
else
    say "LEAK CHECK FAILED: cmd_show own forwarding $fwd/2, blank slip_id gate $lever/2"
    rc=1
fi

if [ "$rc" -eq 0 ]; then
    say "DONE - all changes present, service NOT restarted (restart separately)"
else
    say "FAILED - see markers above; nothing was restarted"
fi

exit "$rc"
