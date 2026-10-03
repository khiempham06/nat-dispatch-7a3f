#!/usr/bin/env python3
"""Watchdog for the throwers.

Why this exists: /usr/local/bin/thrower's get_flagids() swallows any failure and
returns {}, and the caller then does flag_ids["services"], so one transient
/api/flagids hiccup raises KeyError and kills the THROW thread. submit_loop and
stats_loop keep running, so the process stays in pgrep and everything looks
healthy while nothing is thrown or found again. That is exactly what happened:
one KeyError per log, then ~71 minutes of silence.

So liveness is judged by LOG GROWTH, not by the process existing.

Safety: if every thrower looks stale at once the gameserver is probably down, so
back off instead of restarting everything in a loop.

usage: nohup python3 supervise.py > /root/supervise.log 2>&1 &
"""
import os, re, subprocess, sys, time

#: (exploit path, glitch service name). Keep in sync with what we want running.
THROWERS = [
    ("/root/fp.py", "flightplan"),
    ("/root/vg.py", "vegas"),
    ("/root/donor.py", "donor"),
    ("/root/noise-new.py", "noise"),
    ("/root/sploits/shaas/shaas.py", "shaas"),
    ("/services/telescope/solve.py", "telescope"),
]

POLL = 60               # seconds between checks
STALE = 8 * 60          # a log quiet this long means the throw thread is dead
GRACE = 3 * 60          # after a restart, give it this long before judging again
MOST_STALE_OK = 0.75    # if more than this fraction look dead, suspect the gameserver


def log(msg):
    print("[%s] %s" % (time.strftime("%H:%M:%S"), msg), flush=True)


def logpath(exploit):
    return os.path.splitext(exploit)[0] + ".log"


def running(exploit):
    out = subprocess.run(["pgrep", "-af", "bin/thrower"], capture_output=True,
                         text=True).stdout
    return any(exploit in line for line in out.splitlines())


def age(exploit):
    p = logpath(exploit)
    try:
        return time.time() - os.path.getmtime(p)
    except OSError:
        return None          # no log yet


def restart(exploit, service):
    name = os.path.basename(exploit)
    subprocess.run(["glitch", "exploit", "kill", name], capture_output=True, text=True)
    time.sleep(2)
    r = subprocess.run(["glitch", "exploit", "throw", exploit, service],
                       capture_output=True, text=True)
    ok = "started" in (r.stdout or "")
    log("restart %-28s service=%-10s %s" % (name, service, "OK" if ok else
        "FAILED: " + (r.stdout or r.stderr or "no output").strip()[:120]))
    return ok


def main():
    last_restart = {}
    log("watchdog up: %d throwers, poll=%ds stale=%ds" % (len(THROWERS), POLL, STALE))
    while True:
        verdicts = []
        for exploit, service in THROWERS:
            a = age(exploit)
            alive = running(exploit)
            recent = time.time() - last_restart.get(exploit, 0) < GRACE
            dead = (not alive) or (a is None) or (a > STALE)
            verdicts.append((exploit, service, dead, recent, a, alive))

        dead_n = sum(1 for v in verdicts if v[2])          # v[2] is `dead`
        if dead_n and dead_n >= max(1, int(len(THROWERS) * MOST_STALE_OK)):
            log("%d/%d look dead -- suspecting the gameserver, backing off"
                % (dead_n, len(THROWERS)))
            time.sleep(POLL * 5)
            continue

        # ONE restart per cycle, deliberately. Starting several throwers together
        # is what broke them in the first place: each one fetches /api/flagids
        # (144 KB) at startup, the gameserver refuses some of a simultaneous
        # burst, get_flagids() returns {} and the thrower dies on KeyError.
        # Verified by hand: six at once -> 0 survivors, one alone -> survives.
        for exploit, service, dead, recent, a, alive in verdicts:
            if not dead:
                continue
            if recent:
                log("skip %s, restarted recently" % os.path.basename(exploit))
                continue
            why = "not running" if not alive else (
                "no log" if a is None else "log quiet %.0fm" % (a / 60))
            log("%s looks dead (%s)" % (os.path.basename(exploit), why))
            if restart(exploit, service):
                last_restart[exploit] = time.time()
            break          # the rest wait for the next cycle

        time.sleep(POLL)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log("watchdog stopped")
        sys.exit(0)
