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

#: Per-thrower restart budget, instead of a global "most look dead -> back off".
#: The global version misfired: it counted a deliberately-stopped thrower and a
#: broken-but-alive one toward "the gameserver is down", decided the whole game
#: was offline and stopped supervising ANYTHING, so a genuinely recoverable
#: thrower stayed dead. A per-thrower budget gives up only on the one that keeps
#: failing and keeps supervising the rest.
MAX_RESTARTS = 4
BUDGET_WINDOW = 30 * 60


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
    # Do NOT use `glitch exploit kill <name>.py`: it is a no-op. glitch's
    # dispatcher returns on `len(sys.argv) < 5` before reaching the kill
    # branch, even though its own help documents that exact 4-argument form.
    # Trusting it leaked one extra thrower on EVERY restart here and helped
    # drive the box to a 15-minute load average of 202, which took our own
    # flightplan, doors and shaas SLA checks down. So pkill directly, and
    # refuse to start a replacement until the old process is really gone.
    subprocess.run(["pkill", "-f", "thrower .*/%s" % name],
                   capture_output=True, text=True)
    for _ in range(10):
        time.sleep(1)
        if not running(exploit):
            break
    else:
        log("REFUSING to restart %s: the old process will not die" % name)
        return False
    r = subprocess.run(["glitch", "exploit", "throw", exploit, service],
                       capture_output=True, text=True)
    ok = "started" in (r.stdout or "")
    log("restart %-28s service=%-10s %s" % (name, service, "OK" if ok else
        "FAILED: " + (r.stdout or r.stderr or "no output").strip()[:120]))
    return ok


def main():
    last_restart = {}
    history = {}            # exploit -> [restart timestamps]
    log("watchdog up: %d throwers, poll=%ds stale=%ds budget=%d/%dm"
        % (len(THROWERS), POLL, STALE, MAX_RESTARTS, BUDGET_WINDOW // 60))
    while True:
        now = time.time()
        verdicts = []
        for exploit, service in THROWERS:
            a = age(exploit)
            alive = running(exploit)
            recent = now - last_restart.get(exploit, 0) < GRACE
            dead = (not alive) or (a is None) or (a > STALE)
            # drop restarts that have aged out of the rolling window
            history[exploit] = [t for t in history.get(exploit, [])
                                if now - t < BUDGET_WINDOW]
            spent = len(history[exploit])
            verdicts.append((exploit, service, dead, recent, a, alive, spent))

        # ONE restart per cycle, deliberately. Starting several throwers together
        # is what broke them in the first place: each one fetches /api/flagids
        # (144 KB) at startup, the gameserver refuses some of a simultaneous
        # burst, get_flagids() returns {} and the thrower dies on KeyError.
        # Verified by hand: six at once -> 0 survivors, one alone -> survives.
        for exploit, service, dead, recent, a, alive, spent in verdicts:
            if not dead or recent:
                continue
            name = os.path.basename(exploit)
            if spent >= MAX_RESTARTS:
                log("giving up on %s for now (%d restarts in %dm did not stick)"
                    % (name, spent, BUDGET_WINDOW // 60))
                continue
            why = "not running" if not alive else (
                "no log" if a is None else "log quiet %.0fm" % (a / 60))
            log("%s looks dead (%s), restart %d/%d" % (name, why, spent + 1, MAX_RESTARTS))
            if restart(exploit, service):
                last_restart[exploit] = time.time()
                history[exploit].append(time.time())
            break          # the rest wait for the next cycle

        time.sleep(POLL)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log("watchdog stopped")
        sys.exit(0)
