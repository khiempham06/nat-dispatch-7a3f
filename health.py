#!/usr/bin/env python3
"""Thrower health check: is each one alive, and is it still paying?

A live process is not the same as a working exploit, so this cross-references
three things per exploit: the running `thrower` processes, the tail of its log,
and whether that log has grown recently. Anything that is running but silent,
or erroring every pass, shows up as a WARN/FAIL rather than being assumed fine.

usage: python3 health.py [tail_bytes]
"""
import collections, glob, os, re, subprocess, sys, time

TAIL = int(sys.argv[1]) if len(sys.argv) > 1 else 200_000
FLAG = re.compile(r"[A-Z0-9]{31}=")
NOW = time.time()


def run(cmd):
    try:
        return subprocess.run(cmd, shell=True, capture_output=True, text=True,
                              timeout=30).stdout
    except Exception as e:
        return "(%s)" % e


# --- running throwers -------------------------------------------------------
procs = collections.Counter()
pids = collections.defaultdict(list)
for line in run("pgrep -af thrower").splitlines():
    m = re.search(r"^(\d+)\s+.*?/thrower\s+(\S+)\s+(\d+)", line)
    if m:
        pid, path, svc = m.groups()
        procs[(os.path.basename(path), svc)] += 1
        pids[os.path.basename(path)].append(pid)

print("=" * 78)
print("RUNNING THROWERS")
if not procs:
    print("  NONE -- nothing is throwing")
for (name, svc), n in sorted(procs.items(), key=lambda kv: -kv[1]):
    flag = "   <-- DUPLICATE" if n > 1 else ""
    print("  %-20s service=%-3s instances=%d%s" % (name, svc, n, flag))

# --- per-log health ---------------------------------------------------------
print()
print("=" * 78)
print("%-20s %7s %7s %6s %6s %6s  %s" %
      ("log", "size", "age", "flags", "uniq", "errs", "state"))

rows = []
#: /root/*.log also catches our own tooling (the tcpdump capture, the
#: watchdog's log), which are not throwers and were reported as FAIL.
NOT_THROWERS = {"cap.log", "supervise.log", "health.log", "nohup.log"}


def thrower_logs():
    return [p for p in sorted(glob.glob("/root/*.log"))
            if os.path.basename(p) not in NOT_THROWERS]


for path in thrower_logs():
    name = os.path.basename(path)
    base = name[:-4]
    size = os.path.getsize(path)
    age = NOW - os.path.getmtime(path)
    with open(path, "rb") as f:
        if size > TAIL:
            f.seek(-TAIL, os.SEEK_END)
        tail = f.read().decode("utf-8", "replace")

    hits = FLAG.findall(tail)
    uniq = len(set(hits))
    errs = len(re.findall(r"Traceback|Error:|error:|Exception", tail))
    alive = any(base in n for (n, _s) in procs)

    # state: the useful judgement, not just the numbers
    if not alive:
        state = "FAIL not running"
    elif age > 600:
        state = "WARN log stale %.0fm" % (age / 60)
    elif uniq == 0 and errs:
        state = "FAIL erroring, 0 flags"
    elif uniq == 0:
        state = "WARN alive, 0 flags in tail"
    elif errs > uniq:
        state = "WARN more errors than flags"
    else:
        state = "OK"
    rows.append((state, name))
    print("%-20s %6dK %6.0fm %6d %6d %6d  %s" %
          (name, size // 1024, age / 60, len(hits), uniq, errs, state))

# a log for something not running, and a thrower with no log, are both worth saying
logged = {os.path.basename(p)[:-4] for p in glob.glob("/root/*.log")}
for (name, _svc) in procs:
    stem = name[:-3] if name.endswith(".py") else name
    if not any(stem in l for l in logged):
        print("  NOTE %-18s is running but has no /root log (started elsewhere?)" % name)

# --- most recent evidence per log ------------------------------------------
print()
print("=" * 78)
print("LAST FLAG LINE PER LOG (evidence it is still paying)")
for path in thrower_logs():
    with open(path, "rb") as f:
        size = os.path.getsize(path)
        if size > TAIL:
            f.seek(-TAIL, os.SEEK_END)
        tail = f.read().decode("utf-8", "replace")
    last = ""
    for line in tail.splitlines():
        if FLAG.search(line):
            last = line.strip()[:96]
    print("  %-18s %s" % (os.path.basename(path), last or "(no flag line in tail)"))

# --- our own SLA ------------------------------------------------------------
print()
print("=" * 78)
print("OUR SLA (a thrower is worthless if our own services are down)")
checks = run("glitch checks")
tick = re.search(r"Tick\s+(\d+)", re.sub(r"\x1b\[[0-9;]*m", "", checks))
clean = re.sub(r"\x1b\[[0-9;]*m", "", checks)
print("  tick:", tick.group(1) if tick else "?")
svc = None
bad = []
for line in clean.splitlines():
    line = line.rstrip()
    m = re.match(r"^(\w[\w-]*):$", line.strip())
    if m:
        svc = m.group(1)
    m2 = re.match(r"\s+(sla|put|get):\s*(\S+)", line)
    if m2 and m2.group(2) != "OK":
        bad.append("%s/%s=%s" % (svc, m2.group(1), m2.group(2)))
print("  non-OK checks:", ", ".join(bad) if bad else "none -- all 7 services OK")

print()
fails = [n for s, n in rows if s.startswith("FAIL")]
warns = [n for s, n in rows if s.startswith("WARN")]
print("SUMMARY: %d OK, %d WARN %s, %d FAIL %s" %
      (len(rows) - len(fails) - len(warns), len(warns), warns or "", len(fails), fails or ""))
