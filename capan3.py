#!/usr/bin/env python3
"""Third pass: separate real inbound attacks from NAT artefacts and from our
own outbound traffic, then profile what each attacker actually sends.

The matrix in capan2 was ambiguous because Docker rewrites addresses: a packet
to 10.100.90.1:6426 is DNAT'd to the container, so the same flow is captured
twice on -i any, and anything SNAT'd shows OUR host as the source. This
buckets by destination class instead of trusting the source.

usage: python3 capan3.py /root/cap.pcap
"""
import collections, re, struct, sys

sys.path.insert(0, "/root")
from capan import ip_tcp, packets

PATH = sys.argv[1] if len(sys.argv) > 1 else "/root/cap.pcap"
US = "10.100.90.1"
SERVICE_PORTS = {6426: "noise", 7770: "vegas"}
OPS = {1: "REGISTER", 2: "LIST_USERS", 3: "CHALLENGE", 4: "SEND_DM", 5: "GET_MESSAGES",
       6: "CREATE_GROUP", 7: "GROUP_CHALLENGE", 8: "INVITE", 9: "LIST_GROUPS",
       10: "SEND_GROUP", 11: "GROUP_MESSAGES", 12: "LIST_ALL_GROUPS"}
CMDS = {"help", "health", "register", "login", "logout", "session", "whoami", "new",
        "show", "put", "get", "sigs", "rsa", "verify-sig", "verify-rsa", "quit", "exit"}


def is_container(ip):
    """Docker bridge space: our own service containers."""
    a = ip.split(".")
    return a[0] == "172" and 16 <= int(a[1]) <= 31


buckets = collections.Counter()
# (bucket, src, svc) -> payload buffer
flows = collections.OrderedDict()
inbound_src = collections.Counter()
selfattack = collections.Counter()

for lt, frame in packets(PATH):
    p = ip_tcp(lt, frame)
    if not p:
        continue
    src, dst, sport, dport, payload = p
    svc = SERVICE_PORTS.get(dport)
    if not svc:
        continue                                   # ignore replies / other ports
    if dst == US or is_container(dst):
        if src == US:
            bucket = "SELF (we attack our own box, or SNAT hides the source)"
            selfattack[(svc, dst)] += 1
        else:
            bucket = "INBOUND (someone attacking us)"
            inbound_src[(src, svc)] += 1
    elif src == US:
        bucket = "OUTBOUND (our throwers)"
    else:
        bucket = "OTHER"
    buckets[(bucket, svc)] += 1
    if bucket.startswith("INBOUND") and payload:
        key = (src, svc, sport)
        buf = flows.setdefault(key, bytearray())
        if len(buf) < 3000:
            buf += payload[: 3000 - len(buf)]

print("=" * 74)
print("PACKETS TO SERVICE PORTS, bucketed by destination (not source)")
for (b, svc), n in buckets.most_common():
    print("  %-56s %-6s %8d" % (b, svc, n))

print()
print("=" * 74)
print("SELF-DIRECTED traffic to our own services (svc, dst) -> packets")
for (svc, dst), n in selfattack.most_common(8):
    print("  %-6s -> %-14s %8d" % (svc, dst, n))
print("  NOTE: if our throwers include our own team id, this is wasted effort")
print("        and our own flags get resubmitted. Compare with `glitch targets`.")

print()
print("=" * 74)
print("INBOUND attackers (src, service) -> packets   [the exploit-stealing list]")
if not inbound_src:
    print("  none seen -- every packet to our ports came from us or the gameserver")
for (src, svc), n in inbound_src.most_common(25):
    tag = "  <- GAMESERVER/checker" if src == "10.100.0.1" else ""
    print("  %-15s %-6s %8d%s" % (src, svc, n, tag))

# --- what each inbound attacker actually sends ----------------------------
print()
print("=" * 74)
print("WHAT INBOUND SOURCES SEND  (excluding the gameserver)")
prof_v = collections.defaultdict(collections.Counter)
prof_n = collections.defaultdict(collections.Counter)
samples = collections.defaultdict(list)

for (src, svc, _sp), buf in flows.items():
    b = bytes(buf)
    if svc == "vegas":
        for raw in b.replace(b"\r", b"\n").split(b"\n"):
            t = raw.strip().decode("utf-8", "replace")
            if t and t.split()[0].lower() in CMDS:
                prof_v[src][t.split()[0].lower()] += 1
                if len(samples[src]) < 4 and src != "10.100.0.1":
                    samples[src].append(t[:100])
    else:
        i = 0
        while True:
            j = b.find(b"NOIZ", i)
            if j < 0 or j + 11 > len(b):
                break
            _m, ver, _f, op, ln = struct.unpack("!4sBBBI", b[j:j + 11])
            if ver == 1 and ln <= (1 << 20):
                prof_n[src][OPS.get(op, "op%d" % op)] += 1
                i = j + 11 + ln if j + 11 + ln <= len(b) else j + 11
            else:
                i = j + 4

for src, c in sorted(prof_v.items(), key=lambda kv: -sum(kv[1].values())):
    if src == "10.100.0.1":
        continue
    print("  vegas %-15s %s" % (src, dict(c.most_common(10))))
    for s in samples[src]:
        print("        %s" % s)
for src, c in sorted(prof_n.items(), key=lambda kv: -sum(kv[1].values())):
    if src == "10.100.0.1":
        continue
    print("  noise %-15s %s" % (src, dict(c.most_common(10))))
if not any(s != "10.100.0.1" for s in list(prof_v) + list(prof_n)):
    print("  nothing -- no non-gameserver source reached our service ports pre-NAT")
