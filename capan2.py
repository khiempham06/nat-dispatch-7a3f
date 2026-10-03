#!/usr/bin/env python3
"""Second pass: who talks to whom, and is the checker AUTHENTICATED when it
reads the rsa/sigs panels?

That one question decides whether gating code_hex on ownership is SLA-safe or
an instant zero, so it is answered per TCP connection rather than per command.

usage: python3 capan2.py /root/cap.pcap
"""
import collections, re, struct, sys

sys.path.insert(0, "/root")
from capan import ip_tcp, packets          # reuse the validated parser

PATH = sys.argv[1] if len(sys.argv) > 1 else "/root/cap.pcap"
VEGAS, NOISE = 7770, 6426
US = "10.100.90.1"
CMDS = {"help", "health", "register", "login", "logout", "session", "whoami", "new",
        "show", "put", "get", "sigs", "rsa", "verify-sig", "verify-rsa", "quit", "exit"}

matrix = collections.Counter()
flows = collections.OrderedDict()

for lt, frame in packets(PATH):
    p = ip_tcp(lt, frame)
    if not p:
        continue
    src, dst, sport, dport, payload = p
    matrix[(src, dst, dport)] += 1
    if dport == VEGAS and payload:
        flows.setdefault((src, sport), bytearray())
        if len(flows[(src, sport)]) < 8192:
            flows[(src, sport)] += payload

print("=" * 74)
print("TRAFFIC MATRIX  src -> dst:port  (packets)")
for (s, d, dp), n in matrix.most_common(16):
    tag = ""
    if s == US:
        tag = "  <- OUR outbound attack"
    elif d == US:
        tag = "  <- INBOUND to us"
    print("  %-15s -> %-15s :%-6d %7d%s" % (s, d, dp, n, tag))

inbound = {(s, d) for (s, d, _) in matrix if d == US and s != US}
print()
print("distinct hosts sending to US:", sorted({s for s, _ in inbound}) or "none")

# --- per-connection command sequence on vegas ------------------------------
print()
print("=" * 74)
print("VEGAS per-connection command sequences (first 12 cmds per flow)")

auth_state = collections.Counter()
examples = {}
for (src, sport), buf in flows.items():
    seq = []
    for raw in bytes(buf).replace(b"\r", b"\n").split(b"\n"):
        t = raw.strip().decode("utf-8", "replace")
        if not t:
            continue
        head = t.split()[0].lower()
        if head in CMDS:
            seq.append(head)
    if not seq:
        continue
    # Did this connection authenticate BEFORE it read a panel?
    panels = [i for i, c in enumerate(seq) if c in ("rsa", "sigs", "show")]
    logins = [i for i, c in enumerate(seq) if c in ("login", "register", "session")]
    if panels:
        first_panel = panels[0]
        authed = any(i < first_panel for i in logins)
        key = (src, "AUTHED before panel" if authed else "ANONYMOUS panel read")
        auth_state[key] += 1
        examples.setdefault(key, " ".join(seq[:12]))

for (src, state), n in auth_state.most_common():
    print("  %-15s %-22s %4d flows" % (src, state, n))
    print("      e.g. %s" % examples[(src, state)])

print()
print("=" * 74)
print("VERDICT for an ownership gate on code_hex:")
anon = [(s, st) for (s, st) in auth_state if st.startswith("ANONYMOUS") and s != US]
if anon:
    print("  RISKY - a non-us host reads rsa/sigs/show WITHOUT authenticating first:")
    for s, _ in anon:
        print("    %s  (%d flows)" % (s, auth_state[(s, 'ANONYMOUS panel read')]))
    print("  If that host is the checker, gating code_hex on ownership zeroes the SLA.")
else:
    print("  SAFE so far - every non-us panel read authenticated first, so a gate")
    print("  that still serves owners would keep the checker working.")
