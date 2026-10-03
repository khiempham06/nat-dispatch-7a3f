#!/usr/bin/env python3
"""Summarise a tcpdump capture of noise (6426) and vegas (7770) traffic.

Runs on the vulnbox so a multi-megabyte pcap never has to leave it: prints a
compact per-source-IP profile of what every attacker and the checker actually
send. Pure stdlib pcap reader - no scapy, no dpkt.

usage: python3 capan.py /root/cap.pcap [max_bytes_per_flow]
"""
import collections, re, struct, sys

PATH = sys.argv[1] if len(sys.argv) > 1 else "/root/cap.pcap"
CAP = int(sys.argv[2]) if len(sys.argv) > 2 else 4096

NOISE_PORT, VEGAS_PORT = 6426, 7770
OPS = {1: "REGISTER", 2: "LIST_USERS", 3: "CHALLENGE", 4: "SEND_DM", 5: "GET_MESSAGES",
       6: "CREATE_GROUP", 7: "GROUP_CHALLENGE", 8: "INVITE", 9: "LIST_GROUPS",
       10: "SEND_GROUP", 11: "GROUP_MESSAGES", 12: "LIST_ALL_GROUPS"}
VEGAS_CMDS = {"help", "health", "register", "login", "logout", "session", "whoami",
              "new", "show", "put", "get", "sigs", "rsa", "verify-sig", "verify-rsa",
              "quit", "exit"}
FLAG = re.compile(rb"[A-Z0-9]{31}=")


def packets(path):
    """Yield (linktype, raw_frame) from a classic little/big-endian pcap."""
    with open(path, "rb") as f:
        gh = f.read(24)
        if len(gh) < 24:
            return
        magic = gh[:4]
        if magic == b"\xd4\xc3\xb2\xa1":
            end, nano = "<", False
        elif magic == b"\xa1\xb2\xc3\xd4":
            end, nano = ">", False
        elif magic == b"\x4d\x3c\xb2\xa1":
            end, nano = "<", True
        elif magic == b"\xa1\xb2\x3c\x4d":
            end, nano = ">", True
        else:
            sys.exit("not a classic pcap (magic %r) - if this is pcapng, "
                     "re-capture without -w or convert it" % magic)
        linktype = struct.unpack(end + "I", gh[20:24])[0]
        hdr = struct.Struct(end + "IIII")
        while True:
            h = f.read(16)
            if len(h) < 16:
                return
            _s, _us, caplen, _orig = hdr.unpack(h)
            data = f.read(caplen)
            if len(data) < caplen:
                return
            yield linktype, data


def ip_tcp(linktype, frame):
    """Strip link + IP + TCP headers. Returns (src, dst, sport, dport, payload)."""
    if linktype == 113:            # LINUX_SLL, what -i any produces
        if len(frame) < 16:
            return None
        proto = struct.unpack("!H", frame[14:16])[0]
        rest = frame[16:]
    elif linktype == 276:          # LINUX_SLL2
        if len(frame) < 20:
            return None
        proto = struct.unpack("!H", frame[0:2])[0]
        rest = frame[20:]
    elif linktype == 1:            # EN10MB
        if len(frame) < 14:
            return None
        proto = struct.unpack("!H", frame[12:14])[0]
        rest = frame[14:]
    elif linktype == 101:          # RAW IP
        proto, rest = 0x0800, frame
    else:
        return None
    if proto != 0x0800 or len(rest) < 20:
        return None
    ihl = (rest[0] & 0x0F) * 4
    if rest[9] != 6 or len(rest) < ihl + 20:       # TCP only
        return None
    src = ".".join(str(b) for b in rest[12:16])
    dst = ".".join(str(b) for b in rest[16:20])
    tcp = rest[ihl:]
    sport, dport = struct.unpack("!HH", tcp[0:4])
    doff = (tcp[12] >> 4) * 4
    return src, dst, sport, dport, tcp[doff:]


# flow key -> accumulated client->server bytes
flows = collections.OrderedDict()
seen_ports = collections.Counter()
total = 0

for linktype, frame in packets(PATH):
    parsed = ip_tcp(linktype, frame)
    if not parsed:
        continue
    src, dst, sport, dport, payload = parsed
    total += 1
    seen_ports[dport] += 1
    if dport not in (NOISE_PORT, VEGAS_PORT) or not payload:
        continue                                    # client -> service only
    key = (src, sport, dport)
    buf = flows.setdefault(key, bytearray())
    if len(buf) < CAP:
        buf += payload[: CAP - len(buf)]

print("packets parsed        :", total)
print("busiest dst ports     :", seen_ports.most_common(6))
print("client->service flows :", len(flows))
print()

# --- vegas: text protocol -------------------------------------------------
vegas_cmd = collections.defaultdict(collections.Counter)
vegas_lines = collections.Counter()
for (src, _sp, dport), buf in flows.items():
    if dport != VEGAS_PORT:
        continue
    for raw in bytes(buf).replace(b"\r", b"\n").split(b"\n"):
        line = raw.strip()
        if not line:
            continue
        txt = line.decode("utf-8", "replace")
        head = txt.split()[0].lower() if txt.split() else ""
        if head in VEGAS_CMDS:
            vegas_cmd[src][head] += 1
            vegas_lines[txt[:110]] += 1

print("=" * 72)
print("VEGAS 7770 - commands per source IP")
for src, c in sorted(vegas_cmd.items(), key=lambda kv: -sum(kv[1].values())):
    print("  %-15s %s" % (src, dict(c.most_common())))
print()
print("VEGAS - most common exact command lines")
for line, n in vegas_lines.most_common(18):
    print("  %5d  %s" % (n, line))

# --- noise: NOIZ binary framing -------------------------------------------
noise_ops = collections.defaultdict(collections.Counter)
for (src, _sp, dport), buf in flows.items():
    if dport != NOISE_PORT:
        continue
    b, i = bytes(buf), 0
    while True:
        j = b.find(b"NOIZ", i)
        if j < 0 or j + 11 > len(b):
            break
        _m, ver, flags, op, ln = struct.unpack("!4sBBBI", b[j:j + 11])
        if ver == 1 and ln <= (1 << 20):
            noise_ops[src][OPS.get(op, "op%d" % op)] += 1
            i = j + 11 + ln if j + 11 + ln <= len(b) else j + 11
        else:
            i = j + 4

print()
print("=" * 72)
print("NOISE 6426 - opcodes per source IP")
for src, c in sorted(noise_ops.items(), key=lambda kv: -sum(kv[1].values())):
    print("  %-15s %s" % (src, dict(c.most_common())))

# --- anything flag-shaped crossing the wire -------------------------------
hits = collections.Counter()
for buf in flows.values():
    for m in FLAG.findall(bytes(buf)):
        hits[m.decode()] += 1
print()
print("flag-shaped strings in CLIENT->SERVICE traffic:", len(hits))
for f, n in hits.most_common(10):
    print("  %3d  %s" % (n, f))
