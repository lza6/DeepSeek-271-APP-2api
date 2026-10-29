import struct,sys,re,collections
def uload(d,p):
    r=0;s=0
    while True:
        b=d[p];p+=1;r|=(b&0x7f)<<s;s+=7
        if b<0x80:break
    return r,p
def strs(d):
    n,off=struct.unpack('<II',d[56:64]);out=[]
    for i in range(n):
        o=struct.unpack('<I',d[off+i*4:off+i*4+4])[0]
        ln,p=uload(d,o); e=d.index(b'\x00',p)
        out.append(d[p:e].decode('utf-8','replace'))
    return out
def types(d,S):
    n,off=struct.unpack('<II',d[64:72])
    return [S[struct.unpack('<I',d[off+i*4:off+i*4+4])[0]] for i in range(n)]
def classdefs(d,S,T):
    n,off=struct.unpack('<II',d[96:104]);out=[]
    for i in range(n):
        b=off+i*32
        cidx,acc,sup,ifs=struct.unpack('<IIII',d[b:b+16])
        sfi=struct.unpack('<I',d[b+16:b+20])[0]
        out.append((T[cidx],acc,T[sup] if sup!=0xffffffff else None,S[sfi] if sfi!=0xffffffff else None))
    return out
p=sys.argv[1]
d=open(p,'rb').read()
S=strs(d);T=types(d,S);C=classdefs(d,S,T)
print('file',p,'classes',len(C))
pk=collections.Counter()
for name,acc,sup,sf in C:
    pkg=name.rsplit('/',1)[0] if '/' in name else '(default)'
    # collapse to 3 levels
    parts=pkg.lstrip('L').split('/')
    key='/'.join(parts[:3])
    pk[key]+=1
if len(sys.argv)>2 and sys.argv[2]=='pkgs':
    for k,v in pk.most_common(): print('  %-45s %d'%(k,v))
else:
    for name,acc,sup,sf in C:
        print('  %-80s super=%-40s src=%s'%(name,sup,sf))
