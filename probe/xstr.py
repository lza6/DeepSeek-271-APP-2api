import sys,re
def strs(p,minlen=4):
    d=open(p,'rb').read()
    for m in re.finditer(rb'[\x20-\x7e]{%d,}'%minlen,d):
        yield m.start(),m.group().decode('ascii',errors='replace')
if __name__=='__main__':
    path=sys.argv[1]; pat=sys.argv[2]
    rx=re.compile(pat,re.I)
    seen=set()
    for off,s in strs(path):
        if rx.search(s) and s not in seen:
            seen.add(s); print('0x%08x  %s'%(off,s[:200]))
