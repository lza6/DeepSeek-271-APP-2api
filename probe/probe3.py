from curl_cffi import requests as creq
import json, time
BASE='https://chat.deepseek.com'
H={'x-client-platform':'android','x-client-version':'2.7.1','x-client-locale':'zh_CN',
   'x-client-bundle-id':'com.deepseek.chat','Content-Type':'application/json','Accept':'*/*'}
s=creq.Session(impersonate='chrome')
r=s.get(BASE+'/',headers={'Accept':'text/html'},timeout=20)
print('warmup',r.status_code,list(s.cookies.keys()))

def show(tag,r):
    print(f'--- {tag} -> {r.status_code} {len(r.content)}B')
    print('   hdr-x:', {k:v for k,v in r.headers.items() if k.lower().startswith('x-') or k.lower()=='server'})
    print('   body:', r.text[:600].replace('\n',' '))

for method,path,body in [
    ('POST','/api/v0/users/create_guest_challenge',{'target_path':'/api/v0/users/register'}),
    ('POST','/api/v0/users/create_guest_challenge',{'target_path':'/api/v0/users/login'}),
    ('POST','/api/v0/chat/create_pow_challenge',{}),
    ('GET','/api/v0/chat/create_pow_challenge',None),
    ('GET','/api/v0/client/settings',None),
]:
    try:
        t=time.time()
        if method=='POST': r=s.post(BASE+path,json=body,headers=H,timeout=25)
        else: r=s.get(BASE+path,headers=H,timeout=25)
        show(f'{method} {path} body={body}',r)
    except Exception as e:
        print(f'--- {method} {path} EXC {type(e).__name__}: {e}')
