from curl_cffi import requests as creq
import json, time

BASE='https://chat.deepseek.com'
H={'x-client-platform':'android','x-client-version':'2.7.1','x-client-locale':'zh_CN',
   'x-client-bundle-id':'com.deepseek.chat','Accept':'application/json'}

for imp in ['chrome','chrome124','safari','edge101']:
    try:
        s=creq.Session(impersonate=imp)
        t=time.time()
        r=s.get(BASE+'/', headers={'Accept':'text/html'}, timeout=20)
        print(f'[imp={imp}] GET / -> {r.status_code} {1000*(time.time()-t):.0f}ms len={len(r.content)} cookies={list(s.cookies.keys())}')
        if r.status_code==200:
            print('  title ok, testing api...')
            r2=s.post(BASE+'/api/v0/create_guest_challenge', json={'target_path':'/api/v0/users/register'}, headers={**H,'Content-Type':'application/json'}, timeout=20)
            print('  guest_challenge ->', r2.status_code, r2.text[:500])
            break
        else:
            print('  block page:', r.text[:120].replace('\n',' '))
    except Exception as e:
        print(f'[imp={imp}] EXC {type(e).__name__}: {e}')
