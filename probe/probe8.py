import sys, time, json, base64, uuid
sys.path.insert(0,'../lib')
from curl_cffi import requests as creq
import ds_pow_np as P
BASE='https://chat.deepseek.com'
H={'x-client-platform':'android','x-client-version':'2.7.1','x-client-locale':'zh_CN',
   'x-client-bundle-id':'com.deepseek.chat','Content-Type':'application/json','Accept':'*/*'}
s=creq.Session(impersonate='chrome'); s.get(BASE+'/',headers={'Accept':'text/html'},timeout=20)
DEV=str(uuid.uuid4())

def pow_header(target_path):
    r=s.post(BASE+'/api/v0/users/create_guest_challenge',json={'target_path':target_path},headers=H,timeout=20)
    d=r.json()['data']
    if d.get('biz_code')!=0:
        return None, d
    gc=d['biz_data']['guest_challenge']
    n=P.solve(gc['challenge'],gc['salt'],gc['expire_at'],gc['difficulty'],batch=16384)
    v=base64.b64encode(json.dumps({'salt':gc['salt'],'answer':n},separators=(',',':')).encode()).decode()
    return v, gc

tp='/api/v0/users/create_email_verification_code'
hdr,gc=pow_header(tp)
print('pow header ok:', bool(hdr), gc if not hdr else '')

for scen in ['register','login','reset_password','signup','bind_email','update_email']:
    hh=dict(H); hh['X-DS-Guest-Pow-Response']=hdr
    body={'email':'probe%d@example.com'%int(time.time()%100000),'device_id':DEV,'scenario':scen}
    r=s.post(BASE+tp,json=body,headers=hh,timeout=25)
    print(f'--- scenario={scen:15s} -> {r.status_code} | {r.text[:220]}')
