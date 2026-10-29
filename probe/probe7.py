import sys, time, json, base64
sys.path.insert(0,'../lib')
from curl_cffi import requests as creq
import ds_pow_np as P
BASE='https://chat.deepseek.com'
H={'x-client-platform':'android','x-client-version':'2.7.1','x-client-locale':'zh_CN',
   'x-client-bundle-id':'com.deepseek.chat','Content-Type':'application/json','Accept':'*/*'}
s=creq.Session(impersonate='chrome'); s.get(BASE+'/',headers={'Accept':'text/html'},timeout=20)

r=s.post(BASE+'/api/v0/users/create_guest_challenge',json={'target_path':'/api/v0/users/register'},headers=H,timeout=20)
gc=r.json()['data']['biz_data']['guest_challenge']
t=time.time(); nonce=P.solve(gc['challenge'],gc['salt'],gc['expire_at'],gc['difficulty'],batch=16384)
print(f'solved nonce={nonce} in {time.time()-t:.2f}s')

payloads={
 'raw_json': json.dumps({'salt':gc['salt'],'answer':nonce},separators=(',',':')),
 'raw_json_sp': json.dumps({'salt':gc['salt'],'answer':nonce}),
 'b64': base64.b64encode(json.dumps({'salt':gc['salt'],'answer':nonce},separators=(',',':')).encode()).decode(),
 'plus_challenge': json.dumps({'salt':gc['salt'],'answer':nonce,'challenge':gc['challenge'],'signature':gc['signature'],'target_path':gc['target_path']},separators=(',',':')),
}
for name,val in payloads.items():
    hh=dict(H); hh['X-DS-Guest-Pow-Response']=val
    rr=s.post(BASE+'/api/v0/users/register',json={},headers=hh,timeout=20)
    print(f'--- [{name}] -> {rr.status_code} | {rr.text[:250]}')
