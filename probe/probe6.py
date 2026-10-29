import sys, time, json
sys.path.insert(0,'../lib')
from curl_cffi import requests as creq
import ds_pow_np as P

BASE='https://chat.deepseek.com'
H={'x-client-platform':'android','x-client-version':'2.7.1','x-client-locale':'zh_CN',
   'x-client-bundle-id':'com.deepseek.chat','Content-Type':'application/json','Accept':'*/*'}
s=creq.Session(impersonate='chrome')
s.get(BASE+'/',headers={'Accept':'text/html'},timeout=20)

r=s.post(BASE+'/api/v0/users/create_guest_challenge',json={'target_path':'/api/v0/users/register'},headers=H,timeout=20)
gc=r.json()['data']['biz_data']['guest_challenge']
print('challenge:',json.dumps(gc,indent=None))

t=time.time()
nonce=P.solve(gc['challenge'],gc['salt'],gc['expire_at'],gc['difficulty'],batch=16384)
el=time.time()-t
print(f'>>> SOLVED nonce={nonce} in {el:.2f}s (difficulty={gc["difficulty"]})')

# 手工验证一次
if nonce is not None:
    payload=f"{gc['salt']}_{gc['expire_at']}_{nonce}".encode()
    from ds_pow import dshash
    print('    digest match:', dshash(payload).hex()==gc['challenge'])

# 尝试提交 register，用不同 header 载荷格式
variants={
 'json_full': json.dumps({**gc,'answer':nonce}),
 'json_min':  json.dumps({'challenge':gc['challenge'],'salt':gc['salt'],'signature':gc['signature'],'answer':nonce}),
 'json_answer_only': json.dumps({'answer':nonce}),
}
for name,val in variants.items():
    hh=dict(H); hh['X-DS-Guest-Pow-Response']=val
    rr=s.post(BASE+'/api/v0/users/register',json={},headers=hh,timeout=20)
    print(f'--- register [{name}] -> {rr.status_code} | {rr.text[:300]}')
