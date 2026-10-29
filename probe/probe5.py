from curl_cffi import requests as creq
BASE='https://chat.deepseek.com'
H={'x-client-platform':'android','x-client-version':'2.7.1','x-client-locale':'zh_CN',
   'x-client-bundle-id':'com.deepseek.chat','Content-Type':'application/json','Accept':'*/*'}
s=creq.Session(impersonate='chrome')
s.get(BASE+'/',headers={'Accept':'text/html'},timeout=20)
tests=[
 ('POST','/api/v0/users/login',{'email':'test@example.com','password':'x'*8,'device_id':'1','os':'android'}),
 ('POST','/api/v0/users/login',{}),
 ('POST','/api/v0/users/register',{}),
 ('POST','/api/v0/users/create_email_verification_code',{'email':'test@example.com'}),
 ('POST','/api/v0/users/create_sms_verification_code',{'mobile_number':'13800138000','area_code':'+86'}),
]
for m,p,b in tests:
    r=s.post(BASE+p,json=b,headers=H,timeout=25)
    print(f'--- {p} body={list(b.keys())} -> {r.status_code} | {r.text[:450]}')
