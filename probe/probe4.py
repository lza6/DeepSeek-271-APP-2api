from curl_cffi import requests as creq
import json
BASE='https://chat.deepseek.com'
H={'x-client-platform':'android','x-client-version':'2.7.1','x-client-locale':'zh_CN',
   'x-client-bundle-id':'com.deepseek.chat','Content-Type':'application/json','Accept':'*/*'}
s=creq.Session(impersonate='chrome')
s.get(BASE+'/',headers={'Accept':'text/html'},timeout=20)

cands=['/api/v0/users/register','/api/v0/users/login','/api/v0/users/login_by_mobile',
'/api/v0/users/register_by_mobile','/api/v0/users/create_sms_verification_code',
'/api/v0/users/check_sms_code','/api/v0/users/create_email_verification_code',
'/api/v0/users/check_email_code','/api/v0/users/oauth/google/authorize',
'/api/v0/users/oauth/google/login','/api/v0/users/oauth/wechat/bind',
'/api/v0/users/one_tap_login','/api/v0/users/reset_password',
'/api/v0/chat/completion','/api/v0/users/current','/']
for p in cands:
    try:
        r=s.post(BASE+'/api/v0/users/create_guest_challenge',json={'target_path':p},headers=H,timeout=20)
        try:
            j=r.json(); d=j.get('data') or {}
            bc=d.get('biz_code'); bm=d.get('biz_msg')
            gb=(d.get('biz_data') or {}).get('guest_challenge')
            print(f'{p:55s} code={j.get("code")} biz_code={bc} {bm} {"+CHALLENGE target="+gb["target_path"] if gb else ""}')
        except Exception:
            print(f'{p:55s} RAW {r.status_code} {r.text[:100]}')
    except Exception as e:
        print(p,'EXC',e)
