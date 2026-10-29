import urllib.request, urllib.error, http.cookiejar, json, ssl, time

BASE = 'https://chat.deepseek.com'
UA_APP = 'okhttp/4.12.0'
H = {
 'User-Agent': UA_APP,
 'x-client-platform': 'android',
 'x-client-version': '2.7.1',
 'x-client-locale': 'zh_CN',
 'Accept': 'application/json',
 'Content-Type': 'application/json',
 'x-app-version': '2.7.1',
}
cj = http.cookiejar.CookieJar()
ctx = ssl.create_default_context()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))

def call(method, path, body=None, extra=None, timeout=25):
    h = dict(H)
    if extra: h.update(extra)
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(BASE + path, data=data, headers=h, method=method)
    t = time.time()
    try:
        with opener.open(r, timeout=timeout) as resp:
            b = resp.read()
            return resp.status, b, (time.time()-t)*1000, dict(resp.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read(), (time.time()-t)*1000, dict(e.headers)
    except Exception as e:
        return -1, str(e).encode(), (time.time()-t)*1000, {}

print('--- 阶段1: warm-up 3轮 GET / ---')
for i in range(3):
    st, b, ms, hd = call('GET', '/', extra={'Accept':'text/html'})
    print(f'  #{i+1} -> {st} {ms:.0f}ms len={len(b)} cookies={[c.name for c in cj]}')

print('\n--- 阶段2: POST /api/v0/create_guest_challenge ---')
st, b, ms, hd = call('POST', '/api/v0/create_guest_challenge', {'target_path':'/api/v0/users/register'})
print(f'  -> {st} {ms:.0f}ms')
print('  body:', b[:600])

print('\n--- 阶段3: POST /api/v0/chat/completion (无token) ---')
st, b, ms, hd = call('POST', '/api/v0/chat/completion', {'chat_session_id':'x','prompt':'hi'})
print(f'  -> {st} {ms:.0f}ms body={b[:300]}')

print('\n--- 阶段4: GET /api/v0/users/current (无token) ---')
st, b, ms, hd = call('GET', '/api/v0/users/current')
print(f'  -> {st} {ms:.0f}ms body={b[:300]}')
