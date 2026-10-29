# DeepSeek Android v2.7.1 — 协议还原

APK: `DeepSeek_v2.7.1_(288)_Mod.apk` · `md5 f90bf9c83805394b36f8cc2b9106e1c8`
包名 `com.deepseek.chat` · versionCode 288 · arm64-v8a · minSdk 29 / targetSdk 36
上游 `https://chat.deepseek.com`（华为 HWWAF 前置，`Server: CW`）

所有结论标注证据等级：

- **已验证** — 实际跑过，有输出
- **静态确认** — 反编译代码确认，未跑
- **合理推断** — 有间接证据
- **待验证** — 缺条件

---

## 1. 传输层

| 项 | 值 | 等级 |
|---|---|---|
| TLS 指纹 | 必须浏览器指纹（实测 `curl_cffi impersonate="chrome"`）；`urllib` / `requests` 一律 429 `Request Blocked` | 已验证 |
| warm-up | 先 `GET /` 换取 `HWWAFSESID` / `HWWAFSESTIME` / `ds_session_id` cookie，之后所有 API 复用同一 session | 已验证 |
| 请求头 | `x-client-platform: android`、`x-client-version: 2.7.1`（`p000/x06.java:74` 硬编码）、`x-client-locale`、`x-client-bundle-id: com.deepseek.chat`、`x-device-id`、`x-client-timezone-offset` | 已验证 |
| 鉴权 | `x-auth-token: <token>`（自定义头，**不是** `Authorization: Bearer`，见 `nw8.java:434`） | 静态确认 |
| 响应包络 | `{code, msg, data:{biz_code, biz_msg, biz_data}}`；`code=0` 且 `biz_code=0` 才算成功 | 已验证 |
| 常见错误码 | `40002 Missing Token`、`40300 Missing Header`、`40302 PAYLOAD_SCHEMA_MISMATCH`、`biz_code=2 RECAPTCHA_VERIFY_FAILED`、`biz_code=1 INVALID_TARGET_PATH` | 已验证 |

---

## 2. 端点全表（57 个）

```
/api/v0/users/register                          register_by_mobile  login  logout
/api/v0/users/create_guest_challenge            check_email_code    check_sms_code
/api/v0/users/create_email_verification_code    create_sms_verification_code
/api/v0/users/current  settings  update_settings  get_birthday  set_birthday  unregister
/api/v0/users/one_tap_login                     oauth/get_token  oauth/google/authorize
/api/v0/users/oauth/wechat/bind                 auth_token/list  auth_token/revoke
/api/v0/users/mfa/trusted_device/register|verify  mfa/create_verification_code
/api/v0/chat/create_pow_challenge   ← v2.7.1 新增
/api/v0/chat/completion  continue  edit_message  regenerate  resume_stream  stop_stream
/api/v0/chat/history_messages  message_feedback
/api/v0/chat/tts/  tts/voice  tts/voices       ← 语音合成
/api/v0/chat_session/create  delete  delete_all  fetch_page  update_title  update_pinned
/api/v0/call/start  stop  update  config  rating ← 实时语音通话（新增）
/api/v0/asr/ws                                   ← 语音识别 WebSocket
/api/v0/file/upload_file  fetch_files  fork_file_task
/api/v0/index/prepare  index/query               ← RAG / 文件索引
/api/v0/share/create  content  fork  list  delete
/api/v0/telemetry  client/span  client/settings  check_client_update  ip_to_country_code
/api/v0/users/auth_token/check_device
```

---

## 3. Guest PoW（DeepSeekHashV1）

### 3.1 流程

```
POST /api/v0/users/create_guest_challenge   {"target_path": "<白名单路径>"}
   ↓  200 {"guest_challenge":{algorithm,challenge,salt,signature,difficulty,expire_at,expire_after,target_path}}
本地求解 nonce ∈ [0, difficulty)
   ↓
POST <target_path>   header  X-DS-Guest-Pow-Response: base64({"salt":"<salt>","answer":<nonce>})
```

header 值构造（`p000/nfb.java:13356` → `p000/dk0.java:6368a`）：
`salt` 走字符串序列化器、`answer` 走 long 序列化器，序列化成 JSON 后 **Base64**。
紧凑 JSON（无空格）与带空格均可，实测两者都通过。

### 3.2 服务端白名单与难度（实测，随端点变化）

| target_path | allowed | difficulty |
|---|---|---|
| `/api/v0/users/register` | ✅ | 160000 |
| `/api/v0/users/register_by_mobile` | ✅ | 160000 |
| `/api/v0/users/login_by_mobile_sms` | ✅ | 80000 |
| `/api/v0/users/oauth/google/login` | ✅ | 80000 |
| `/api/v0/users/create_sms_verification_code` | ✅ | 20 |
| `/api/v0/users/create_email_verification_code` | ✅ | 20 |
| `/api/v0/users/oauth/google/authorize` | ✅ | 20 |
| `/api/v0/users/mfa/create_verification_code` | ✅ | 20 |
| `/api/v0/users/login` | ❌ INVALID_TARGET_PATH | — |
| `/api/v0/chat/completion` | ❌ INVALID_TARGET_PATH | — |

客户端硬编码白名单在 `p000/hp3.java`（7 条）。服务端比客户端多接受 `oauth/google/authorize` 与 `mfa/create_verification_code`，并且**不再接受 `login`**（v1.2.6 时代 login 在白名单内，v2.7.1 已收紧）。

### 3.3 算法（100% 还原）

`Java_com_deepseek_crypto_PowCalculator_nativeCalculateDeepSeekHashV1Pow(base, challenge, difficulty) → long`
实现在 `lib/arm64-v8a/librscrypto.so`。等价实现三份：`lib/ds_pow.py`（参考实现）、`lib/ds_pow_fast.py`（numpy）、`lib/ds_pow.c`（native，~1.27M hash/s 单线程）；求解器 `lib/ds_pow_solve.py` 优先用 native、自动回退 numpy，并按 8 段并行。：

| 参数 | 值 |
|---|---|
| 置换 | Keccak-f[1600]，**只跑 23 轮**（轮常数 `RC[1..23]`，跳过 `RC[0]=0x1`） |
| rate | 136 字节（17 lanes） |
| 填充 | `0x06` + 末字节 `|= 0x80` |
| 输入 | `f"{salt}_{expire_at}_{nonce}"` |
| 输出 | state lanes[0..3] 小端拼接 32 字节 |
| 判定 | `digest == bytes.fromhex(challenge)`（逐字节相等） |
| 搜索空间 | `nonce ∈ [0, difficulty)` |

**这不是标准 SHA3-256**：只差一轮轮常数，但哈希值完全不同。标准 SHA3 实现会永远搜不到。验证方式：同一份置换改成 24 轮即等于 `hashlib.sha3_256`（`lib/verify_perm.py`，三条测试向量全过）。

同一 challenge 的答案恒定（`expire_after=300000ms` 内复用），可以缓存。

---

## 4. 鉴权 PoW（v2.7.1 新机制）

登录后聊天也要 PoW：

```
POST /api/v0/chat/create_pow_challenge   {"target_path":"/api/v0/chat/completion"}
   → data.challenge = ServerChatChallenge{algorithm,challenge,salt,signature,difficulty,expire_at,expire_after,target_path}
求解（同一算法）
POST /api/v0/chat/completion   header  X-DS-PoW-Response: base64({"salt","answer"})
```

需要 PoW 的鉴权路径（`p000/jp3.java`）：`/api/v0/chat/completion`、`edit_message`、`regenerate`、`continue`、`/api/v0/call/start`。
无关机凭证时该端点返回 `40002 Missing Token`（已验证）。

`X-DS-Challenge-Response` 是另一套（hCaptcha / 数美），与 PoW 无关。

---

## 5. 请求 DTO（kotlinx serializer 逐字段还原）

### UsersLoginWithEmailAndPwdRequest
```json
{"email":"…","password":"…","device_id":"…"}          // os 字段客户端默认 "android"，服务端接受
```

### RegisterByEmailRequest
```json
{"region":"…","locale":"…","os":"android","device_id":"…",
 "payload":{"email":"…","email_verification_code":"…","password":"…"}}
```

### ChatFullCompletionRequest（10 字段）
```json
{"chat_session_id":"…","parent_message_id":"…","prompt":"…","preempt":false,
 "ref_file_ids":["…"], "thinking_enabled":true, "search_enabled":true,
 "audio_id":"…","model_type":"default|expert|vision","action":"…"}
```
必填：`chat_session_id`、`parent_message_id`、`prompt`、`preempt`。

### 其他
- `GuestChallengeRequest {target_path}`
- `ChatChallengeRequest {target_path}`
- `ChallengeResponse {provider, challenge_id, shumei_verification{rid,region}, shumei_device_id, hcaptcha_token}`
- `ChatSessionCreateBizData {chat_session{id,title,version,…}, ttl_seconds}`
- SSE 事件：`ready` / `update_session` / `update_parent_message` / `title` / `toast` / `close` / `auto_tts_capability` / `check_client_update`

---

## 6. 可行性判定

| 能力 | 状态 | 证据 |
|---|---|---|
| PoW 求解 | ✅ 100% 打通 | 求解后提交，错误从 `40300 Missing Header` 变为 `40302 PAYLOAD_SCHEMA_MISMATCH`（说明 header 被解析接受） |
| 邮箱密码登录 | ✅ 直通，无 PoW 无人机验证 | `{"biz_msg":"PASSWORD_OR_USER_NAME_IS_WRONG"}` 到达业务层 |
| 注册（邮箱/手机） | ❌ 卡人机验证 | PoW 通过后 `RECAPTCHA_VERIFY_FAILED`，需 hCaptcha / 数美真机 token |
| 短信验证码 | ❌ 同上 | 同 |
| 聊天 | ⚠️ 协议已还原，缺真实账号验证 | `40002 Missing Token`；DTO/PoW/SSE 均已静态还原并接线 |

**结论：唯一现实入口是「已有账号 → `/api/v0/users/login` → token」。** 账号注册链路被 hCaptcha/数美彻底封死，不是 PoW 能解决的。
