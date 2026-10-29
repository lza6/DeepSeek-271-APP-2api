# DeepSeek Android v2.7.1 逆向 · 协议还原 + OpenAI 兼容网关 + 压测

APK `DeepSeek_v2.7.1_(288)_Mod.apk`（`md5 f90bf9c83805394b36f8cc2b9106e1c8`）
包名 `com.deepseek.chat` · vc288 · arm64-v8a · 上游 `chat.deepseek.com`

> 仅供安全研究与互操作性学习。不包含、也不提供任何绕过付费或未授权访问的手段；
> 使用前请自备合法账号，并遵守上游服务条款。

**一句话结论**：PoW 侧 100% 打通（native 内核 16-29 ms 解 160000 难度），
注册侧被 hCaptcha/数美彻底封死，**唯一现实入口是「已有账号 → 账密登录 → token」**。

| 想做什么 | 看哪里 |
|---|---|
| 把这个网关接进 new-api | **[`docs/NEW-API-HANDOFF.md`](docs/NEW-API-HANDOFF.md)** |
| 搞懂协议细节（端点/PoW/DTO/错误码） | [`docs/PROTOCOL.md`](docs/PROTOCOL.md) |
| 想知道这个 Mod 版被改了什么 | [`docs/MOD-ANALYSIS.md`](docs/MOD-ANALYSIS.md) |
| 只想跑一下看效果 | `python demo_server.py` → http://127.0.0.1:8933 |

## 仓库结构

```
client.py            协议客户端（warm-up / guest&authed PoW / 登录 / 建会话 / SSE）
demo_server.py       FastAPI 网关 :8933（OpenAI 兼容 /v1 + 原生 SSE + PoW 观测 + /stats）
demo.html            单文件演示页（真实浏览器验证过，见 screenshots/）
benchmark.py         6 组压测场景 → benchmark_results.json
browser_test.py      Playwright 真实浏览器验证
build_ds_pow.ps1     一键重编译 native 内核并自检
requirements.txt     运行依赖

lib/                 DeepSeekHashV1 三份实现 + 求解器
  ds_pow.py            纯 Python 参考实现（SHA3-256 交叉校验）
  ds_pow_fast.py       numpy 向量化
  ds_pow.c + ds_pow.dll native 内核（主引擎，~1.27M hash/s 单线程）
  ds_pow_c.py          ctypes 绑定
  ds_pow_solve.py      引擎选择 + 8 路分段并行
  verify_perm.py       置换正确性验证
  dbg_round.c          单轮分阶段调试内核（定位算法 bug 用）

docs/                PROTOCOL.md · MOD-ANALYSIS.md · NEW-API-HANDOFF.md · signer-cert.der
probe/               黑盒探测脚本（白名单枚举 / PoW 探测 / 字符串提取），可复现全部结论
screenshots/         demo 页真实浏览器截图
```

`app.apk` / `unzip/` / `jadx_out/` 属于可复现的中间产物，未入库。

---

## 一句话结论

**PoW 侧 100% 打通，注册侧彻底封死，唯一现实入口是「已有账号 → 账密登录 → token」。**
`/api/v0/users/login` 不需要 PoW、不需要人机验证，只要一对真实的邮箱+密码即可换 token（已验证到达业务层）。
注册 / 邮箱验证码 / 短信验证码全部卡在 hCaptcha/数美（`RECAPTCHA_VERIFY_FAILED`），PoW 只是它们的第一道廉价门（difficulty 仅 20）。

---

## 快速开始

```bash
pip install -r requirements.txt
python demo_server.py                           # → http://127.0.0.1:8933
python benchmark.py --quick                     # 压测（约 1 分钟）
python benchmark.py                             # 完整压测（约 5 分钟）
powershell -File build_ds_pow.ps1               # 需要时重编译 native 内核（会自检）
```

```python
import client as dsc
s = dsc.make_session()                                  # warm-up + cookie
ch = s.guest_challenge("/api/v0/users/register")        # difficulty=160000
nonce, sec = s.solve(ch)                                # 16-29 ms（native 内核）
hdr = s.pow_header_value(ch, nonce)                     # base64({"salt","answer"})
s.call("POST", "/api/v0/users/register", {}, {"X-DS-Guest-Pow-Response": hdr})

s.login("you@example.com", "password")                  # 无需 PoW，唯一可用入口
sid = s.create_session()
for chunk in s.completion("你好", sid): print(chunk)     # 需真账号
```

---

## 第一轮实测数据

环境：Windows 10 · 出口经本地代理（海外 IP）· 2026-10-29。
命令 `python benchmark.py`，原始数据 `benchmark_results.json`。

### 延迟

| 场景 | n | mean | p50 | p90 | p99 | 错误 |
|---|---|---|---|---|---|---|
| `create_guest_challenge`（含 HWWAF 会话复用） | 30 | 61.6 ms | 56.5 | 62.4 | 187.9 | 0 |
| `users/login`（错密码，验证可达性） | 1 | 152.6 ms | — | — | — | 0 |

### 并发（同一 session 打 challenge 端点）

| 并发 | 请求 | 墙钟 | QPS | p50 | 结果 |
|---|---|---|---|---|---|
| c1 | 20 | 1.53 s | 13.1 | 65.1 ms | 20/20 ok |
| c5 | 20 | 0.39 s | 51.9 | 68.1 ms | 20/20 ok |
| c10 | 20 | 0.43 s | 47.0 | 160.8 ms | 20/20 ok |
| c20 | 20 | 0.39 s | 51.3 | 179.9 ms | 20/20 ok |

c5 之后吞吐封顶在 **47-52 qps**，p50 从 68 ms 抬到 180 ms，但**没有任何 429 或业务错误**——瓶颈在上游排队而非 WAF 限流。

### PoW 求解（difficulty 160000，即全量扫描上限）

| 引擎 | 吞吐 | 单次求解（平均路径） |
|---|---|---|
| 纯 Python 参考实现 | ≈3.3 k hash/s | ≈25 s |
| numpy 单线程 | 34.7 k hash/s | 2.5-5.6 s |
| numpy 8 路分段并行 | 139-201 k hash/s | 0.72-1.03 s |
| **native C 单线程（交付用）** | **1.27 M hash/s** | 0.32 s |
| **native C 8 路分段并行（交付用）** | **5.99 – 7.69 M hash/s** | **16 – 29 ms** |

端到端（challenge → solve → submit）：**143 – 210 ms**，其中 challenge 60-70 ms、submit 65-72 ms、solve 16-29 ms。
换句话说：**PoW 已经不再是瓶颈，网络往返占了 95% 的时间。**

### 关键验证链

1. **置换正确性**：C 与 Python 两套实现跑 24 轮都等于 `hashlib.sha3_256`（4 条向量，`lib/verify_perm.py` + `ds_pow_c` 自检）
2. **实现一致**：C 内核与纯 Python 参考实现对 10 个 nonce 逐字节相同
3. **算法正确性**：对同一 challenge 独立求解得到同一 nonce（109478），digest 逐字节等于 challenge
4. **服务端接受度**：带 `X-DS-Guest-Pow-Response` 提交 register，错误码从 `40300 Missing Header` → `40302 PAYLOAD_SCHEMA_MISMATCH`（PoW 校验已通过，只剩 body schema）
5. **注册墙**：补全 body 后返回 `RECAPTCHA_VERIFY_FAILED`（biz_code=2）
6. **登录直通**：`{"email","password","device_id"}` 无 PoW 无头 → `PASSWORD_OR_USER_NAME_IS_WRONG`
7. **前端真实浏览器验证**：Playwright chromium 走完五个交互（PoW 求解 / 白名单探测 / 登录探针 / 无 token 聊天拦截），0 page error，截图见 `screenshots/`

> 调试记录：C 内核第一次跑出的哈希与参考实现不符，逐轮对比定位到第 11 轮 chi 阶段差 1 bit —— 根因是轮常数 `RC[11]` 抄写错误（`0x8000800a` 应为 `0x8000000a`），差值恰好是 0x8000。修正后三重校验全过。

---

## 相对 v1.2.6 的变化（历史对比）

| 项 | v1.2.6 | v2.7.1 |
|---|---|---|
| guest challenge 路径 | `/api/v0/create_guest_challenge` | `/api/v0/users/create_guest_challenge` |
| `login` 是否在 guest PoW 白名单 | 是 | **否**（`INVALID_TARGET_PATH`） |
| 聊天侧 PoW | 无 | **有**：`/api/v0/chat/create_pow_challenge` + `X-DS-PoW-Response` |
| difficulty | 80000–160000 | **按端点分级：20 / 80000 / 160000** |
| 新功能端点 | — | TTS、实时通话 `/api/v0/call/*`、ASR WebSocket、RAG 索引、分享体系、MFA |
| WAF | Python urllib 可过 | **必须浏览器 TLS 指纹**，urllib/requests 全 429 |

---

## 未验证项 / 剩余风险

- **聊天主链路没有真账号验证**：DTO、PoW、SSE 事件名全部静态还原并接线，但没有实际跑通过一次真实补全。`parent_message_id` 首条消息的正确取值（`"0"` 或空串）需真号确认。
- **authed PoW 的 difficulty 未知**：`create_pow_challenge` 需要 token 才能拿到 challenge，难度值待真号实测。若与 guest 同级（160000），每条消息 ≈1 s 额外开销，接网关前必须评估。
- **native C 内核已修通并通过三重校验**（SHA3-256 向量 / 参考实现比对 / 已知 challenge 复现），16-29 ms 解出 160000 难度。仅 Windows 需要预编译的 `lib/ds_pow.dll`；DLL 缺失时自动回退 numpy 引擎（0.7-1.0 s）。
- **账号池规模未知**：登录不需要 PoW 意味着可以用账号池轮换，但 DeepSeek 免费额度/风控阈值（同设备多号、同 IP 多号）没有实测数据。
- 上游对未授权的 `chat/completion` 直接 429 WAF 拦截（而不是返回 40002），说明该路径有独立的严格规则。

---

## 下一步（需决策）

1. **拿到一对真实 DeepSeek 账号**就能把聊天链路从「静态确认」升级为「已验证」，同时测出 authed PoW 的真实 difficulty 和免费额度。在此之前 README 与 PROTOCOL 里相关条目一律标「待验证」。
2. PoW 已压到 16-29 ms，**即使每条消息都要求 PoW 也不再是硬伤**（对比网络往返占 95%），native 内核这关已经过了。
3. 接 new-api 渠道（`/v1/chat/completions` shim 已写好），建议等第 1 条验证通过再上生产。
