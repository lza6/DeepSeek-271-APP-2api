# new-api 对接指南

本文档给负责对接的会话/同学使用。目标：把本地 DeepSeek 网关（`demo_server.py`）作为一个 OpenAI 兼容上游挂进 new-api。

> **先读这一段，别跳。**
> 聊天主链路**没有用真账号端到端验证过**（样本来源方不愿提供账号）。已验证的是：
> ① PoW 全链路被服务端接受；② 鉴权头格式被上游正确识别（假 token 返回 `INVALID_TOKEN`，而不是 `40002 Missing Token`）；
> ③ DTO / SSE / 会话创建按反编译结果接线。
> 也就是说：**代码路径是对的，但没跑通过一次真实补全**。所以请按下文「第 5 步 自测」逐项确认后再上生产渠道。

---

## 0. 你需要先准备什么

| 物料 | 说明 |
|---|---|
| 一个 DeepSeek 账号 | 邮箱 + 密码即可。注册通道被人机验证封死，只能自己有号 |
| Python 3.10+ | 网关运行环境 |
| 网关的出口网络 | 必须能访问 `chat.deepseek.com`；TLS 指纹由 `curl_cffi` 处理，无需额外配置 |

### 0.1 把账号换成 token（关键一步）

DeepSeek App/网页的 token 是 `x-auth-token`，**不是** `Authorization: Bearer`。获取方式二选一：

**方式 A：用网关自带的登录接口换（推荐，不用抓包）**

```bash
curl -X POST http://127.0.0.1:8933/api/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"you@example.com","password":"your-password"}'
# → {"ok":true,"token":"<x-auth-token>","user":"you@example.com"}
```

或直接用 Python：

```python
import sys; sys.path.insert(0, ".")
import client as dsc
s = dsc.make_session()
s.login("you@example.com", "your-password")
print(s.token)
```

**方式 B：从已登录的 App 抓包**

抓 `chat.deepseek.com` 任意请求的 `x-auth-token` 头，复制值。
（注意：token 会过期，App 每次启动可能轮换，长期跑建议用方式 A 定时刷新。）

> ⚠️ 不要把 token 写进仓库、日志或渠道备注。new-api 的密钥字段会存库，请自行评估。

---

## 1. 启动网关

```bash
cd DeepSeek-271-APP-2api
pip install -r requirements.txt      # curl_cffi numpy fastapi uvicorn
python demo_server.py                # 监听 127.0.0.1:8933
```

生产环境建议监听内网全地址并加进程守护：

```bash
python -m uvicorn demo_server:app --host 0.0.0.0 --port 8933 --workers 1
```

> `--workers 1` 是刻意选的：网关内部维护每 token 一个 session（cookie + 设备指纹 + PoW 缓存），多进程会让同一 token 的会话分裂，反而更容易触发风控。

自检：

```bash
curl http://127.0.0.1:8933/health
# → {"ok":true,"upstream_ok":true,"pow_engine":"c · DeepSeekHashV1 …"}
```

`upstream_ok` 必须是 `true`。为 `false` 说明网关连不上 `chat.deepseek.com`（查代理/DNS/出网策略），此时所有请求都会失败。

---

## 2. 网关暴露的接口

| 方法 | 路径 | 用途 |
|---|---|---|
| POST | `/v1/chat/completions` | **OpenAI 兼容，new-api 用这个** |
| GET | `/v1/models` | 返回 `deepseek-chat` / `deepseek-reasoner` |
| POST | `/api/login` | 账密换 token |
| POST | `/api/chat` | 原生 SSE 直通（调试用） |
| GET | `/api/pow/challenge` · POST `/api/pow/solve` | PoW 观测 |
| GET | `/health` · `/stats` | 健康与延迟统计 |

OpenAI 兼容端的鉴权：`Authorization: Bearer <x-auth-token>`。
（网关会把它转成上游需要的 `x-auth-token` 头，并自动完成建会话 + 取 authed PoW + 解 PoW。）

---

## 3. new-api 渠道配置

新增渠道，按下表填：

| 字段 | 值 |
|---|---|
| 类型 | **OpenAI**（不要选 "DeepSeek" 原生类型——那个打的是 `api.deepseek.com`，不是我们这条链） |
| 名称 | `DeepSeek-App-2API`（随意） |
| 代理地址 / Base URL | `http://<网关内网IP>:8933` （若 new-api 与网关同机：`http://127.0.0.1:8933`） |
| 密钥 | 第 0.1 步拿到的 `x-auth-token`**（一个渠道 = 一个 DeepSeek 账号）** |
| 模型 | `deepseek-chat,deepseek-reasoner` |
| 模型重定向 | `deepseek-chat→deepseek-chat`，`deepseek-reasoner→deepseek-reasoner`（不用重定向也可，网关按模型名自动选 `default` / `expert`） |
| 分组 | 按你的运营策略 |
| 流式 | 开启（网关支持 SSE） |

### 3.1 如果需要走代理池

网关侧不内置代理池，但支持在进程环境里挂全局代理（`curl_cffi` 会自动继承）：

```bash
export HTTPS_PROXY=http://127.0.0.1:10808
python demo_server.py
```

多账号分摊流量时，最省事的做法是**每个账号起一个网关实例（不同端口），new-api 里配成多个渠道**，让 new-api 自己做负载均衡与重试。不要试图在单进程里塞几十个账号——同 IP 同设备的并发特征很容易被风控。

---

## 4. 模型映射说明

| new-api 请求的 model | 网关行为 | 上游 `model_type` |
|---|---|---|
| 名字里含 `reason`（如 `deepseek-reasoner`） | 走推理模式 | `expert` |
| 其它（如 `deepseek-chat`） | 走普通对话 | `default` |

上游还有 `vision`（读图）可用，但网关目前**没有实现多模态入参转换**（`ref_file_ids` 需要先走 `/api/v0/file/upload_file`）。
需要图像能力时告诉我，这块要单独做。

---

## 5. 自测（上生产前必须逐条过）

### 5.1 网关直连

```bash
# 无鉴权应 401
curl -sS -o /dev/null -w '%{http_code}\n' -X POST http://127.0.0.1:8933/v1/chat/completions \
  -H 'Content-Type: application/json' -d '{"model":"deepseek-chat","messages":[{"role":"user","content":"hi"}]}'
# 期望：401

# 带真 token 应开始出字
curl -N -X POST http://127.0.0.1:8933/v1/chat/completions \
  -H 'Authorization: Bearer <x-auth-token>' -H 'Content-Type: application/json' \
  -d '{"model":"deepseek-chat","stream":true,"messages":[{"role":"user","content":"用一句话介绍你自己"}]}'
# 期望：一串 data: {"choices":[{"delta":{"content":"…"}}]}，最后一行为 data: [DONE]
```

**这一步跑不通就别往下走**，把返回体贴给我。

### 5.2 通过 new-api 打

```bash
curl -N http://<new-api>/v1/chat/completions \
  -H 'Authorization: Bearer sk-<你的 new-api 令牌>' -H 'Content-Type: application/json' \
  -d '{"model":"deepseek-chat","stream":true,"messages":[{"role":"user","content":"1+1=?"}]}'
```

同时打开 new-api 的渠道测试按钮，确认返回 200 且 `usage` 有值。

---

## 6. 已知限制与风险（务必读）

1. **额度与风控未知**：DeepSeek 免费账号的每日消息数、同 IP 多号、同设备多号阈值，都没实测。压测只覆盖了 `create_guest_challenge` 端点（c5-c20 封顶 47-52 qps，无 429），**不代表聊天接口的限额**。
2. **authed PoW 难度未知**：登录后每条消息前要取一次 PoW（网关已自动处理，本机 16-29 ms），但难度值要真账号才看得到。若上游把难度提到千万级，网关会有明显延迟。
3. **SSE 文本提取是宽松解析**：网关用 `_extract_text()` 尽力从 DeepSeek 的 patch 式事件里抽文本。真实事件结构没验证过，可能出现「流正常结束但内容是空的」。若发生，把原始 SSE 贴给我，我按真实结构改解析器。
4. **单账号单 session**：网关按 token 复用 curl_cffi session（cookie + 设备 id）。同一 token 被多路并发时，行为靠上游，未压测。
5. **不要把网关裸奔到公网**：它没有鉴权层（只把 `Authorization` 原样当上游 token 用），也没有限流。必须只监听内网/本机，前面挂 new-api。

---

## 7. 排错对照表

| 现象 | 原因 | 处理 |
|---|---|---|
| `/health` 的 `upstream_ok=false` | 网关出不了网 / DNS / 被 WAF 挡 | 配 `HTTPS_PROXY`；确认能 `curl https://chat.deepseek.com` |
| `401 missing token` | 没传 `Authorization: Bearer` | 检查 new-api 渠道密钥是否为空 |
| `502 {"biz_msg":"INVALID_TOKEN"}` | token 错/过期 | 重新走 0.1 拿 token |
| `502 {"biz_msg":"Missing Token"}`（40002） | 网关没把 token 转成 `x-auth-token` | 这是网关 bug，报我 |
| `502 {"biz_code":…,"biz_msg":"RECAPTCHA_VERIFY_FAILED"}` | 你触发的是注册/验证码路径，不是聊天 | 与聊天无关 |
| 请求 20 s 才开始出字 | 上游排队或 PoW 难度升高 | 看 `/stats` 里的 `pow_seconds` |
| 内容为空但流结束 | SSE 解析没命中真实字段 | 贴原始 SSE 给我 |

---

## 8. 一句话总结

网关是 `http://<内网IP>:8933`，new-api 里按 **OpenAI 类型**建渠道、密钥填 **DeepSeek 的 `x-auth-token`**、模型填 `deepseek-chat,deepseek-reasoner`。
单账号单渠道，账号靠 `/api/login` 换 token，先跑通 5.1 再谈生产。
