"""DeepSeek APK v2.7.1 reverse-engineering demo server.

    python demo_server.py            # http://127.0.0.1:8933

Endpoints
    GET  /health                     service + upstream warm-up status
    GET  /stats                      request counters / latency histogram
    GET  /api/pow/challenge          fetch a guest PoW challenge (raw upstream pass-through)
    POST /api/pow/solve              solve DeepSeekHashV1 and return the header value
    GET  /api/pow/whitelist          guest PoW target_path whitelist probe
    POST /api/login                  email/password login (real upstream, no PoW needed)
    POST /api/chat                   SSE proxy -> /api/v0/chat/completion (needs token)
    POST /v1/chat/completions        OpenAI-compatible shim over the same path
    GET  /demo.html                  browser demo page

Nothing here talks to a paid API. The only credentials used are a DeepSeek
account you supply at call time; nothing is persisted.
"""
from __future__ import annotations

import asyncio
import json
import time
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from pydantic import BaseModel, Field

import client as dsc
from lib import ds_pow_solve

ROOT = Path(__file__).parent
START = time.time()

# ---------------------------------------------------------------- statistics
STATS: dict[str, Any] = {
    "requests": 0,
    "errors": 0,
    "pow_solved": 0,
    "pow_seconds": [],
    "upstream_ms": [],
    "by_path": {},
}


def _bump(path: str, ok: bool, ms: float) -> None:
    STATS["requests"] += 1
    STATS["by_path"][path] = STATS["by_path"].get(path, 0) + 1
    if not ok:
        STATS["errors"] += 1
    STATS["upstream_ms"].append(ms)
    for key in ("upstream_ms", "pow_seconds"):
        if len(STATS[key]) > 5000:
            del STATS[key][:-2000]


def _pct(vals: list[float], p: float) -> float:
    if not vals:
        return 0.0
    s = sorted(vals)
    return s[min(len(s) - 1, int(len(s) * p))]


# session pool: one device identity per token, keyed by token suffix
_SESSIONS: dict[str, dsc.Session] = {}
_LOCK = asyncio.Lock()
_upstream_ok: bool | None = None


async def _get_session(token: str | None = None) -> dsc.Session:
    key = (token or "anon")[-12:]
    async with _LOCK:
        s = _SESSIONS.get(key)
        if s is None:
            s = await asyncio.to_thread(dsc.make_session)
            if token:
                s.token = token
            _SESSIONS[key] = s
        return s


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _upstream_ok
    try:
        await asyncio.to_thread(dsc.make_session)
        _upstream_ok = True
    except Exception as e:  # upstream blocked / offline: still serve the page
        _upstream_ok = False
        print(f"[warn] upstream warm-up failed: {e}")
    print(f"[demo] listening on http://127.0.0.1:8933  (upstream_ok={_upstream_ok})")
    yield


app = FastAPI(title="DeepSeek APK v2.7.1 RE demo", lifespan=lifespan)


class SolveReq(BaseModel):
    challenge: str
    salt: str
    expire_at: int
    difficulty: int
    batch: int = Field(default=16384, ge=1024, le=131072)


class LoginReq(BaseModel):
    email: str
    password: str


class ChatReq(BaseModel):
    token: str
    prompt: str
    chat_session_id: str | None = None
    parent_message_id: str = "0"
    thinking_enabled: bool = False
    search_enabled: bool = False
    model_type: str | None = None


class OAIReq(BaseModel):
    model: str = "deepseek-chat"
    messages: list[dict]
    stream: bool = True
    token: str | None = None


# ---------------------------------------------------------------------- infra
@app.get("/health")
async def health():
    return {
        "ok": True,
        "upstream_ok": _upstream_ok,
        "uptime_s": round(time.time() - START, 1),
        "pow_engine": f"{ds_pow_solve.engine_name()} · DeepSeekHashV1 (23-round keccak-f1600)",
        "sessions": len(_SESSIONS),
    }


@app.get("/stats")
async def stats():
    ms = STATS["upstream_ms"]
    pw = STATS["pow_seconds"]
    return {
        **{k: v for k, v in STATS.items() if k not in ("upstream_ms", "pow_seconds")},
        "latency_ms": {
            "count": len(ms),
            "p50": round(_pct(ms, 0.50), 1),
            "p90": round(_pct(ms, 0.90), 1),
            "p99": round(_pct(ms, 0.99), 1),
            "max": round(max(ms), 1) if ms else 0,
        },
        "pow_seconds": {
            "count": len(pw),
            "mean": round(sum(pw) / len(pw), 2) if pw else 0,
            "p90": round(_pct(pw, 0.90), 2),
            "max": round(max(pw), 2) if pw else 0,
        },
    }


# ------------------------------------------------------------------- pow api
@app.get("/api/pow/challenge")
async def pow_challenge(target_path: str = "/api/v0/users/register"):
    s = await _get_session()
    t = time.time()
    try:
        ch = await asyncio.to_thread(s.guest_challenge, target_path)
    except dsc.DeepSeekError as e:
        _bump("pow/challenge", False, (time.time() - t) * 1000)
        raise HTTPException(502, detail={"biz_code": e.biz_code, "biz_msg": e.biz_msg,
                                         "hint": "target_path not in server whitelist"})
    _bump("pow/challenge", True, (time.time() - t) * 1000)
    return {"ok": True, "challenge": ch.__dict__, "fetch_ms": round((time.time() - t) * 1000, 1)}


@app.post("/api/pow/solve")
async def pow_solve(req: SolveReq):
    t = time.time()
    nonce = await asyncio.to_thread(
        ds_pow_solve.solve, req.challenge, req.salt, req.expire_at, req.difficulty, batch=req.batch)
    el = time.time() - t
    if nonce is None:
        _bump("pow/solve", False, 0)
        raise HTTPException(422, detail="nonce not found in [0, difficulty)")
    STATS["pow_solved"] += 1
    STATS["pow_seconds"].append(el)
    _bump("pow/solve", True, 0)
    raw = json.dumps({"salt": req.salt, "answer": nonce}, separators=(",", ":")).encode()
    import base64
    return {
        "ok": True,
        "nonce": nonce,
        "seconds": round(el, 3),
        "header_name": "X-DS-Guest-Pow-Response",
        "header_value": base64.b64encode(raw).decode(),
    }


@app.get("/api/pow/whitelist")
async def pow_whitelist():
    s = await _get_session()
    probes = [
        "/api/v0/users/register",
        "/api/v0/users/register_by_mobile",
        "/api/v0/users/login_by_mobile_sms",
        "/api/v0/users/create_sms_verification_code",
        "/api/v0/users/create_email_verification_code",
        "/api/v0/users/oauth/google/authorize",
        "/api/v0/users/oauth/google/login",
        "/api/v0/users/mfa/create_verification_code",
        "/api/v0/users/login",
        "/api/v0/chat/completion",
    ]

    def run():
        out = {}
        for p in probes:
            try:
                ch = s.guest_challenge(p)
                out[p] = {"allowed": True, "difficulty": ch.difficulty}
            except dsc.DeepSeekError as e:
                out[p] = {"allowed": False, "biz_msg": e.biz_msg}
        return out

    return {"ok": True, "client_whitelist": list(dsc.GUEST_POW_PATHS), "server": await asyncio.to_thread(run)}


# ----------------------------------------------------------------- auth/chat
@app.post("/api/login")
async def login(req: LoginReq):
    s = await _get_session()
    t = time.time()
    try:
        data = await asyncio.to_thread(s.login, req.email, req.password)
    except dsc.DeepSeekError as e:
        _bump("login", False, (time.time() - t) * 1000)
        raise HTTPException(401, detail={"biz_code": e.biz_code, "biz_msg": e.biz_msg})
    _bump("login", True, (time.time() - t) * 1000)
    _SESSIONS[s.token[-12:]] = s
    return {"ok": True, "token": s.token, "user": data.get("user", {}).get("email") or "?"}


@app.post("/api/chat")
async def chat(req: ChatReq):
    s = await _get_session(req.token)
    s.token = req.token
    sid = req.chat_session_id
    try:
        if not sid:
            sid = await asyncio.to_thread(s.create_session)
        gen = await asyncio.to_thread(
            s.completion, req.prompt, sid, req.parent_message_id,
            req.thinking_enabled, req.search_enabled, req.model_type)

        async def relay():
            yield f"event: meta\ndata: {json.dumps({'chat_session_id': sid})}\n\n".encode()
            loop = asyncio.get_running_loop()
            it = iter(gen)
            while True:
                chunk = await loop.run_in_executor(None, lambda: next(it, None))
                if chunk is None:
                    break
                yield chunk
            yield b"event: done\ndata: {}\n\n"

        return StreamingResponse(relay(), media_type="text/event-stream")
    except dsc.DeepSeekError as e:
        raise HTTPException(502, detail={"biz_code": e.biz_code, "biz_msg": e.biz_msg})


@app.get("/v1/models")
async def list_models():
    """Model list for new-api / any OpenAI client to probe the channel."""
    now = int(time.time())
    return {"object": "list", "data": [
        {"id": "deepseek-chat", "object": "model", "created": now, "owned_by": "deepseek"},
        {"id": "deepseek-reasoner", "object": "model", "created": now, "owned_by": "deepseek"},
    ]}


@app.post("/v1/chat/completions")
async def openai_shim(req: OAIReq, authorization: str | None = Header(default=None)):
    """OpenAI-compatible bridge so new-api can point at this process.

    Auth: `Authorization: Bearer <deepseek x-auth-token>` (standard clients) or
    the legacy `token` body field. One DeepSeek account token per channel key.
    """
    token = (req.token or "").strip()
    if not token and authorization:
        token = authorization.removeprefix("Bearer ").strip()
    if not token:
        raise HTTPException(401, detail="missing token: send 'Authorization: Bearer <x-auth-token>'")
    prompt = "\n".join(f"{m.get('role')}: {m.get('content')}" for m in req.messages)
    s = await _get_session(token)
    s.token = token
    try:
        sid = await asyncio.to_thread(s.create_session)
        gen = await asyncio.to_thread(s.completion, prompt, sid, "0", False, False,
                                     "expert" if "reason" in req.model else "default")
    except dsc.DeepSeekError as e:
        raise HTTPException(502, detail={"biz_code": e.biz_code, "biz_msg": e.biz_msg})

    cid = "chatcmpl-" + uuid.uuid4().hex[:24]
    created = int(time.time())

    async def relay():
        loop = asyncio.get_running_loop()
        it = iter(gen)
        while True:
            chunk = await loop.run_in_executor(None, lambda: next(it, None))
            if chunk is None:
                break
            for line in chunk.split(b"\n"):
                if not line.startswith(b"data:"):
                    continue
                payload = line[5:].strip()
                if payload in (b"", b"[DONE]"):
                    continue
                try:
                    ev = json.loads(payload)
                except Exception:
                    continue
                text = _extract_text(ev)
                if not text:
                    continue
                if req.stream:
                    yield ("data: " + json.dumps({
                        "id": cid, "object": "chat.completion.chunk", "created": created,
                        "model": req.model,
                        "choices": [{"index": 0, "delta": {"content": text}, "finish_reason": None}],
                    }, ensure_ascii=False) + "\n\n").encode()
                else:
                    yield text.encode()
        if req.stream:
            yield ("data: " + json.dumps({
                "id": cid, "object": "chat.completion.chunk", "created": created, "model": req.model,
                "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]}) + "\n\n").encode()
            yield b"data: [DONE]\n\n"

    if req.stream:
        return StreamingResponse(relay(), media_type="text/event-stream")
    body = b"".join([c async for c in relay()]).decode(errors="ignore")
    return {"id": cid, "object": "chat.completion", "created": created, "model": req.model,
            "choices": [{"index": 0, "message": {"role": "assistant", "content": body},
                         "finish_reason": "stop"}]}


def _extract_text(ev: dict) -> str:
    """Best-effort text extraction from DeepSeek SSE patches (v / p+o format)."""
    if not isinstance(ev, dict):
        return ""
    for key in ("v", "content", "text"):
        v = ev.get(key)
        if isinstance(v, str) and v:
            return v
        if isinstance(v, dict):
            for k2 in ("response", "content", "text", "v"):
                v2 = v.get(k2)
                if isinstance(v2, str) and v2:
                    return v2
    return ""


# ------------------------------------------------------------------- web page
@app.get("/", response_class=HTMLResponse)
@app.get("/demo.html", response_class=HTMLResponse)
async def demo_page():
    return (ROOT / "demo.html").read_text(encoding="utf-8")


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8933, log_level="warning")
