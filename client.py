"""DeepSeek Android (com.deepseek.chat v2.7.1 / vc288) protocol client.

Reverse engineered from the official APK; no server-side secret is required.
Transport notes learned from live probing (2026-10-29):

  * chat.deepseek.com sits behind Huawei HWWAF. A plain urllib/requests TLS
    fingerprint is answered with 429 "Request Blocked". A browser-like TLS
    fingerprint (curl_cffi impersonate="chrome") passes and the warm-up
    ``GET /`` hands out HWWAFSESID / HWWAFSESTIME / ds_session_id cookies.
  * Rate limiting / geo rules still apply: keep one session per device id.

Auth model:
  * ``x-auth-token: <token>`` (custom header, **not** Bearer)
  * ``x-client-version: 2.7.1`` is hard coded client side (p000/x06.java:74)
  * ``/api/v0/users/login`` needs no PoW and no captcha - only a real
    email/password pair. Everything else on the auth surface is gated.
"""
from __future__ import annotations

import base64
import json
import os
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Iterator

from curl_cffi import requests as creq

from lib import ds_pow_solve

BASE = "https://chat.deepseek.com"
CLIENT_VERSION = "2.7.1"
BUNDLE_ID = "com.deepseek.chat"

# Paths the client sends guest PoW for (p000/hp3.java: whitelist HashSet)
GUEST_POW_PATHS = (
    "/api/v0/users/register",
    "/api/v0/users/register_by_mobile",
    "/api/v0/users/login_by_mobile_sms",
    "/api/v0/users/oauth/google/login",
    "/api/v0/users/create_sms_verification_code",
    "/api/v0/users/create_email_verification_code",
    "/api/v0/users/mfa/create_verification_code",
)

# Paths that require an *authenticated* PoW challenge (p000/jp3.java)
AUTHED_POW_PATHS = (
    "/api/v0/chat/completion",
    "/api/v0/chat/edit_message",
    "/api/v0/chat/regenerate",
    "/api/v0/chat/continue",
    "/api/v0/call/start",
)


class DeepSeekError(RuntimeError):
    """Raised when the upstream envelope reports a business error."""

    def __init__(self, code: int, biz_code: int | None, biz_msg: str | None, payload: Any):
        self.code = code
        self.biz_code = biz_code
        self.biz_msg = biz_msg
        self.payload = payload
        super().__init__(f"code={code} biz_code={biz_code} biz_msg={biz_msg}")


@dataclass
class Challenge:
    algorithm: str
    challenge: str
    salt: str
    signature: str
    difficulty: int
    expire_at: int
    expire_after: int = 0
    target_path: str | None = None

    @classmethod
    def from_dict(cls, d: dict) -> "Challenge":
        return cls(
            algorithm=d["algorithm"],
            challenge=d["challenge"],
            salt=d["salt"],
            signature=d.get("signature", ""),
            difficulty=int(d["difficulty"]),
            expire_at=int(d["expire_at"]),
            expire_after=int(d.get("expire_after", 0)),
            target_path=d.get("target_path"),
        )


@dataclass
class Session:
    """One device identity + cookie jar + cached token."""

    device_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    token: str | None = None
    proxy: str | None = None
    _s: Any = None
    _pw_lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def __post_init__(self):
        self._s = creq.Session(impersonate="chrome", proxy=self.proxy or None)
        self._warm = False

    # ------------------------------------------------------------------ http
    def _headers(self, extra: dict | None = None) -> dict:
        h = {
            "x-client-platform": "android",
            "x-client-version": CLIENT_VERSION,
            "x-client-locale": "zh_CN",
            "x-client-bundle-id": BUNDLE_ID,
            "x-client-timezone-offset": "28800",
            "x-device-id": self.device_id,
            "Accept": "*/*",
            "Content-Type": "application/json",
        }
        if self.token:
            h["x-auth-token"] = self.token
        if extra:
            h.update(extra)
        return h

    def warmup(self) -> None:
        r = self._s.get(BASE + "/", headers={"Accept": "text/html"}, timeout=20)
        if r.status_code != 200:
            raise DeepSeekError(r.status_code, None, "warmup blocked by WAF", r.text[:200])
        self._warm = True

    def call(
        self,
        method: str,
        path: str,
        body: dict | None = None,
        extra_headers: dict | None = None,
        timeout: int = 30,
        stream: bool = False,
    ):
        if not self._warm:
            self.warmup()
        fn = self._s.get if method == "GET" else self._s.post
        kw = dict(headers=self._headers(extra_headers), timeout=timeout)
        if body is not None:
            kw["json"] = body
        if stream:
            kw["stream"] = True
        return fn(BASE + path, **kw)

    # ---------------------------------------------------------- envelope api
    def api(self, method: str, path: str, body: dict | None = None, extra_headers: dict | None = None,
            timeout: int = 30) -> dict:
        r = self.call(method, path, body, extra_headers, timeout)
        try:
            j = r.json()
        except Exception:
            raise DeepSeekError(r.status_code, None, "non-json response", r.text[:400])
        if j.get("code") != 0:
            raise DeepSeekError(j.get("code", -1), None, j.get("msg"), j)
        data = j.get("data") or {}
        if data.get("biz_code") != 0:
            raise DeepSeekError(0, data.get("biz_code"), data.get("biz_msg"), data)
        return data.get("biz_data") or {}

    # ------------------------------------------------------------- guest pow
    def guest_challenge(self, target_path: str) -> Challenge:
        data = self.api("POST", "/api/v0/users/create_guest_challenge", {"target_path": target_path})
        return Challenge.from_dict(data["guest_challenge"])

    @staticmethod
    def solve(ch: Challenge, batch: int = 16384) -> tuple[int, float]:
        """Run the DeepSeekHashV1 search. Returns (nonce, seconds)."""
        t = time.time()
        nonce = ds_pow_solve.solve(ch.challenge, ch.salt, ch.expire_at, ch.difficulty, batch=batch)
        if nonce is None:
            raise DeepSeekError(0, None, "PoW search exhausted (algorithm/prefix mismatch?)", ch)
        return nonce, time.time() - t

    @staticmethod
    def pow_header_value(ch: Challenge, nonce: int) -> str:
        """p000/nfb.m13356c builds {"salt":..,"answer":..}, dk0.m6368a base64-encodes it."""
        raw = json.dumps({"salt": ch.salt, "answer": nonce}, separators=(",", ":")).encode()
        return base64.b64encode(raw).decode()

    def guest_pow(self, path: str) -> dict:
        ch = self.guest_challenge(path)
        nonce, _ = self.solve(ch)
        return {"X-DS-Guest-Pow-Response": self.pow_header_value(ch, nonce)}

    # ------------------------------------------------------------------- auth
    def login(self, email: str, password: str) -> dict:
        """POST /api/v0/users/login - no PoW, no captcha. Returns biz_data."""
        data = self.api("POST", "/api/v0/users/login",
                        {"email": email, "password": password, "device_id": self.device_id, "os": "android"})
        user = data.get("user") or {}
        tok = user.get("token") or data.get("token")
        if not tok:
            raise DeepSeekError(0, None, f"login ok but no token in payload: {list(data)}", data)
        self.token = tok
        return data

    def current_user(self) -> dict:
        data = self.api("GET", "/api/v0/users/current")
        return data.get("user", data)

    # ------------------------------------------------------------ authed pow
    def chat_challenge(self, target_path: str = "/api/v0/chat/completion") -> Challenge:
        data = self.api("POST", "/api/v0/chat/create_pow_challenge", {"target_path": target_path})
        return Challenge.from_dict(data["challenge"])

    def authed_pow(self, target_path: str) -> dict:
        ch = self.chat_challenge(target_path)
        nonce, _ = self.solve(ch)
        return {"X-DS-PoW-Response": self.pow_header_value(ch, nonce)}

    # ------------------------------------------------------------------- chat
    def create_session(self) -> str:
        data = self.api("POST", "/api/v0/chat_session/create", {})
        sess = data.get("chat_session") or {}
        sid = sess.get("id")
        if not sid:
            raise DeepSeekError(0, None, f"no chat_session.id in {data}", data)
        return sid

    def completion(
        self,
        prompt: str,
        chat_session_id: str,
        parent_message_id: str = "0",
        thinking_enabled: bool = False,
        search_enabled: bool = False,
        model_type: str | None = None,
        ref_file_ids: list[str] | None = None,
        preempt: bool = False,
    ) -> Iterator[bytes]:
        """Stream the raw SSE body of /api/v0/chat/completion.

        Body shape = ChatFullCompletionRequest (10 fields, see docs/PROTOCOL.md).
        The PoW challenge is fetched per request; the header carries
        ``X-DS-PoW-Response: base64({"salt","answer"})``.
        """
        body: dict[str, Any] = {
            "chat_session_id": chat_session_id,
            "parent_message_id": parent_message_id,
            "prompt": prompt,
            "preempt": preempt,
        }
        if thinking_enabled:
            body["thinking_enabled"] = True
        if search_enabled:
            body["search_enabled"] = True
        if model_type:
            body["model_type"] = model_type
        if ref_file_ids:
            body["ref_file_ids"] = ref_file_ids

        pow_h = self.authed_pow("/api/v0/chat/completion")
        r = self.call("POST", "/api/v0/chat/completion", body, extra_headers={
            **pow_h, "Accept": "text/event-stream", "x-ds-sse-heartbeat-timeout-secs": "60",
        }, timeout=300, stream=True)
        if r.status_code != 200:
            raise DeepSeekError(r.status_code, None, "completion rejected", r.text[:400])
        return r.iter_content(chunk_size=None)


def make_session(proxy: str | None = None, device_id: str | None = None) -> Session:
    """Convenience factory. Proxy format: http://user:pass@host:port"""
    s = Session(device_id=device_id or os.environ.get("DS_DEVICE_ID") or str(uuid.uuid4()), proxy=proxy)
    s.warmup()
    return s
