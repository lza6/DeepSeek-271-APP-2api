"""Round-1 stress / latency benchmark for the DeepSeek v2.7.1 protocol surface.

    python benchmark.py                # full run, writes benchmark_results.json
    python benchmark.py --quick        # small sample, ~30s

Every request targets the live upstream (chat.deepseek.com). No mock.
"""
from __future__ import annotations

import argparse
import json
import statistics
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import client as dsc
from lib import ds_pow_solve

RESULTS: dict = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S"), "sections": {}}


def _stats(vals: list[float]) -> dict:
    if not vals:
        return {}
    s = sorted(vals)
    return {
        "n": len(s),
        "mean": round(statistics.fmean(s), 2),
        "p50": round(s[int(len(s) * 0.50)], 2),
        "p90": round(s[min(len(s) - 1, int(len(s) * 0.90))], 2),
        "p99": round(s[min(len(s) - 1, int(len(s) * 0.99))], 2),
        "max": round(s[-1], 2),
    }


def section(name: str):
    def deco(fn):
        def run(*a, **kw):
            print(f"\n=== {name} ===")
            t = time.time()
            try:
                out = fn(*a, **kw)
            except Exception as e:
                out = {"error": f"{type(e).__name__}: {e}"}
                print(f"  !! {out['error']}")
            out = out or {}
            out["elapsed_s"] = round(time.time() - t, 1)
            RESULTS["sections"][name] = out
            return out
        return run
    return deco


@section("1. warm-up + latency of challenge fetch")
def bench_challenge(n: int):
    s = dsc.make_session()
    lat, errs = [], 0
    for i in range(n):
        t = time.time()
        try:
            ch = s.guest_challenge("/api/v0/users/register")
            lat.append((time.time() - t) * 1000)
            print(f"  #{i+1} {lat[-1]:.0f}ms difficulty={ch.difficulty}", end="\r")
        except Exception as e:
            errs += 1
            print(f"  #{i+1} ERR {e}")
    print()
    return {"latency_ms": _stats(lat), "errors": errs, "difficulty_sample": ch.difficulty}


@section("2. PoW solve throughput (local CPU engine)")
def bench_pow(n: int):
    s = dsc.make_session()
    ch = s.guest_challenge("/api/v0/users/register")
    times, nonces = [], []
    for _ in range(n):
        nonce, sec = s.solve(ch)
        times.append(sec)
        nonces.append(nonce)
    bw = ds_pow_solve.bench()
    return {
        "engine": ds_pow_solve.engine_name(),
        "solve_seconds": _stats(times),
        "difficulty": ch.difficulty,
        "hash_rate_hash_per_s": bw["hash_per_s"],
        "bench_workers": bw["workers"],
        "samples_nonce": nonces[:8],
    }


@section("3. concurrent challenge fetch (WAF behaviour under load)")
def bench_concurrency(levels: list[int], per_level: int):
    out = {}
    for c in levels:
        s = dsc.make_session()
        lat, codes = [], {}

        def one(_):
            t = time.time()
            try:
                s2 = dsc.Session(device_id=s.device_id)
                s2._s = s._s
                s2._warm = True
                s2.guest_challenge("/api/v0/users/register")
                return (time.time() - t) * 1000, "ok"
            except dsc.DeepSeekError as e:
                return (time.time() - t) * 1000, f"biz:{e.biz_msg}"
            except Exception as e:
                return (time.time() - t) * 1000, f"exc:{type(e).__name__}"

        t0 = time.time()
        with ThreadPoolExecutor(max_workers=c) as ex:
            res = list(ex.map(one, range(per_level)))
        wall = time.time() - t0
        for ms, code in res:
            lat.append(ms)
            codes[code] = codes.get(code, 0) + 1
        out[f"c{c}"] = {
            "requests": per_level,
            "wall_s": round(wall, 2),
            "qps": round(per_level / wall, 2),
            "latency_ms": _stats(lat),
            "outcomes": codes,
        }
        print(f"  c{c}: {per_level} req in {wall:.1f}s → {per_level/wall:.2f} qps  {codes}")
    return out


@section("4. auth surface reachability (no credential used)")
def bench_auth_surface():
    s = dsc.make_session()
    out = {}

    # login with a bogus account: proves the endpoint is reachable without PoW
    t = time.time()
    try:
        s.api("POST", "/api/v0/users/login",
              {"email": "probe@invalid.example", "password": "x" * 12, "device_id": s.device_id, "os": "android"})
        out["login"] = {"reachable": True, "unexpected": "accepted"}
    except dsc.DeepSeekError as e:
        out["login"] = {"reachable": True, "biz_msg": e.biz_msg, "ms": round((time.time() - t) * 1000, 1)}
    print(f"  login ⇢ {out['login']}")

    # chat/completion without token
    t = time.time()
    r = s.call("POST", "/api/v0/chat/completion", {"chat_session_id": "x", "parent_message_id": "0",
                                                  "prompt": "hi", "preempt": False})
    out["chat_completion_no_token"] = {"status": r.status_code, "body": r.text[:120],
                                       "ms": round((time.time() - t) * 1000, 1)}
    print(f"  completion(no token) ⇢ {out['chat_completion_no_token']}")

    # authed pow endpoint without token
    t = time.time()
    r = s.call("POST", "/api/v0/chat/create_pow_challenge", {"target_path": "/api/v0/chat/completion"})
    out["create_pow_challenge_no_token"] = {"status": r.status_code, "body": r.text[:120],
                                            "ms": round((time.time() - t) * 1000, 1)}
    print(f"  create_pow_challenge(no token) ⇢ {out['create_pow_challenge_no_token']}")
    return out


@section("5. registration channel = PoW pass but captcha wall")
def bench_register_wall():
    s = dsc.make_session()
    tp = "/api/v0/users/create_email_verification_code"
    ch = s.guest_challenge(tp)
    nonce, sec = s.solve(ch)
    hdr = {"X-DS-Guest-Pow-Response": s.pow_header_value(ch, nonce)}
    t = time.time()
    r = s.call("POST", tp, {"email": f"probe{int(time.time())%100000}@example.com",
                            "device_id": s.device_id, "scenario": "register"}, hdr)
    body = r.json()
    out = {
        "pow_solve_s": round(sec, 2),
        "pow_accepted": body.get("code") != 40300 and body.get("code") != 40302,
        "status": r.status_code,
        "biz_msg": ((body.get("data") or {}).get("biz_msg")),
        "ms": round((time.time() - t) * 1000, 1),
    }
    print(f"  {out}")
    return out


@section("6. end-to-end guest PoW round trip")
def bench_e2e(n: int):
    """challenge → solve → submit, measuring each hop."""
    s = dsc.make_session()
    rows = []
    for i in range(n):
        t0 = time.time()
        ch = s.guest_challenge("/api/v0/users/register")
        t1 = time.time()
        nonce, _ = s.solve(ch)
        t2 = time.time()
        hdr = {"X-DS-Guest-Pow-Response": s.pow_header_value(ch, nonce)}
        r = s.call("POST", "/api/v0/users/register", {}, hdr)
        t3 = time.time()
        rows.append({
            "challenge_ms": round((t1 - t0) * 1000, 1),
            "solve_ms": round((t2 - t1) * 1000, 1),
            "submit_ms": round((t3 - t2) * 1000, 1),
            "total_ms": round((t3 - t0) * 1000, 1),
            "verdict": r.json().get("code"),
        })
        print(f"  #{i+1} {rows[-1]}")
    return {
        "rows": rows,
        "challenge_ms": _stats([r["challenge_ms"] for r in rows]),
        "solve_ms": _stats([r["solve_ms"] for r in rows]),
        "submit_ms": _stats([r["submit_ms"] for r in rows]),
        "total_ms": _stats([r["total_ms"] for r in rows]),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true")
    ap.add_argument("--out", default="benchmark_results.json")
    a = ap.parse_args()
    q = a.quick

    bench_challenge(10 if q else 30)
    bench_pow(3 if q else 8)
    bench_concurrency([1, 5, 10] if q else [1, 5, 10, 20], 10 if q else 20)
    bench_auth_surface()
    bench_register_wall()
    bench_e2e(3 if q else 6)

    Path(a.out).write_text(json.dumps(RESULTS, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\n=== summary ===")
    for k, v in RESULTS["sections"].items():
        brief = {kk: vv for kk, vv in v.items() if kk in
                 ("latency_ms", "errors", "solve_seconds", "hash_rate_hash_per_s", "biz_msg", "pow_accepted")}
        print(f"{k}\n   {json.dumps(brief, ensure_ascii=False)}")
    print(f"\nwritten -> {a.out}")


if __name__ == "__main__":
    main()
