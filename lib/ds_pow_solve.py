"""DeepSeekHashV1 solver — engine selection + segmented parallel search.

Primary engine : native C (lib/ds_pow.dll)  ~570k hash/s, verified against
                 hashlib.sha3_256 and the pure-python reference.
Fallback engine: numpy vectorised Keccak (lib/ds_pow_fast.py), used when the
                 DLL is missing (non-Windows / not built yet).

Both engines are segmented across threads: the C call releases the GIL and
numpy releases it for the bulk of the permutation, so N threads scanning
disjoint nonce ranges scale close to linearly.
"""
from __future__ import annotations

import os
import time
from concurrent.futures import ThreadPoolExecutor

DEFAULT_WORKERS = max(1, min(8, os.cpu_count() or 4))
_BATCH = 32768


def _engine():
    try:
        from . import ds_pow_c as c
        if c.available():
            return "c", c
    except Exception:
        pass
    try:
        from . import ds_pow_c as c
        if c.available():
            return "c", c
    except Exception:
        pass
    try:
        from . import ds_pow_fast as f
    except ImportError:
        import ds_pow_fast as f
    return "numpy", f


ENGINE, _E = _engine()


def engine_name() -> str:
    return ENGINE


def _segments(difficulty: int, workers: int) -> list[tuple[int, int]]:
    step = (difficulty + workers - 1) // workers
    return [(i * step, min((i + 1) * step, difficulty)) for i in range(workers)]


# ------------------------------------------------------------------ engines
def _scan_c(args):
    base, target, lo, hi = args
    return _E.solve_range(target, base, lo, hi)


def _scan_np(args):
    base, target, lo, hi = args
    import numpy as np
    tgt = np.frombuffer(target, dtype="<u8")
    cur = lo
    while cur < hi:
        nxt = min(cur + _BATCH, hi)
        d = _E.digests(base, cur, nxt)
        hit = ((d[:, 0] == tgt[0]) & (d[:, 1] == tgt[1]) &
               (d[:, 2] == tgt[2]) & (d[:, 3] == tgt[3])).nonzero()[0]
        if hit.size:
            return cur + int(hit[0])
        cur = nxt
    return None


def solve(challenge_hex: str, salt: str, expire_at: int, difficulty: int,
          workers: int = DEFAULT_WORKERS, batch: int = _BATCH, progress=None):
    """Return the nonce whose digest equals the challenge, or None."""
    global _BATCH
    workers = max(1, min(int(workers), 32))
    if batch != _BATCH:
        _BATCH = max(1024, min(int(batch), 262144))

    difficulty = int(difficulty)
    base = f"{salt}_{expire_at}_".encode()
    target = bytes.fromhex(challenge_hex)
    scan = _scan_c if ENGINE == "c" else _scan_np

    segs = _segments(difficulty, workers)
    if len(segs) == 1:
        return scan((base, target, *segs[0]))
    with ThreadPoolExecutor(max_workers=len(segs)) as ex:
        for res in ex.map(scan, [(base, target, lo, hi) for lo, hi in segs]):
            if res is not None:
                return res
    return None


def bench(workers: int = DEFAULT_WORKERS, hashes: int = 400_000) -> dict:
    """Throughput on a synthetic 160k-difficulty range (no hit expected)."""
    base = b"60abb4757fbda6dc5b8b_1793283137643_"
    target = bytes(range(32))
    segs = _segments(hashes, workers)
    scan = _scan_c if ENGINE == "c" else _scan_np
    t = time.time()
    with ThreadPoolExecutor(max_workers=len(segs)) as ex:
        list(ex.map(scan, [(base, target, lo, hi) for lo, hi in segs]))
    el = time.time() - t
    return {"engine": ENGINE, "workers": workers, "hashes": hashes,
            "seconds": round(el, 3), "hash_per_s": round(hashes / el)}


if __name__ == "__main__":
    print(bench(8))
    print(bench(1))
    t = time.time()
    n = solve("e4d05f8eaf31bea91fac6a8ec62eb7dcca9589467be1b9d12c6f1b83b27a5253",
              "cace58a80ae0889759d5", 1793283450015, 160000)
    print(f"known challenge -> nonce={n} (expect 109478) in {1000*(time.time()-t):.0f} ms")
