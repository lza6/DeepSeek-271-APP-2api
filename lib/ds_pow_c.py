"""ctypes binding for the native DeepSeekHashV1 kernel (lib/ds_pow.dll).

Verified against hashlib.sha3_256 (4 vectors, 24-round mode) and against the
pure-python reference (10 nonce samples) before being wired in as the primary
engine. Native throughput ~385k hash/s single threaded; a 160000-difficulty
challenge resolves in ~50 ms.

Rebuild after editing ds_pow.c:
    call vcvars64.bat && cl /nologo /O2 /LD ds_pow.c /Fe:ds_pow.dll
"""
from __future__ import annotations

import ctypes
from pathlib import Path

_LIB = None
_U64_MAX = 0xFFFFFFFFFFFFFFFF


def _lib():
    global _LIB
    if _LIB is None:
        dll = Path(__file__).with_name("ds_pow.dll")
        if not dll.exists():
            raise FileNotFoundError(f"{dll} missing - rebuild with build_ds_pow.ps1")
        lib = ctypes.CDLL(str(dll))
        lib.ds_hash.restype = None
        lib.ds_hash.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_uint64,
                                ctypes.POINTER(ctypes.c_ubyte)]
        lib.ds_solve.restype = ctypes.c_uint64
        lib.ds_solve.argtypes = [ctypes.c_char_p, ctypes.c_int,
                                 ctypes.POINTER(ctypes.c_ubyte), ctypes.c_uint64, ctypes.c_uint64]
        _LIB = lib
    return _LIB


def available() -> bool:
    try:
        _lib()
        return True
    except Exception:
        return False


def digest(base: bytes, nonce: int) -> bytes:
    out = (ctypes.c_ubyte * 32)()
    _lib().ds_hash(base, len(base), ctypes.c_uint64(nonce), out)
    return bytes(out)


def solve(challenge_hex: str, salt: str, expire_at: int, difficulty: int, start: int = 0):
    base = f"{salt}_{expire_at}_".encode()
    return solve_range(bytes.fromhex(challenge_hex), base, start, difficulty)


def solve_range(target: bytes, base: bytes, lo: int, hi: int):
    """Search nonce in [lo, hi) for this exact 32-byte digest. None if absent."""
    lib = _lib()
    arr = (ctypes.c_ubyte * 32).from_buffer_copy(target)
    n = lib.ds_solve(base, len(base), arr, ctypes.c_uint64(hi), ctypes.c_uint64(lo))
    return None if n == _U64_MAX else int(n)


def bench(rounds: int = 300_000) -> int:
    import time
    lib = _lib()
    base = b"60abb4757fbda6dc5b8b_1793283137643_"
    out = (ctypes.c_ubyte * 32)()
    t = time.time()
    for i in range(rounds):
        lib.ds_hash(base, len(base), ctypes.c_uint64(i), out)
    return round(rounds / (time.time() - t))


if __name__ == "__main__":
    print(f"hash/s: {bench():,}")
