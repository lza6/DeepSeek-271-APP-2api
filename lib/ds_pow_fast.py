"""Fast DeepSeekHashV1 search.

The bottleneck in the naive version is Python-side message construction
(16384 `bytes` objects per batch), not the permutation. Here the whole batch
is built as one uint8 matrix inside numpy, so the permutation dominates.
"""
from __future__ import annotations

import numpy as np

RC = np.array([
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
], dtype=np.uint64)
ROT = np.array([
    [0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56], [27, 20, 39, 8, 14],
], dtype=np.uint64)
RATE = 136

# rho+pi map: lane src -> (dst lane, rotation)
_RPI = tuple((x + 5 * y, int(ROT[x][y]), y + 5 * ((2 * x + 3 * y) % 5))
             for x in range(5) for y in range(5))


def _rotl(v, r):
    return v if r == 0 else (v << np.uint64(r)) | (v >> np.uint64(64 - r))


def permute(A):
    """A: (5,5,B) uint64, 23 rounds (RC[1..23])."""
    A = A.copy()
    for rnd in range(1, 24):
        C = A[:, 0] ^ A[:, 1] ^ A[:, 2] ^ A[:, 3] ^ A[:, 4]
        D = np.empty_like(C)
        for x in range(5):
            D[x] = C[(x - 1) % 5] ^ _rotl(C[(x + 1) % 5], 1)
        A ^= D[:, None, :]
        B = np.empty_like(A)
        for src, r, dst in _RPI:
            B[dst % 5, dst // 5] = _rotl(A[src % 5, src // 5], r)
        for x in range(5):
            A[x] = B[x] ^ (~B[(x + 1) % 5] & B[(x + 2) % 5])
        A[0, 0] ^= RC[rnd]
    return A


def _blocks(base: bytes, lo: int, hi: int) -> np.ndarray:
    """Build (n,136) uint8 padded blocks for payloads base+str(lo..hi)."""
    n = hi - lo
    buf = np.zeros((n, RATE), dtype=np.uint8)
    bl = len(base)
    base_arr = np.frombuffer(base, dtype=np.uint8)
    buf[:, :bl] = base_arr
    vals = np.arange(lo, hi, dtype=np.uint64)
    digits = np.ones(n, dtype=np.int64)
    for d in range(2, 7):
        digits += (vals >= 10 ** (d - 1)).astype(np.int64)
    for d in range(1, 7):
        m = digits == d
        if not m.any():
            continue
        v = vals[m]
        cols = np.arange(bl, bl + d)
        buf[np.ix_(np.nonzero(m)[0], cols)] = (
            48 + (v[:, None] // (10 ** (d - 1 - np.arange(d, dtype=np.uint64))[None, :])) % 10
        ).astype(np.uint8)
    rows = np.arange(n)
    buf[rows, bl + digits] = 0x06
    buf[:, RATE - 1] |= 0x80
    return buf


def digests(base: bytes, lo: int, hi: int) -> np.ndarray:
    """Return (n,4) uint64 little-endian digest words for nonces [lo,hi)."""
    buf = _blocks(base, lo, hi)
    lanes = buf.view("<u8").reshape(len(buf), 17)
    A = np.zeros((5, 5, len(buf)), dtype=np.uint64)
    for k in range(17):
        A[k % 5, k // 5] = lanes[:, k]
    A = permute(A)
    return np.stack([A[k % 5, k // 5] for k in range(4)], axis=1)


def solve(challenge_hex: str, salt: str, expire_at: int, difficulty: int,
          batch: int = 65536, progress=None):
    target = np.frombuffer(bytes.fromhex(challenge_hex), dtype="<u8")
    base = f"{salt}_{expire_at}_".encode()
    lo = 0
    while lo < difficulty:
        hi = min(lo + batch, difficulty)
        d = digests(base, lo, hi)
        hit = np.nonzero((d == target[None, :]).all(axis=1))[0]
        if hit.size:
            return int(lo + hit[0])
        lo = hi
        if progress:
            progress(lo, difficulty)
    return None


if __name__ == "__main__":
    import time
    import ds_pow_np
    base = b"60abb4757fbda6dc5b8b_1793283137643_"
    t = time.time()
    d = digests(base, 0, 200000)
    el = time.time() - t
    print(f"200k hashes in {el:.3f}s = {200000/el:,.0f} hash/s")
    # correctness vs reference impl
    import ds_pow
    for i in (0, 1, 9, 10, 99, 100, 1000, 99999, 123456):
        ref = ds_pow.dshash(base + str(i).encode())
        got = b"".join(int(x).to_bytes(8, "little") for x in d[i])
        assert ref == got, (i, ref.hex(), got.hex())
    print("cross-check vs pure-python reference: OK (9 samples)")
