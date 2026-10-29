"""Vectorised DeepSeekHashV1 (23-round Keccak-f1600) — batch nonce search."""
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
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
], dtype=np.uint64)
RATE = 136
ROUNDS = range(1, 24)


def _rotl(v, r):
    if r == 0:
        return v
    return (v << np.uint64(r)) | (v >> np.uint64(64 - r))


def permute(A):
    """A: (5,5,B) uint64 -> permuted (5,5,B)."""
    A = A.copy()
    for rnd in ROUNDS:
        C = A[:, 0] ^ A[:, 1] ^ A[:, 2] ^ A[:, 3] ^ A[:, 4]   # C[x] = XOR_y A[x][y], (5,B)
        D = np.empty_like(C)
        for x in range(5):
            D[x] = C[(x - 1) % 5] ^ _rotl(C[(x + 1) % 5], 1)
        A ^= D[:, None, :]
        B = np.empty_like(A)
        for x in range(5):
            for y in range(5):
                B[y][(2 * x + 3 * y) % 5] = _rotl(A[x][y], int(ROT[x][y]))
        for x in range(5):
            A[x] = B[x] ^ (~B[(x + 1) % 5] & B[(x + 2) % 5])
        A[0][0] ^= RC[rnd]
    return A


def hash_batch(msgs):
    """msgs: list[bytes] (<136 B) -> list[32B digest]"""
    n = len(msgs)
    A = np.zeros((5, 5, n), dtype=np.uint64)
    for i, m in enumerate(msgs):
        blk = bytearray(m)
        blk.append(0x06)
        blk.extend(b"\x00" * (RATE - len(blk)))
        blk[-1] |= 0x80
        for j in range(0, RATE, 8):
            A[(j // 8) % 5][(j // 8) // 5][i] ^= np.uint64(int.from_bytes(blk[j:j + 8], "little"))
    A = permute(A)
    out = []
    for i in range(n):
        out.append(b"".join(int(A[k % 5][k // 5][i]).to_bytes(8, "little") for k in range(4)))
    return out


def solve(challenge_hex, salt, expire_at, difficulty, batch=4096, progress=None):
    target = bytes.fromhex(challenge_hex)
    base = f"{salt}_{expire_at}_".encode()
    lo = 0
    while lo < difficulty:
        hi = min(lo + batch, difficulty)
        idx = list(range(lo, hi))
        digs = hash_batch([base + str(i).encode() for i in idx])
        for i, d in zip(idx, digs):
            if d == target:
                return i
        lo = hi
        if progress:
            progress(lo, difficulty)
    return None


if __name__ == "__main__":
    import time
    t = time.time()
    res = hash_batch([b"60abb4757fbda6dc5b8b_1793283137643_" + str(i).encode() for i in range(4096)])
    el = time.time() - t
    print(f"4096 hashes in {el*1000:.0f}ms = {el/4096*1e6:.2f} us/hash")
    print("sample:", res[7].hex())
    # cross-check against reference impl
    import ds_pow
    for i in (0, 7, 100):
        ref = ds_pow.dshash(b"60abb4757fbda6dc5b8b_1793283137643_" + str(i).encode())
        assert ref == res[i], (i, ref.hex(), res[i].hex())
    print("cross-check OK")
