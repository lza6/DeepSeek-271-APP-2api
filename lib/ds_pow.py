"""DeepSeekHashV1 PoW solver (v2.7.x, com.deepseek.chat)

Reversed from lib/arm64-v8a/librscrypto.so
  Java_com_deepseek_crypto_PowCalculator_nativeCalculateDeepSeekHashV1Pow(base, challenge, difficulty) -> long

Algorithm (cross-verified in earlier session, re-validated here against live server):
  - digest function = Keccak-f[1600] permutation with 23 rounds (RC[1..23], RC[0]=0x1 skipped)
  - rate = 136 bytes, padding = 0x06 ... 0x80
  - digest = lanes[0..3] little-endian (32 bytes)
  - payload = f"{base}_{nonce}"  where base = f"{salt}_{expire_at}"
  - search nonce in [0, difficulty) for digest == bytes.fromhex(challenge)
"""
MASK = (1 << 64) - 1

RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]
ROT = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
]
# precomputed (src_lane, rot) -> dst_lane for rho+pi
_RPI = []
for _x in range(5):
    for _y in range(5):
        _RPI.append((_x + 5 * _y, ROT[_x][_y], _y + 5 * ((2 * _x + 3 * _y) % 5)))
_RPI = tuple(_RPI)

ROUNDS = list(range(1, 24))  # 23 rounds, skip RC[0]


def keccak_f1600_23(state):
    A = list(state)
    for rnd in ROUNDS:
        # theta
        c0 = A[0] ^ A[5] ^ A[10] ^ A[15] ^ A[20]
        c1 = A[1] ^ A[6] ^ A[11] ^ A[16] ^ A[21]
        c2 = A[2] ^ A[7] ^ A[12] ^ A[17] ^ A[22]
        c3 = A[3] ^ A[8] ^ A[13] ^ A[18] ^ A[23]
        c4 = A[4] ^ A[9] ^ A[14] ^ A[19] ^ A[24]
        d0 = c4 ^ (((c1 << 1) | (c1 >> 63)) & MASK)
        d1 = c0 ^ (((c2 << 1) | (c2 >> 63)) & MASK)
        d2 = c1 ^ (((c3 << 1) | (c3 >> 63)) & MASK)
        d3 = c2 ^ (((c4 << 1) | (c4 >> 63)) & MASK)
        d4 = c3 ^ (((c0 << 1) | (c0 >> 63)) & MASK)
        for x in range(5):
            dx = (d0, d1, d2, d3, d4)[x]
            for y in range(0, 25, 5):
                A[x + y] ^= dx
        # rho + pi
        B = [0] * 25
        for src, r, dst in _RPI:
            v = A[src]
            B[dst] = ((v << r) | (v >> (64 - r))) & MASK if r else v
        # chi
        for y in range(0, 25, 5):
            b0, b1, b2, b3, b4 = B[y], B[y + 1], B[y + 2], B[y + 3], B[y + 4]
            A[y] = b0 ^ ((~b1) & b2) & MASK
            A[y + 1] = b1 ^ ((~b2) & b3) & MASK
            A[y + 2] = b2 ^ ((~b3) & b4) & MASK
            A[y + 3] = b3 ^ ((~b4) & b0) & MASK
            A[y + 4] = b4 ^ ((~b0) & b1) & MASK
        # iota
        A[0] ^= RC[rnd]
    return A


RATE = 136


def dshash(msg: bytes) -> bytes:
    """DeepSeekHashV1 digest of an arbitrary short (<=135 byte) message."""
    assert len(msg) < RATE
    blk = bytearray(msg)
    blk.append(0x06)
    blk.extend(b"\x00" * (RATE - 1 - len(blk) + 1 - 0) if False else b"")
    blk.extend(b"\x00" * (RATE - len(blk)))
    blk[-1] |= 0x80
    st = [0] * 25
    for i in range(0, RATE, 8):
        st[i // 8] ^= int.from_bytes(blk[i:i + 8], "little")
    st = keccak_f1600_23(st)
    return b"".join(st[i].to_bytes(8, "little") for i in range(4))


def solve(challenge_hex: str, salt: str, expire_at: int, difficulty: int, progress=None):
    target = bytes.fromhex(challenge_hex)
    base = f"{salt}_{expire_at}_"
    bb = base.encode()
    for nonce in range(max(1, difficulty)):
        if dshash(bb + str(nonce).encode()) == target:
            return nonce
        if progress and nonce % 50000 == 0:
            progress(nonce)
    return None


if __name__ == "__main__":
    import time, sys
    # 1) sanity: digest length + determinism
    d1 = dshash(b"hello")
    d2 = dshash(b"hello")
    print("digest:", d1.hex(), "det:", d1 == d2, "len:", len(d1))
    # 2) speed
    t = time.time()
    N = 3000
    for i in range(N):
        dshash(b"60abb4757fbda6dc5b8b_1793283137643_" + str(i).encode())
    el = time.time() - t
    print(f"speed: {N} hashes in {el:.2f}s = {el/N*1e6:.1f} us/hash")
