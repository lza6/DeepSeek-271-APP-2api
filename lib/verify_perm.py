"""Validate both permutation impls against SHA3-256 (24 rounds, RC[0..23])."""
import hashlib, importlib
import numpy as np
import ds_pow, ds_pow_np

def ref_sha3(msg):
    st = [0]*25
    blk = bytearray(msg); blk.append(0x06)
    blk.extend(b"\x00"*(136-len(blk))); blk[-1] |= 0x80
    for i in range(0,136,8):
        st[i//8] ^= int.from_bytes(blk[i:i+8],'little')
    # full 24 rounds
    saved = ds_pow.ROUNDS
    ds_pow.ROUNDS = list(range(24))
    try:
        st = ds_pow.keccak_f1600_23(st)
    finally:
        ds_pow.ROUNDS = saved
    return b"".join(st[i].to_bytes(8,'little') for i in range(4))

def np_sha3(msg):
    saved = ds_pow_np.ROUNDS
    ds_pow_np.ROUNDS = range(24)
    try:
        A = np.zeros((5,5,1), dtype=np.uint64)
        blk = bytearray(msg); blk.append(0x06)
        blk.extend(b"\x00"*(136-len(blk))); blk[-1] |= 0x80
        for j in range(0,136,8):
            A[(j//8)%5][(j//8)//5][0] ^= np.uint64(int.from_bytes(blk[j:j+8],'little'))
        A = ds_pow_np.permute(A)
    finally:
        ds_pow_np.ROUNDS = saved
    return b"".join(int(A[k%5][k//5][0]).to_bytes(8,'little') for k in range(4))

for m in [b"", b"abc", b"a"*135]:
    exp = hashlib.sha3_256(m).hexdigest()
    r = ref_sha3(m).hex(); n = np_sha3(m).hex()
    print(f"len={len(m):3d} sha3={exp[:16]} ref={'OK ' if r==exp else 'FAIL '+r[:16]} np={'OK ' if n==exp else 'FAIL '+n[:16]}")
