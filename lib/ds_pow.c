/* DeepSeekHashV1 PoW search - native kernel.
 *
 * Java_com_deepseek_crypto_PowCalculator_nativeCalculateDeepSeekHashV1Pow
 * recovered from lib/arm64-v8a/librscrypto.so:
 *   23-round Keccak-f[1600] (RC[1..23], RC[0] skipped),
 *   rate 136 bytes, padding 0x06 ... 0x80,
 *   digest = state lanes[0..3] little-endian (32 bytes),
 *   payload = base followed by the decimal representation of the nonce.
 *
 * build: call vcvars64.bat && cl /nologo /O2 /LD ds_pow.c /Fe:ds_pow.dll
 */
#include <stdint.h>
#include <string.h>

#if defined(_MSC_VER)
#define EXPORT __declspec(dllexport)
#else
#define EXPORT __attribute__((visibility("default")))
#endif

static inline uint64_t rotl64(uint64_t v, int r)
{
    return r ? ((v << r) | (v >> (64 - r))) : v;
}

static const uint64_t RC[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL, 0x8000000080008000ULL,
    0x000000000000808bULL, 0x0000000080000001ULL, 0x8000000080008081ULL, 0x8000000000008009ULL,
    0x000000000000008aULL, 0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL, 0x8000000000008003ULL,
    0x8000000000008002ULL, 0x8000000000000080ULL, 0x000000000000800aULL, 0x800000008000000aULL,
    0x8000000080008081ULL, 0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL,
};

/* ROT[x][y] - standard Keccak rho offsets */
static const int ROT[5][5] = {
    {0, 36, 3, 41, 18},
    {1, 44, 10, 45, 2},
    {62, 6, 43, 15, 61},
    {28, 55, 25, 21, 56},
    {27, 20, 39, 8, 14},
};

static int u64_to_dec(uint64_t v, char *out)
{
    char tmp[24];
    int n = 0, i;
    if (v == 0) { out[0] = '0'; return 1; }
    while (v) { tmp[n++] = (char)('0' + (int)(v % 10)); v /= 10; }
    for (i = 0; i < n; i++) out[i] = tmp[n - 1 - i];
    return n;
}

/* one round of Keccak-f[1600] on a 5x5 lane state (lane index = x + 5*y) */
static void keccak_round(uint64_t st[25], int rnd)
{
    uint64_t C[5], D[5], B[25];
    int x, y;
    for (x = 0; x < 5; x++)
        C[x] = st[x] ^ st[x + 5] ^ st[x + 10] ^ st[x + 15] ^ st[x + 20];
    for (x = 0; x < 5; x++)
        D[x] = C[(x + 4) % 5] ^ rotl64(C[(x + 1) % 5], 1);
    for (x = 0; x < 5; x++)
        for (y = 0; y < 5; y++)
            st[x + 5 * y] ^= D[x];
    for (x = 0; x < 5; x++)
        for (y = 0; y < 5; y++)
            B[y + 5 * ((2 * x + 3 * y) % 5)] = rotl64(st[x + 5 * y], ROT[x][y]);
    for (x = 0; x < 5; x++)
        for (y = 0; y < 5; y++)
            st[x + 5 * y] = B[x + 5 * y] ^ ((~B[(x + 1) % 5 + 5 * y]) & B[(x + 2) % 5 + 5 * y]);
    st[0] ^= RC[rnd];
}

/* build the padded 136-byte block for base||dec(nonce) */
static void build_block(const char *base, int base_len, uint64_t nonce, char blk[136])
{
    int len;
    memset(blk, 0, 136);
    if (base_len > 0) memcpy(blk, base, (size_t)base_len);
    len = base_len + u64_to_dec(nonce, blk + base_len);
    blk[len] = 0x06;
    blk[135] = (char)(blk[135] | (char)0x80);
}

/* 23-round DeepSeekHashV1 over base||dec(nonce) */
EXPORT void ds_hash(const char *base, int base_len, uint64_t nonce, uint8_t *out)
{
    uint64_t st[25];
    char blk[136];
    int r;
    build_block(base, base_len, nonce, blk);
    memset(st, 0, sizeof(st));
    memcpy(st, blk, 136);
    for (r = 1; r < 24; r++) keccak_round(st, r);
    memcpy(out, st, 32);
}

/* search nonce in [start, difficulty); returns UINT64_MAX when exhausted */
EXPORT uint64_t ds_solve(const char *base, int base_len, const uint8_t *target,
                         uint64_t difficulty, uint64_t start)
{
    uint64_t n;
    uint8_t dig[32];
    for (n = start; n < difficulty; n++) {
        ds_hash(base, base_len, n, dig);
        if (memcmp(dig, target, 32) == 0)
            return n;
    }
    return ~0ULL;
}

/* ---- debug helpers (cross-validation only) ---- */
EXPORT void ds_blk_state(const char *base, int base_len, uint64_t nonce, uint64_t *out25, int permute)
{
    uint64_t st[25];
    char blk[136];
    int r;
    build_block(base, base_len, nonce, blk);
    memset(st, 0, sizeof(st));
    memcpy(st, blk, 136);
    if (permute) { for (r = 1; r < 24; r++) keccak_round(st, r); }
    memcpy(out25, st, sizeof(st));
}

/* full 24-round variant == SHA3-256 (permutation validation) */
EXPORT void ds_sha3(const char *base, int base_len, uint64_t nonce, uint8_t *out)
{
    uint64_t st[25];
    char blk[136];
    int r;
    build_block(base, base_len, nonce, blk);
    memset(st, 0, sizeof(st));
    memcpy(st, blk, 136);
    for (r = 0; r < 24; r++) keccak_round(st, r);
    memcpy(out, st, 32);
}

EXPORT void ds_perm_round(uint64_t *st, int rnd) { keccak_round(st, rnd); }
