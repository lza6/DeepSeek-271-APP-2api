/* stage-by-stage debug of one Keccak round, mirrors ds_pow.c logic exactly */
#include <stdint.h>
#include <string.h>
#define EXPORT __declspec(dllexport)

static const uint64_t RC[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL, 0x8000000080008000ULL,
    0x000000000000808bULL, 0x0000000080000001ULL, 0x8000000080008081ULL, 0x8000000000008009ULL,
    0x000000000000008aULL, 0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL, 0x8000000000008003ULL,
    0x8000000000008002ULL, 0x8000000000000080ULL, 0x000000000000800aULL, 0x800000008000000aULL,
    0x8000000080008081ULL, 0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL,
};
static const int ROT[5][5] = {
    {0, 36, 3, 41, 18}, {1, 44, 10, 45, 2}, {62, 6, 43, 15, 61},
    {28, 55, 25, 21, 56}, {27, 20, 39, 8, 14},
};
static uint64_t rotl64(uint64_t v, int r) { return r ? ((v << r) | (v >> (64 - r))) : v; }

EXPORT void stage_theta(uint64_t *st) {
    uint64_t C[5], D[5]; int x, y;
    for (x = 0; x < 5; x++) C[x] = st[x] ^ st[x+5] ^ st[x+10] ^ st[x+15] ^ st[x+20];
    for (x = 0; x < 5; x++) D[x] = C[(x+4)%5] ^ rotl64(C[(x+1)%5], 1);
    for (x = 0; x < 5; x++) for (y = 0; y < 5; y++) st[x+5*y] ^= D[x];
}
EXPORT void stage_rhopi(uint64_t *st, uint64_t *Bout) {
    uint64_t B[25]; int x, y;
    for (x = 0; x < 5; x++) for (y = 0; y < 5; y++)
        B[y + 5*((2*x + 3*y) % 5)] = rotl64(st[x+5*y], ROT[x][y]);
    memcpy(Bout, B, sizeof(B)); memcpy(st, B, sizeof(B));
}
EXPORT void stage_chi_iota(uint64_t *st, int rnd) {
    uint64_t B[25]; int x, y;
    memcpy(B, st, sizeof(B));
    for (x = 0; x < 5; x++) for (y = 0; y < 5; y++)
        st[x+5*y] = B[x+5*y] ^ ((~B[(x+1)%5 + 5*y]) & B[(x+2)%5 + 5*y]);
    st[0] ^= RC[rnd];
}
