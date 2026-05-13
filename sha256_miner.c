/* rpow2-miner native core - Dedicated single-block SHA-256 miner
 * Eliminates all OpenSSL overhead for single-block (≤55 byte) messages.
 * Compile: gcc -O3 -march=native -shared -fPIC -o libminer.so sha256_miner.c
 */
#include <stdint.h>
#include <string.h>

/* Rotate right */
#define ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

/* SHA-256 sigma functions */
#define SIG0(x) (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define SIG1(x) (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define ssig0(x) (ROTR(x, 7) ^ ROTR(x, 18) ^ ((x) >> 3))
#define ssig1(x) (ROTR(x, 17) ^ ROTR(x, 19) ^ ((x) >> 10))

/* SHA-256 round constants */
static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

/* SHA-256 initial hash values */
static const uint32_t H0[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
};

/* Count leading zero bits from MSB side of a 256-bit hash */
static inline int count_lzb(const uint8_t hash[32]) {
    for (int i = 0; i < 32; i++) {
        uint8_t b = hash[i];
        if (b == 0) continue;
        int c = 7;
        while (!(b & (1 << c))) c--;
        return i * 8 + (7 - c);
    }
    return 256;
}

/* Single-block SHA-256: hash exactly one 64-byte padded block.
 * Input 'in' must be 64 bytes (padded message).
 * Output 'out' is 32 bytes (digest). */
static inline void sha256_single_block(const uint8_t in[64], uint8_t out[32]) {
    uint32_t W[64];
    uint32_t state[8];
    uint32_t a, b, c, d, e, f, g, h, T1, T2;

    /* Copy state */
    memcpy(state, H0, sizeof(state));

    /* Message schedule */
    for (int t = 0; t < 16; t++) {
        W[t] = ((uint32_t)in[t*4] << 24) |
               ((uint32_t)in[t*4+1] << 16) |
               ((uint32_t)in[t*4+2] << 8)  |
               ((uint32_t)in[t*4+3]);
    }
    for (int t = 16; t < 64; t++) {
        W[t] = ssig1(W[t-2]) + W[t-7] + ssig0(W[t-15]) + W[t-16];
    }

    /* Compression rounds - fully unrolled via macros */
    a = state[0]; b = state[1]; c = state[2]; d = state[3];
    e = state[4]; f = state[5]; g = state[6]; h = state[7];

    #define ROUND(t) \
        T1 = h + (ROTR(e, 6) ^ ROTR(e, 11) ^ ROTR(e, 25)) + ((e & f) ^ (~e & g)) + K[t] + W[t]; \
        T2 = (ROTR(a, 2) ^ ROTR(a, 13) ^ ROTR(a, 22)) + ((a & b) ^ (a & c) ^ (b & c)); \
        h = g; g = f; f = e; e = d + T1; d = c; c = b; b = a; a = T1 + T2;

    ROUND(0)  ROUND(1)  ROUND(2)  ROUND(3)  ROUND(4)  ROUND(5)  ROUND(6)  ROUND(7)
    ROUND(8)  ROUND(9)  ROUND(10) ROUND(11) ROUND(12) ROUND(13) ROUND(14) ROUND(15)
    ROUND(16) ROUND(17) ROUND(18) ROUND(19) ROUND(20) ROUND(21) ROUND(22) ROUND(23)
    ROUND(24) ROUND(25) ROUND(26) ROUND(27) ROUND(28) ROUND(29) ROUND(30) ROUND(31)
    ROUND(32) ROUND(33) ROUND(34) ROUND(35) ROUND(36) ROUND(37) ROUND(38) ROUND(39)
    ROUND(40) ROUND(41) ROUND(42) ROUND(43) ROUND(44) ROUND(45) ROUND(46) ROUND(47)
    ROUND(48) ROUND(49) ROUND(50) ROUND(51) ROUND(52) ROUND(53) ROUND(54) ROUND(55)
    ROUND(56) ROUND(57) ROUND(58) ROUND(59) ROUND(60) ROUND(61) ROUND(62) ROUND(63)

    #undef ROUND

    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;

    /* Output as big-endian bytes */
    for (int t = 0; t < 8; t++) {
        out[t*4]   = (uint8_t)(state[t] >> 24);
        out[t*4+1] = (uint8_t)(state[t] >> 16);
        out[t*4+2] = (uint8_t)(state[t] >> 8);
        out[t*4+3] = (uint8_t)(state[t]);
    }
}

int mine_worker(
    const uint8_t *prefix, size_t prefix_len,
    int difficulty_bits,
    uint64_t start_nonce, uint64_t step,
    volatile int *stop_flag,
    uint64_t *found_nonce,
    volatile uint64_t *hash_count)
{
    /* Build the full 64-byte padded block template.
     * Input = prefix (16 bytes) + nonce (8 bytes) = 24 bytes
     * SHA-256 padding: 0x80, zeros up to byte 55, big-endian length at bytes 56-63 */
    uint8_t block[64];
    uint8_t hash[32];
    uint64_t nonce = start_nonce;
    uint64_t local = 0;

    /* Fill constant parts of the block */
    memset(block, 0, sizeof(block));
    memcpy(block, prefix, prefix_len);            /* prefix bytes */
    block[prefix_len + 8] = 0x80;                 /* padding start */
    /* Length in bits = (prefix_len + 8) * 8, big-endian at bytes 56-63 */
    uint64_t bitlen = (uint64_t)(prefix_len + 8) * 8;
    block[56] = (uint8_t)(bitlen >> 56);
    block[57] = (uint8_t)(bitlen >> 48);
    block[58] = (uint8_t)(bitlen >> 40);
    block[59] = (uint8_t)(bitlen >> 32);
    block[60] = (uint8_t)(bitlen >> 24);
    block[61] = (uint8_t)(bitlen >> 16);
    block[62] = (uint8_t)(bitlen >> 8);
    block[63] = (uint8_t)(bitlen);

    while (!(*stop_flag)) {
        /* Write nonce (little-endian) into block at offset prefix_len */
        uint64_t n = nonce;
        block[prefix_len + 0] = (uint8_t)(n & 0xFF);
        block[prefix_len + 1] = (uint8_t)((n >> 8) & 0xFF);
        block[prefix_len + 2] = (uint8_t)((n >> 16) & 0xFF);
        block[prefix_len + 3] = (uint8_t)((n >> 24) & 0xFF);
        block[prefix_len + 4] = (uint8_t)((n >> 32) & 0xFF);
        block[prefix_len + 5] = (uint8_t)((n >> 40) & 0xFF);
        block[prefix_len + 6] = (uint8_t)((n >> 48) & 0xFF);
        block[prefix_len + 7] = (uint8_t)((n >> 56) & 0xFF);

        sha256_single_block(block, hash);

        if (count_lzb(hash) >= difficulty_bits) {
            *found_nonce = nonce;
            *hash_count = local;
            return 1;
        }
        nonce += step;
        local++;
        if ((local & 0xFFFF) == 0 && hash_count) {
            *hash_count = local;
        }
    }

    *hash_count = local;
    return 0;
}
