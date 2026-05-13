/* rpow2-miner GPU core - CUDA SHA-256 mining kernel
 * Compile: nvcc -O3 -shared -Xcompiler -fPIC -o libgpu_miner.so sha256_miner.cu
 * Requires: NVIDIA CUDA Toolkit (nvcc), CUDA-capable GPU (CC 5.0+)
 */

#include <cuda_runtime.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* ================================================================
 * Device-side SHA-256 (single 64-byte block)
 * ================================================================ */
#define ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define SIG0(x) (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define SIG1(x) (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define ssig0(x) (ROTR(x, 7) ^ ROTR(x, 18) ^ ((x) >> 3))
#define ssig1(x) (ROTR(x, 17) ^ ROTR(x, 19) ^ ((x) >> 10))

__constant__ uint32_t d_K[64] = {
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

__constant__ uint32_t d_H0[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
};

/* Count MSB-leading zero bits in a 32-byte hash */
__device__ int count_lzb(const uint8_t *hash) {
    for (int i = 0; i < 32; i++) {
        uint8_t b = hash[i];
        if (b == 0) continue;
        int c = 7;
        while (!(b & (1 << c))) c--;
        return i * 8 + (7 - c);
    }
    return 256;
}

/* Single-block SHA-256 on device */
__device__ void sha256_single_block(const uint8_t in[64], uint8_t out[32]) {
    uint32_t W[64];
    uint32_t a, b, c, d, e, f, g, h, T1, T2;

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

    /* Compression */
    a = d_H0[0]; b = d_H0[1]; c = d_H0[2]; d = d_H0[3];
    e = d_H0[4]; f = d_H0[5]; g = d_H0[6]; h = d_H0[7];

    for (int t = 0; t < 64; t++) {
        T1 = h + SIG1(e) + ((e & f) ^ (~e & g)) + d_K[t] + W[t];
        T2 = SIG0(a) + ((a & b) ^ (a & c) ^ (b & c));
        h = g; g = f; f = e; e = d + T1; d = c; c = b; b = a; a = T1 + T2;
    }

    a += d_H0[0]; b += d_H0[1]; c += d_H0[2]; d += d_H0[3];
    e += d_H0[4]; f += d_H0[5]; g += d_H0[6]; h += d_H0[7];

    out[0]  = (uint8_t)(a >> 24); out[1]  = (uint8_t)(a >> 16);
    out[2]  = (uint8_t)(a >> 8);  out[3]  = (uint8_t)(a);
    out[4]  = (uint8_t)(b >> 24); out[5]  = (uint8_t)(b >> 16);
    out[6]  = (uint8_t)(b >> 8);  out[7]  = (uint8_t)(b);
    out[8]  = (uint8_t)(c >> 24); out[9]  = (uint8_t)(c >> 16);
    out[10] = (uint8_t)(c >> 8);  out[11] = (uint8_t)(c);
    out[12] = (uint8_t)(d >> 24); out[13] = (uint8_t)(d >> 16);
    out[14] = (uint8_t)(d >> 8);  out[15] = (uint8_t)(d);
    out[16] = (uint8_t)(e >> 24); out[17] = (uint8_t)(e >> 16);
    out[18] = (uint8_t)(e >> 8);  out[19] = (uint8_t)(e);
    out[20] = (uint8_t)(f >> 24); out[21] = (uint8_t)(f >> 16);
    out[22] = (uint8_t)(f >> 8);  out[23] = (uint8_t)(f);
    out[24] = (uint8_t)(g >> 24); out[25] = (uint8_t)(g >> 16);
    out[26] = (uint8_t)(g >> 8);  out[27] = (uint8_t)(g);
    out[28] = (uint8_t)(h >> 24); out[29] = (uint8_t)(h >> 16);
    out[30] = (uint8_t)(h >> 8);  out[31] = (uint8_t)(h);
}

/* ================================================================
 * Mining kernel
 * ================================================================ */

/* Each thread processes many nonces. The thread index determines the
 * starting nonce, and grid_stride determines the step. */
__global__ void mine_kernel(
    const uint8_t* d_prefix, size_t prefix_len,
    int difficulty_bits,
    uint64_t base_nonce, uint64_t grid_stride,
    uint64_t nonces_per_thread,
    volatile uint64_t* found_nonce,
    volatile uint64_t* hash_count)
{
    uint64_t tid = blockIdx.x * blockDim.x + threadIdx.x;
    uint64_t nonce = base_nonce + tid;
    uint64_t local_count = 0;

    /* Build constant block template in registers */
    uint8_t block[64];
    memset(block, 0, 64);
    memcpy(block, d_prefix, prefix_len);
    block[prefix_len + 8] = 0x80;
    uint64_t bitlen = (uint64_t)(prefix_len + 8) * 8;
    block[63] = (uint8_t)(bitlen);
    block[62] = (uint8_t)(bitlen >> 8);
    block[61] = (uint8_t)(bitlen >> 16);
    block[60] = (uint8_t)(bitlen >> 24);
    block[59] = (uint8_t)(bitlen >> 32);
    block[58] = (uint8_t)(bitlen >> 40);
    block[57] = (uint8_t)(bitlen >> 48);
    block[56] = (uint8_t)(bitlen >> 56);

    for (uint64_t k = 0; k < nonces_per_thread; k++) {
        // Write nonce into block (little-endian)
        block[prefix_len + 0] = (uint8_t)(nonce & 0xFF);
        block[prefix_len + 1] = (uint8_t)((nonce >> 8) & 0xFF);
        block[prefix_len + 2] = (uint8_t)((nonce >> 16) & 0xFF);
        block[prefix_len + 3] = (uint8_t)((nonce >> 24) & 0xFF);
        block[prefix_len + 4] = (uint8_t)((nonce >> 32) & 0xFF);
        block[prefix_len + 5] = (uint8_t)((nonce >> 40) & 0xFF);
        block[prefix_len + 6] = (uint8_t)((nonce >> 48) & 0xFF);
        block[prefix_len + 7] = (uint8_t)((nonce >> 56) & 0xFF);

        uint8_t hash[32];
        sha256_single_block(block, hash);

        if (count_lzb(hash) >= difficulty_bits) {
            atomicMin((uint64_t*)found_nonce, nonce);
        }

        nonce += grid_stride;
        local_count++;
    }

    /* Accumulate hash count (batch per thread) */
    atomicAdd((uint64_t*)hash_count, local_count);
}

/* ================================================================
 * Host-side wrapper (C ABI for ctypes)
 * ================================================================ */

static int gpu_initialized = 0;
static cudaDeviceProp gpu_props;

extern "C" int gpu_init() {
    if (gpu_initialized) return 1;
    int count;
    cudaError_t err = cudaGetDeviceCount(&count);
    if (err != cudaSuccess || count == 0) return 0;
    cudaSetDevice(0);
    cudaGetDeviceProperties(&gpu_props, 0);
    gpu_initialized = 1;
    return 1;
}

extern "C" const char* gpu_name() {
    if (!gpu_initialized && !gpu_init()) return "N/A";
    return gpu_props.name;
}

extern "C" int gpu_sm_count() {
    if (!gpu_initialized && !gpu_init()) return 0;
    return gpu_props.multiProcessorCount;
}

/* GPU batch mine: runs ONE kernel launch, returns immediately.
 * Call in a loop from Python, reporting progress between batches.
 * Returns: 0=continue, 1=found, -1=error */
extern "C" int gpu_mine_batch(
    const uint8_t* prefix, size_t prefix_len,
    int difficulty_bits,
    uint64_t* base_nonce,      /* in/out: starting nonce for this batch */
    volatile uint64_t* hash_count, /* in/out: cumulative hashes */
    uint64_t* found_nonce)     /* out: found nonce or 0xFFFFFFFFFFFFFFFF */
{
    if (!gpu_initialized && !gpu_init()) return -1;

    /* Determine launch configuration */
    int sm_count = gpu_props.multiProcessorCount;
    int threads_per_block = 256;
    int blocks = sm_count * 16;
    uint64_t total_threads = (uint64_t)blocks * threads_per_block;

    /* 10M nonces per batch (~50ms on modern GPU) */
    uint64_t nonces_per_thread = (10UL * 1024 * 1024) / total_threads;
    if (nonces_per_thread < 50) nonces_per_thread = 50;

    /* Allocate/reuse device memory */
    static uint8_t* d_prefix = nullptr;
    static uint64_t* d_found = nullptr;
    static uint64_t* d_count = nullptr;
    static size_t cached_prefix_len = 0;

    if (!d_prefix || cached_prefix_len != prefix_len) {
        if (d_prefix) { cudaFree(d_prefix); cudaFree(d_found); cudaFree(d_count); }
        cudaMalloc(&d_prefix, prefix_len);
        cudaMalloc(&d_found, sizeof(uint64_t));
        cudaMalloc(&d_count, sizeof(uint64_t));
        cudaMemcpy(d_prefix, prefix, prefix_len, cudaMemcpyHostToDevice);
        cached_prefix_len = prefix_len;
    }

    /* Reset found flag */
    uint64_t no_found = 0xFFFFFFFFFFFFFFFFULL;
    cudaMemcpy(d_found, &no_found, sizeof(uint64_t), cudaMemcpyHostToDevice);

    uint64_t grid_stride = total_threads;

    mine_kernel<<<blocks, threads_per_block>>>(
        d_prefix, prefix_len, difficulty_bits,
        *base_nonce, grid_stride, nonces_per_thread,
        (volatile uint64_t*)d_found,
        (volatile uint64_t*)d_count);

    cudaError_t err = cudaDeviceSynchronize();
    if (err != cudaSuccess) {
        fprintf(stderr, "CUDA error: %s\n", cudaGetErrorString(err));
        return -1;
    }

    /* Accumulate hash count and check for solution */
    uint64_t batch_count;
    cudaMemcpy(&batch_count, d_count, sizeof(uint64_t), cudaMemcpyDeviceToHost);
    *hash_count += batch_count;

    uint64_t h_found;
    cudaMemcpy(&h_found, d_found, sizeof(uint64_t), cudaMemcpyDeviceToHost);
    if (h_found != 0xFFFFFFFFFFFFFFFFULL) {
        *found_nonce = h_found;
        cudaFree(d_prefix); cudaFree(d_found); cudaFree(d_count);
        d_prefix = nullptr; cached_prefix_len = 0;
        return 1;
    }

    /* Advance nonce for next batch */
    *base_nonce += total_threads * nonces_per_thread;

    /* Reset device counter for next batch (reuse cudaMemset) */
    cudaMemset(d_count, 0, sizeof(uint64_t));
    return 0;
}

extern "C" void gpu_cleanup() {
    cudaDeviceReset();
    gpu_initialized = 0;
}
