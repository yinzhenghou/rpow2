"""Benchmark: Python hashlib vs C libminer.so"""
import hashlib, ctypes, time

# Load C lib
lib = ctypes.CDLL("/root/libminer.so")
lib.mine_worker.argtypes = [
    ctypes.c_void_p, ctypes.c_size_t,  # prefix, prefix_len
    ctypes.c_int,                       # difficulty_bits
    ctypes.c_uint64, ctypes.c_uint64,  # start_nonce, step
    ctypes.c_void_p,                    # stop_flag
    ctypes.c_void_p, ctypes.c_void_p,  # found_nonce, hash_count
]
lib.mine_worker.restype = ctypes.c_int

prefix_hex = "611a14a014a0591d9cf44491"
prefix = bytes.fromhex(prefix_hex)
difficulty = 256  # Never achievable — pure loop speed test

def bench_c(seconds=3):
    """Run C miner for `seconds` and measure hashes/sec"""
    import threading
    stop = ctypes.c_int(0)
    found = ctypes.c_uint64(0)
    count = ctypes.c_uint64(0)

    def stopper():
        time.sleep(seconds)
        stop.value = 1
    threading.Thread(target=stopper, daemon=True).start()
    
    t0 = time.time()
    lib.mine_worker(
        (ctypes.c_uint8 * len(prefix))(*prefix), len(prefix),
        difficulty,
        0, 1,
        ctypes.byref(stop), ctypes.byref(found), ctypes.byref(count)
    )
    elapsed = time.time() - t0
    h = count.value
    return h, elapsed, h / elapsed / 1e6

def bench_py(seconds=3):
    """Same logic in Python"""
    buf = bytearray(prefix + b"\x00" * 8)
    plen = len(prefix)
    nonce = 0
    count = 0
    t0 = time.time()
    deadline = t0 + seconds
    while time.time() < deadline:
        n = nonce
        for i in range(8):
            buf[plen + i] = n & 0xFF
            n >>= 8
        hashlib.sha256(buf).digest()
        nonce += 1
        count += 1
    elapsed = time.time() - t0
    return count, elapsed, count / elapsed / 1e6

# Run benchmarks
print("=== Performance Comparison ===\n")

h_c, t_c, mh_c = bench_c(3)
print(f"C (libminer.so):    {h_c/1e6:.2f}M hashes in {t_c:.1f}s  →  {mh_c:.2f} MH/s")

h_py, t_py, mh_py = bench_py(3)
print(f"Python (hashlib):   {h_py/1e6:.2f}M hashes in {t_py:.1f}s  →  {mh_py:.2f} MH/s")

print(f"\nSpeedup: {mh_c/mh_py:.1f}x")
