#!/usr/bin/env python3
"""rpow2.com VPS miner — uses curl_cffi to impersonate Chrome TLS and bypass Cloudflare.
Usage: venv/bin/python rpow2-miner.py -c "full_cookie_string"
Get cookie: F12→Network→right-click api.rpow2.com request→Copy as cURL→grab Cookie value."""

import argparse, ctypes, json, os, re, sys, threading, time
from concurrent.futures import ThreadPoolExecutor, as_completed

# ===================== Backend Detection =====================
# Priority: GPU (CUDA) > CPU (C native) > Python fallback
GPU = False
NATIVE = False

# Try GPU library first (libgpu_miner.so, CUDA)
try:
    _gpu_lib = ctypes.CDLL(os.path.join(os.path.dirname(__file__), "libgpu_miner.so"))
    _gpu_lib.gpu_init.restype = ctypes.c_int
    _gpu_lib.gpu_name.restype = ctypes.c_char_p
    _gpu_lib.gpu_mine_batch.argtypes = [
        ctypes.c_void_p, ctypes.c_size_t,
        ctypes.c_int,
        ctypes.POINTER(ctypes.c_uint64),
        ctypes.POINTER(ctypes.c_uint64),
        ctypes.POINTER(ctypes.c_uint64),
    ]
    _gpu_lib.gpu_mine_batch.restype = ctypes.c_int
    if _gpu_lib.gpu_init():
        GPU = True
except Exception:
    pass

# Fallback to CPU native C
if not GPU:
    try:
        _lib = ctypes.CDLL(os.path.join(os.path.dirname(__file__), "libminer.so"))
        _lib.mine_worker.argtypes = [
            ctypes.c_void_p, ctypes.c_size_t,
            ctypes.c_int,
            ctypes.c_uint64, ctypes.c_uint64,
            ctypes.c_void_p,
            ctypes.c_void_p, ctypes.c_void_p,
        ]
        NATIVE = True
    except Exception:
        NATIVE = False

try:
    from curl_cffi import requests
    CURL_CFFI = True
except ImportError:
    import requests
    CURL_CFFI = False

API_BASE = "https://api.rpow2.com"
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36"





def parse_cookies(s: str) -> dict:
    d = {}
    for part in s.split(";"):
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            d[k.strip()] = v.strip()
    return d


class Miner:
    def __init__(self, cookie_str: str, threads: int = None):
        self.cookies = parse_cookies(cookie_str)
        if "rpow_session" not in self.cookies:
            print("WARN: no rpow_session in cookie")

        if CURL_CFFI:
            self.sess = requests.Session(impersonate="chrome131")
        else:
            self.sess = requests.Session()

        self.sess.headers.update({
            "User-Agent": UA,
            "Content-Type": "application/json",
            "Accept": "application/json, text/plain, */*",
            "Origin": "https://rpow2.com",
            "Referer": "https://rpow2.com/",
        })
        for k, v in self.cookies.items():
            self.sess.cookies.set(k, v, domain="api.rpow2.com")
            self.sess.cookies.set(k, v, domain="rpow2.com")

        self.threads = threads or os.cpu_count() or max(1, threading.active_count())
        if GPU:
            gpu_name = _gpu_lib.gpu_name().decode()
            print(f"  Backend: GPU [{gpu_name}]")
        elif NATIVE:
            print(f"  Backend: CPU native C ({self.threads} cores)")
        else:
            print(f"  Backend: Python hashlib ({self.threads} threads, SLOW)")
        self._stop = threading.Event()
        self._found = None
        self._flock = threading.Lock()
        self._hcount = 0
        self._hlock = threading.Lock()
        self._cstop = ctypes.c_int(0)

    def _api(self, method, path, data=None):
        url = f"{API_BASE}{path}"
        hdr = {"Cookie": "; ".join(f"{k}={v}" for k, v in self.cookies.items())}
        if method == "GET":
            r = self.sess.get(url, headers=hdr, timeout=30)
        else:
            r = self.sess.post(url, json=(data or {}), headers=hdr, timeout=30)
        if r.status_code == 403 and "Just a moment" in r.text:
            raise RuntimeError("Cloudflare blocked (403). Cookie may be expired.")
        if r.status_code == 204:
            return {}
        if not r.ok:
            try:
                e = r.json()
            except Exception:
                e = {"error": "HTTP", "message": r.text[:200]}
            raise RuntimeError(f"API error ({r.status_code}): {e}")
        return r.json()

    def me(self): return self._api("GET", "/me")
    def challenge(self): return self._api("POST", "/challenge")
    def mint(self, cid, nonce): return self._api("POST", "/mint", {"challenge_id": cid, "solution_nonce": nonce})

    def _worker_gpu(self, prefix_bytes, diff):
        """GPU-backed mining worker — calls gpu_mine_batch in a loop."""
        base = ctypes.c_uint64(0)
        count = ctypes.c_uint64(0)
        found = ctypes.c_uint64(0xFFFFFFFFFFFFFFFF)
        prefix_arr = (ctypes.c_uint8 * len(prefix_bytes))(*prefix_bytes)

        t0 = time.time()
        last_report = t0
        while not self._stop.is_set():
            ret = _gpu_lib.gpu_mine_batch(
                prefix_arr, len(prefix_bytes), diff,
                ctypes.byref(base), ctypes.byref(count),
                ctypes.byref(found)
            )
            if ret == 1 or found.value != 0xFFFFFFFFFFFFFFFF:
                self._hcount = count.value
                elapsed = time.time() - t0
                total = count.value
                print(f"\n  Found! nonce={found.value} ({total/1e6:.1f}M hashes, {total/elapsed/1e6:.2f} MH/s, {elapsed:.1f}s)")
                return str(found.value)
            if ret < 0:
                raise RuntimeError(f"GPU error code={ret}")

            # Report progress
            now = time.time()
            if now - last_report >= 2.0:
                e = now - t0
                cv = count.value
                print(f"    {cv/1e6:.1f}M hashes, {cv/e/1e6:.2f} MH/s", end="\r")
                last_report = now

            if self._stop.is_set():
                break

        self._hcount = count.value
        raise RuntimeError("Mining interrupted, no solution")

    def _worker(self, tid, prefix, diff, start, step):
        if NATIVE:
            prefix_arr = (ctypes.c_uint8 * len(prefix))(*prefix)
            found = ctypes.c_uint64(0)
            count = ctypes.c_uint64(0)
            # Store count ref for progress reporting
            self._counts[tid] = count
            _lib.mine_worker(
                prefix_arr, len(prefix), diff, start, step,
                ctypes.byref(self._cstop),
                ctypes.byref(found), ctypes.byref(count)
            )
            with self._hlock:
                self._hcount += count.value
            if found.value:
                with self._flock:
                    if self._found is None:
                        self._found = found.value
                        self._stop.set()
            return found.value if found.value else None
        # Python fallback
        import hashlib
        buf = bytearray(prefix + b"\x00" * 8)
        plen = len(prefix)
        nonce = start
        while not self._stop.is_set():
            n = nonce
            for i in range(8):
                buf[plen + i] = n & 0xFF
                n >>= 8
            digest = hashlib.sha256(buf).digest()
            z = 0
            for i2 in range(32):
                b = digest[i2]
                if b:
                    c = 7
                    while not (b & (1 << c)): c -= 1
                    z = i2 * 8 + (7 - c)
                    break
                z += 8
            if z >= diff:
                with self._flock:
                    if self._found is None:
                        self._found = nonce
                        self._stop.set()
                return nonce
            nonce += step
            if nonce & 0xFFFF == 0:
                with self._hlock:
                    self._hcount += 65536

    def _mine(self, phex, diff):
        prefix = bytes.fromhex(phex)
        if GPU:
            print(f"  Mining... prefix={phex[:24]}... diff={diff} [GPU]")
            return self._worker_gpu(prefix, diff)
        n = max(1, self.threads or os.cpu_count())
        self._stop.clear()
        self._found = None
        self._hcount = 0
        self._cstop.value = 0
        self._counts = {}
        print(f"  Mining... prefix={phex[:24]}... diff={diff} threads={n}")
        t0 = time.time()
        with ThreadPoolExecutor(max_workers=n) as ex:
            futs = [ex.submit(self._worker, t, prefix, diff, t, n) for t in range(n)]
            last = t0
            while not self._stop.is_set() and self._found is None:
                time.sleep(0.5)
                now = time.time()
                if now - last >= 2.0:
                    # Sum hash counts from all live C threads
                    h = sum(c.value for c in self._counts.values())
                    e = now - t0
                    print(f"    {h/1e6:.1f}M hashes, {h/e/1e6:.2f} MH/s", end="\r")
                    last = now
            self._stop.set()
            for f in as_completed(futs): pass
        elapsed = time.time() - t0
        with self._hlock: total = self._hcount
        if self._found is None:
            raise RuntimeError("Mining interrupted, no solution")
        print(f"\n  Found! nonce={self._found} ({total/1e6:.1f}M hashes, {total/elapsed/1e6:.2f} MH/s, {elapsed:.1f}s)")
        return str(self._found)

    def run(self):
        tag = "GPU" if GPU else ("NATIVE C" if NATIVE else "PYTHON")
        print("=" * 60)
        print(f" rpow2.com VPS Miner [{tag}] ({'curl_cffi' if CURL_CFFI else 'requests'})")
        print("=" * 60)
        try:
            u = self.me()
            bal = int(u.get('balance_base_units', '0')) / 1e8
            mnt = int(u.get('minted_base_units', '0')) / 1e8
            print(f"\nLogged in: {u.get('email','?')}  balance={bal:.2f} RPOW  mined_total={mnt:.2f} RPOW")
        except Exception as e:
            print(f"\nAuth failed: {e}")
            sys.exit(1)

        total = 0
        rn = 0
        while True:
            rn += 1
            print(f"\n--- Round {rn} ---")
            try:
                ch = self.challenge()
            except Exception as e:
                es = str(e)
                if "COOLDOWN" in es:
                    m = re.search(r"'retry_after':\s*(\d+)", es)
                    cd = int(m.group(1)) if m else 5
                    print(f"  Cooldown {cd}s...")
                    time.sleep(cd)
                    continue
                if "rate_limited" in es or "429" in es:
                    m = re.search(r"'retry_after':\s*(\d+)", es)
                    cd = int(m.group(1)) if m else 30
                    print(f"  Rate limited, waiting {cd}s...")
                    time.sleep(cd)
                    continue
                print(f"  Challenge failed: {e}")
                time.sleep(5)
                continue

            cid = ch.get("challenge_id")
            npre = ch.get("nonce_prefix")
            diff = ch.get("difficulty_bits")
            if not all([cid, npre, diff is not None]):
                print(f"  Bad challenge: {json.dumps(ch)[:200]}")
                time.sleep(5)
                continue

            try:
                sol = self._mine(npre, diff)
            except RuntimeError as e:
                print(f"  Mine failed: {e}")
                break

            try:
                r = self.mint(cid, sol)
                amt_units = r.get("amount_base_units", r.get("amount", "?"))
                bal_units = r.get("balance_base_units", r.get("balance", "?"))
                amt = int(amt_units) / 1e8 if isinstance(amt_units, str) and amt_units.isdigit() else amt_units
                bal = int(bal_units) / 1e8 if isinstance(bal_units, str) and bal_units.isdigit() else bal_units
                if isinstance(amt, (int, float)): total += amt
                print(f"  Minted +{amt:.2f} RPOW | balance={bal:.2f} RPOW | total={total:.2f}")
            except Exception as e:
                print(f"  Mint failed: {e}")
                time.sleep(3)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("-c", "--cookie", required=True)
    p.add_argument("-t", "--threads", type=int, default=0)
    args = p.parse_args()
    th = args.threads if args.threads > 0 else None
    Miner(args.cookie, th).run()


if __name__ == "__main__":
    main()
