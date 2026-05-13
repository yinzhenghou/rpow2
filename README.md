# rpow2.com VPS Miner

rpow2.com 的 VPS 挖矿程序。使用 `curl_cffi` 模拟 Chrome TLS 指纹绕过 Cloudflare，原生 C SHA-256 运算。

## 目录

- [快速部署](#快速部署)
- [获取 Cookie](#获取-cookie)
- [运行](#运行)
- [架构说明](#架构说明)
- [性能](#性能)
- [已知问题](#已知问题)
- [优化建议](#优化建议)

---

## 快速部署

### 1. 环境要求

- **CPU**: x86_64，推荐 4 核以上
- **OS**: Linux (Ubuntu/Debian 测试通过)
- **Python**: 3.9+（推荐 3.10+）
- **GCC**: 用于编译 C 库

### 2. 克隆 & 安装依赖

```bash
git clone https://github.com/yinzhenghou/rpow2.git
cd rpow2

python3 -m venv venv
venv/bin/pip install curl_cffi requests
```

### 3. 编译 C 库（如已有 libminer.so 可跳过）

```bash
gcc -O3 -march=native -shared -fPIC -o libminer.so sha256_miner.c
```

编译产物 `libminer.so` 会自动被 Python 脚本加载。若加载失败则回退到纯 Python（慢 15 倍）。

---

## 获取 Cookie

rpow2.com 使用 Cloudflare 防护，需要从浏览器获取有效的 Cookie。

### 步骤

1. 用 **Chrome/Edge** 打开 https://rpow2.com 并登录
2. 按 **F12** 打开开发者工具 → **Network**（网络）标签
3. 刷新页面，找到任意发往 `api.rpow2.com` 的请求
4. **右键**该请求 → **复制 as cURL (bash)**
5. 在 curl 命令中找到 `Cookie:` 后面的完整字符串

一个有效的 Cookie 包含三个关键字段：

| Cookie | 作用 | 有效期 |
|--------|------|--------|
| `rpow_session` | 登录会话 JWT | ~30 天 |
| `cf_clearance` | Cloudflare 验证通过的凭证 | ~30 分钟~数小时 |
| `_ga` / `_ga_*` | Google Analytics（非必需） | - |

> ⚠️ `cf_clearance` 会过期。如果遇到 403/Cloudflare 拦截，需要重新获取 Cookie。
> 建议保持浏览器登录 rpow2.com 不要关，每隔几小时重新复制一次。

---

## 运行

```bash
venv/bin/python rpow2-miner.py -c "你的完整Cookie字符串"
```

### 参数

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `-c` / `--cookie` | **必需**。完整的 Cookie 字符串 | — |
| `-t` / `--threads` | 线程数 | CPU 核数（如 8） |

### 输出示例

```
============================================================
 rpow2.com VPS Miner [NATIVE C] (curl_cffi)
============================================================

Logged in: user@example.com  balance=8.50 RPOW  mined_total=6715.45 RPOW

--- Round 1 ---
  Mining... prefix=5c101e448b5f48ba6c31b68c... diff=33 threads=8
    46.6M hashes, 23.21 MH/s
    92.9M hashes, 23.17 MH/s
    ...
  Found! nonce=987654321 (8432.1M hashes, 23.45 MH/s, 359.2s)
  Minted +0.01 RPOW | balance=8.51 RPOW | total=0.01
```

---

## 架构说明

### 整体流程

```
浏览器 Cookie → rpow2-miner.py → curl_cffi (Cloudflare 绕过)
                                       ↓
                                POST /challenge
                                       ↓
                              challenge_id + nonce_prefix + difficulty_bits
                                       ↓
                           sha256_miner.c (C SHA-256 多线程挖矿)
                                       ↓
                                 POST /mint (提交解)
```

### C 库设计

`sha256_miner.c` 是一个**单块专用 SHA-256** 实现：

- 输入固定为 **16 字节 prefix + 8 字节 nonce = 24 字节**
- SHA-256 填充后恰好构成 **1 个 64 字节块**
- 移除了 OpenSSL 依赖和 API 调用开销，全部内联展开（64 轮宏展开）
- 每核 ~3 MH/s（无 SHA-NI 的 Xeon Gold 6133）
- 使用栈分配（无 malloc/free），`volatile` 指针保证进度正确回传

### Python 层

- `curl_cffi` 模拟 Chrome 131 TLS 指纹绕过 Cloudflare
- `ThreadPoolExecutor` 管理多线程，C 代码释放 GIL 实现真并行
- 自动重试（Cooldown、Rate Limit）

---

## 性能

在 Intel Xeon Gold 6133 @ 2.50GHz（8 核，无 SHA-NI）上测试：

| 实现 | 单核 | 8 核 | 说明 |
|------|------|------|------|
| C (自定义 SHA-256) | ~3.0 MH/s | ~24 MH/s | 主力实现 |
| Python (hashlib) | ~0.2 MH/s | ~1.6 MH/s | 回退方案 |

难度 `difficulty_bits = 33` 时：
- 需要 `2^33 ≈ 86 亿次` 哈希（平均）
- 8 核约 **6 分钟** 出一个解
- Challenge 过期时间约 5 分钟

**有 SHA-NI 指令的 CPU**（Intel Ice Lake 或更新）单核可达 15-20 MH/s。

---

## 已知问题

### 1. C 库 count_lzb 字节序错误（已修复 ⚠️ 关键）

**现象**: 挖矿程序一直跑，偶尔显示 "Found!"，但 mint 总是返回 `INVALID_SOLUTION`。

**原因**: 原始 `count_lzb` 函数从哈希的 **LSB 末尾** 数零位，而 rpow2 协议要求从 **MSB 开头** 数零位。挖到的"解"全都无效。

**修复**: 将迭代方向从 `for (i = 31 → 0)` 改为 `for (i = 0 → 31)`，bit 遍历从低位改高位。

```diff
- for (int i = 31; i >= 0; i--)
+ for (int i = 0; i < 32; i++)
```

### 2. hash_count 缺少 volatile（已修复）

**现象**: 进度条一直显示 `0.0M hashes, 0.00 MH/s`，但实际上在正常挖。

**原因**: `hash_count` 指针没有 `volatile` 修饰，GCC 优化掉了循环内的中间写入，只在函数末尾写一次。Python 端看不到中间值。

**修复**: 参数声明加 `volatile`。

```diff
- uint64_t *hash_count
+ volatile uint64_t *hash_count
```

### 3. Challenge 过期 vs 挖矿速度

Challenge 过期时间约 5 分钟，而 difficulty=33 平均需 6 分钟（8 核）。约 50-60% 的概率在过期前找到解。让程序持续运行即可（会自动请求新 challenge）。

---

## 优化建议

### 换有 SHA-NI 的 CPU

这是单核 ~3 MH/s 的硬件上限。换支持 SHA-NI 的 CPU（Intel Ice Lake / AMD Zen 3+）单核可达 15-20 MH/s。

### 使用 `screen` 持久运行

SSH 断开后程序会停，建议用 `screen`：

```bash
screen -S miner
venv/bin/python rpow2-miner.py -c "你的cookie"
# Ctrl+A, D 断开；screen -r miner 重连
```

### 自动化 Cookie 刷新

可写脚本定期从浏览器同步最新 cookie（通过 Chrome REST API 或 Selenium），用 cron 定时刷新。
