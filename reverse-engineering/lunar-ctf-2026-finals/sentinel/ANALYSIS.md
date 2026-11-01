# SENTINEL [LNR-06] — Reverse Engineering Analysis

**Category:** Rev · **Points:** 500 · **Target:** `gateway.kumosec.rootriet.in:9000` (TCP)
**Artifact:** `sentinel-agent` — ELF 64-bit LSB PIE, x86-64, **stripped**, 14,384 bytes
**SHA-256:** `2bb9604eb46f16c5e75a03f8e200d0d10ee66aadf9dacc14f23a80d0ac58c0a7` (matches challenge spec)

---

## 1. Binary triage

Imported symbols (dynamic) — **no crypto library**, only libc + sockets:
```
socket, connect, gethostbyname, close, strcmp, strtol,
__memcpy_chk, __printf_chk, __fprintf_chk, puts, perror, fwrite
```
`.text` is only **0x518 (1304) bytes** → it cannot contain real SHA256/AES. The heavy crypto
is **not** in the binary; it is defined by the gateway's published SNTL/2.0 spec (standard algos).

## 2. Control flow (`main` @ 0x1140)

1. `0x1600` — prints the ASCII banner (cosmetic).
2. Parse args: `--team`, `--host` (default `gateway.kumosec.rootriet.in`), `--port` (default 9000).
3. Prints `[*] Initializing SNTL/2.0 wire framing & crypto engine...`
4. `0x15d0` — **deobfuscates the client seed** into a stack buffer (see §3).
5. `gethostbyname` + `socket` + `connect` to the gateway.
6. Prints `[+] Connected ... Initiating SNTL handshake...`
7. **`close(fd)` and exit.**

> **The binary is a stub.** It deobfuscates the seed and opens a TCP connection, then exits
> **without sending anything**. The only secret it carries is the seed below. The RE "flag"
> of this binary is recovering that seed; the protocol itself must be implemented from the spec.

## 3. Seed deobfuscation (`0x15d0`)

```asm
rsi = 0x2560 (obfuscated data, 45 bytes)
rcx = 0x2520 (XOR key, 45 bytes)
for i in 0..0x2d:  out[i] = data[0x2560+i] XOR key[0x2520+i]
```
- `data@0x2560 = 1b342d2f1325236d...`
- `key @0x2520 = 504140404040...40`  (0x50,0x41, then 0x40 repeated)

**Recovered client seed (45 bytes):**
```
KumoSec-Sentinel-v2.3-KeyDerivation-Seed-2026
```

## 4. SNTL/2.0 protocol (from the gateway spec)

| Phase | Client → | Server → | Notes |
|-------|----------|----------|-------|
| 1 | `CMD_HELO (0x01)` + team id | `CMD_CHALLENGE (0x02)` + 16-byte server nonce | framing: SNTL/2.0, CRC-16-CCITT |
| 2 | *(local)* HKDF-SHA256 | — | derive `k_enc`(16) + `k_hmac`(16) from seed + server nonce |
| 3 | `CMD_AUTH_REQ (0x03)` + proof | `CMD_AUTH_OK (0x04)` | prove possession of key material |
| 4 | `CMD_PULL_CONFIG (0x10)` | `CMD_CONFIG_DATA (0x11)` | AES-128-CTR-encrypted policy blob → **flag** |

Encryption: **HKDF-SHA256** (RFC 5869) → **AES-128-CTR**. Auth: HMAC (k_hmac).

## 5. Known vs. unknown (what still needs pinning down)

**Known (from binary / spec):**
- Client seed (above), command bytes, phase order, CRC-16-CCITT, HKDF-SHA256, AES-128-CTR.

**Not in the binary — must be derived empirically from the live gateway:**
- Exact frame header layout (magic/version/cmd/length ordering, endianness, CRC position).
- CRC-16-CCITT parameters (init 0xFFFF vs 0x0000).
- HELO payload exact format (team id as the `--team` string).
- HKDF inputs: which of {seed, team id, nonce} is IKM vs salt vs info.
- AUTH proof definition: `HMAC(k_hmac, server_nonce)`? over transcript? truncation?
- AES-CTR IV/counter initialization (server nonce? zero?).

## 6. Next step

Because the binary never emits a frame, these last parameters must be confirmed by a **small,
controlled number of probes** to `gateway.kumosec.rootriet.in:9000` (observe the `CMD_CHALLENGE`
frame to learn the exact framing, then iterate auth). `solve_sentinel.py` is the scaffold for this.

## Files
| File | Description |
|------|-------------|
| `sentinel-agent` | the challenge binary (stub) |
| `README_challenge.txt` | original challenge README from the bundle |
| `gateway_landing.html` | gateway page documenting SNTL/2.0 |
| `REVERSE_sentinel_player.tar.gz` | original downloaded bundle |
| `analysis/disasm.intel.txt` | full objdump disassembly |
| `analysis/strings.txt`, `analysis/rodata.txt` | strings / .rodata dumps |
| `solve_sentinel.py` | protocol client scaffold (seed + HKDF/AES/CRC, params to tune) |

---

## 7. Live probing results (10 connections used)

**Frame format — CONFIRMED** (server leaked its own framing in an error reply):
```
SNTL(4) | ver=0x02 | cmd(1) | flags(1) | rsv(1) | len(2 BE)
       | CRC16-CCITT-FALSE(header[0:10]) (2 BE) | payload | (client frames padded to 76 bytes)
```
- Verified: `crc16(b"SNTL\x02\xff\x01\x00\x00\x20") == 0x5263` == bytes[10:12] of the server reply.
- CRC covers the **10-byte header only**; client frames must be padded to **76 bytes** (shorter → `"Protocol error: Packet truncated"`).

**Phase 1 — WORKS.** `CMD_HELO(0x01)` + team → `CMD_CHALLENGE(0x02)` + 16-byte nonce.

**Phase 3 — OPEN.** Wrong proof → `"Signature rejected"`; server **closes after ~2 auth tries per connection**.
Tried & rejected: `HKDF(ikm=SEED, salt=nonce, info∈{"", "SNTL/2.0"})`, `proof=HMAC(k_hmac, nonce)` [32] and [16].

**Phase 4 — OPEN.** AES-128-CTR IV for `CMD_CONFIG_DATA(0x11)` not yet determined.

**Remaining unknowns:** HKDF info/salt assignment, exact proof message, AES-CTR IV.
`solve_sentinel.py` sweeps these in likelihood order, `TRIES_PER_CONN=2` per connection
(`./.venv/bin/python solve_sentinel.py <start_index>`), resumable across connections.
