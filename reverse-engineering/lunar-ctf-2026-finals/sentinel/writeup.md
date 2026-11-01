# SENTINEL (LNR-06, Rev, 500) — Writeup

**Team:** Piedd Piper (engagement code `LNR-93BED1401D`) · **Status:** protocol fully reversed;
Phase-3 auth **unresolved** (0 global solves — suspected mis-deployment, see §8).
**Target:** `gateway.kumosec.rootriet.in:9000` (TCP) = `103.49.131.90:9000`
**Artifact:** `sentinel-agent` (ELF x86-64, PIE, stripped, 14,384 B,
SHA-256 `2bb9604e…c0a7`).

---

## 1. Summary

The challenge ships a stripped Linux "EDR agent" binary and asks us to reverse its wire protocol
(**SNTL/2.0**) and complete a cryptographic handshake with the gateway to pull an
AES-128-CTR-encrypted config containing the team's dynamic flag.

**What is fully solved:** the binary RE (seed + CRC), the complete frame format, and Phase 1
(`HELO → CHALLENGE`). The client is implemented and verified correct against RFC/CRC/live server.

**The single blocker:** the Phase-3 authentication proof. The exact construction
`HMAC(k_hmac, ?)` — the HKDF `info`/salt and the HMAC message — is **not present in the binary,
the spec page, the web surface, or the server's error behaviour**, and the gateway allows **one
guess per connection**. ~100 reasonable constructions were tried; all `"Signature rejected"`.

---

## 2. Binary reverse engineering (`sentinel-agent`)

- **Imports:** libc + sockets only (`socket, connect, gethostbyname, close, strcmp, strtol,
  __memcpy_chk, __printf_chk, …`). **No crypto library.** `.text` is 0x518 (1304) bytes — too
  small to contain inline SHA256/AES.
- **`main` (0x1140):** parse `--team/--host/--port` → print banner → **deobfuscate seed (0x15d0)**
  → `gethostbyname`/`socket`/`connect` → print "Initiating SNTL handshake…" → **`close()` and
  exit.** There is **no `send`/`recv`** anywhere — *the binary never emits a frame.* It is a stub
  whose only secret is the seed; the protocol must be inferred from the spec + live server.
- **Seed deobfuscation (0x15d0):** `out[i] = data[0x2560+i] XOR key[0x2520+i]` for 45 bytes.
  Re-derived directly from the file:
  ```
  KumoSec-Sentinel-v2.3-KeyDerivation-Seed-2026
  ```
  (45 bytes, nothing appended — verified byte-for-byte.)
- **Dead CRC routine (0x1580):** init `0xFFFF`, poly `0x1021`, 16-bit → **CRC-16/CCITT-FALSE**.
  Left in deliberately as a spec hint (it is never called by `main`).

## 3. SNTL/2.0 protocol — CONFIRMED

```
Frame:  SNTL(4) | ver=0x02 | cmd(1) | flags(1) | rsv(1) | len(2 BE)
              | CRC16-CCITT-FALSE(header[0:10]) (2 BE) | payload
        client frames padded to 76 bytes; CRC covers the 10-byte header only.
Server frames padded to 60 bytes; flags=0x02 on server replies.
```
- **CRC proof:** `crc16("SNTL\x02\xff\x01\x00\x00\x20") == 0x5263` and
  `crc16("SNTL\x02\x02\x02\x00\x00\x10") == 0xe1c0`, both matching live server bytes.
- **Commands:** `HELO 0x01`, `CHALLENGE 0x02`, `AUTH_REQ 0x03`, `AUTH_OK 0x04`,
  `PULL_CONFIG 0x10`, `CONFIG_DATA 0x11`, `ERROR 0xff`.
- **Phases:** (1) HELO+team → CHALLENGE+16-byte nonce · (2) *local* HKDF-SHA256 → k_enc, k_hmac ·
  (3) AUTH_REQ+proof → AUTH_OK · (4) PULL_CONFIG → CONFIG_DATA (AES-128-CTR) → flag.

## 4. What works

- **Phase 1:** `HELO(0x01, team)` → `CHALLENGE(0x02)` + **16-byte nonce** (no hidden fields; the
  32 trailing bytes are zero padding). This proves framing, CRC, version, and padding are correct.
- **Phase-3 frame structure (reversed from error messages):** the AUTH payload must be a **bare
  ≤32-byte value** the server compares to its own HMAC. Payloads of 46/48 B →
  `"Protocol error: Incomplete payload/HMAC"`; payloads ≤32 B reach the compare →
  `"Signature rejected"`. So the proof is a bare 32-byte `HMAC-SHA256(k_hmac, message)`, **no
  prefix/echo wrapping** (`nonce‖mac`, `team‖mac`, `mac‖nonce` are all rejected as malformed).
- **Tooling verified:** our HKDF matches **RFC 5869 TC1 & TC3**; CRC matches the live server; the
  seed is re-derived from the binary. Every rejection below is therefore real, not a client bug.

## 5. Phase-3 — exhaustive attempts (all `"Signature rejected"`)

Server closes after exactly **one** auth attempt per connection (nonce is per-connection), so each
candidate below = one gateway connection. ~100 total.

**Correct-crypto (HMAC-SHA256):**
- HKDF idiom A `salt=nonce, ikm=seed` and idiom B `salt=0, info=nonce`; both key halves
  (`okm[:16]`, `okm[16:32]`); 16- and 32-byte `k_hmac` (HKDF length 32 and 48).
- `info` ∈ `{"", "SNTL/2.0", "sentinel", "Sentinel", "SNTL", "session", "KumoSec",
  "KumoSec Sentinel", "KeyDerivation", "v2.3.1", "SNTL/2.0 session keys", TEAM, …}`.
- Two-expand HKDF with per-key `info` ∈ `{"k_enc"/"k_hmac", "enc"/"hmac", "enc"/"mac",
  "encryption"/"authentication", "SNTL/2.0 enc"/"SNTL/2.0 hmac"}`.
- Keys = PRK / `sha256(seed)` / raw seed.
- Per-team two-level: `pts = HKDF/HMAC(seed, team)` → session keys → HMAC.
- `ikm` = `seed‖team`, `team‖seed`, `team`; `salt` = `team‖nonce`, `nonce_hex`.
- **Messages** ∈ `{nonce, team‖nonce, nonce‖team, seed, seed‖nonce, k_enc, okm, nonce_hex
  (lower/upper), challenge-frame (hdr10+N / hdr12+N / full-60), team-only, empty}`.

**Author-style raw-SHA256 "MAC"** (Nightwatch uses `SHA256(secret‖payload)` and calls it HMAC):
- `SHA256(seed‖nonce)`, `SHA256(nonce‖seed)`, `SHA256(k_hmac‖nonce)`, `SHA256(nonce‖k_hmac)`,
  `SHA256(seed‖nonce‖seed)`, `SHA256(k_hmac‖nonce‖k_hmac)`, `SHA256(k_enc‖nonce)`,
  `SHA256(okm‖nonce)`, `SHA256(seed‖nonce‖team)`. All rejected.

## 6. Bypass / flaw attempts (all rejected or closed)

The KumoSec family is solved by *breaking* the mechanism (Nightwatch = SHA256 length-extension;
ChainVault = reentrancy), so the gateway was probed for a bypass:
- All-zero[32], all-0xff[32], zeros[16], `nonce‖nonce` proofs → `"Signature rejected"`.
- Client-sent `AUTH_OK(0x04)` then `PULL_CONFIG` → socket closed (state machine enforced).
- `PULL_CONFIG` before auth / with `flags=0x02` → closed.
- Version downgrade `ver=0x01` → `"Invalid magic or protocol version"`.
- `PULL_CONFIG`/unknown command as first frame → closed.

**The gateway is robustly built — no trivial auth bypass, no state-machine confusion.**

## 7. Recon (web surface — exhausted)

- Host `103.49.131.90` open ports: 22, 80 (ChainVault), 5003 (Sentinel landing — the page we have),
  5005/8000 (Nightwatch), 9000 (gateway).
- Wildcard `*.kumosec.rootriet.in → 103.49.131.90`. Vhost enumeration via `Host` header: `:5003`
  serves the Sentinel landing for all hosts; `:80` reverse-proxies by subdomain (most → 502;
  `telemetry` → a static "Device Security Console" dashboard; `nightwatch` → Nightwatch). **No
  spec, no server source, no reference client, no leaked key, no Swagger/OpenAPI for Sentinel.**
- Challenge dossier contains only §01 (description) and §05 (flag box) — no technical hints.
  Organizers confirmed no additional info.

## 8. Conclusion

Everything derivable is correct and verified; the proof's exact `(info, message)` is **not
obtainable from any shipped artifact**, the gateway permits one guess per connection (no brute
force), and it is not bypassable. ~100 reasonable constructions — including the textbook-correct
handshake and the author's own `SHA256(secret‖nonce)` style — are all rejected.

**Strongest hypothesis:** this challenge is **mis-deployed/broken server-side**, like **ChainVault**
(same KumoSec family, also 0-solve, *removed from the CTF for server issues* per commit
`149ac27`). SENTINEL shows the same signature: 0 global solves and rejection of even the canonical
implementation — which a correct server should accept.

## 9. How to finish (the one missing piece)

The entire client is built and verified; only the proof construction is unknown. Either unlocks it
**in a single connection**:
1. The **gateway server binary / source / container image**, or
2. The **exact proof definition** (what `HMAC(k_hmac, ·)` covers; the HKDF `info`/salt).

Recommended action: report to organizers with the evidence above (canonical + ~100 variants
rejected; same symptom as the pulled ChainVault) and request verification of the gateway's auth
deployment or the proof spec.

## 10. Reproduce

```bash
cd sentinel
python3 -m venv .venv && ./.venv/bin/pip install pycryptodome   # or use any env with pycryptodome
./.venv/bin/python solve_sentinel.py diag       # dump the raw CHALLENGE frame (1 connection)
./.venv/bin/python solve_sentinel.py 0 N        # try candidates #0..N-1, one per connection
```
`solve_sentinel.py` holds the verified framing/HKDF/CRC client and a swappable `candidates()`
generator; drop the correct construction in and it auto-pulls + AES-128-CTR-decrypts CONFIG_DATA
(tries IV ∈ {nonce, zero, prepended}) and prints the `Lun4R{…}` flag.

## 11. Files

`sentinel-agent` (stub binary) · `README_challenge.txt` · `gateway_landing.html` (SNTL/2.0 spec) ·
`REVERSE_sentinel_player.tar.gz` · `analysis/` (disasm/strings/rodata) · `solve_sentinel.py`
(client) · `ANALYSIS.md` (RE detail) · `PROGRESS.md` (timeline) · `MEMORY.md` (fact index).
