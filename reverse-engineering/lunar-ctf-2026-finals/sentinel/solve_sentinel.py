#!/usr/bin/env python3
"""
SENTINEL (LNR-06) — SNTL/2.0 client.

Run (toolkit venv has pycryptodome):
    ~/.ctf-tools/venv/bin/python solve_sentinel.py [start_index] [num_connections]

CONFIRMED (offline + live):
  - Binary is a pure STUB: parses args, deobfuscates the seed, connects, close()s. No crypto
    inside. .rodata carries ONLY the seed (XOR @0x2560 ^ @0x2520) + UI strings. So the auth
    formula has NO offline oracle and must be confirmed against the gateway.
  - Frame: SNTL(4)|ver=0x02|cmd|flags|rsv|len(2BE)|CRC16-CCITT-FALSE(header[0:10])(2BE)|payload,
    client frames padded to 76 bytes; CRC covers the 10-byte header only.
  - Phase 1 HELO(0x01,team) -> CHALLENGE(0x02, 16-byte nonce) WORKS  => framing is correct, so
    the ONLY unknown is the Phase-3 proof formula.
  - Seed: KumoSec-Sentinel-v2.3-KeyDerivation-Seed-2026

ALREADY BURNED (do not repeat): with HKDF(ikm=seed, salt=nonce), k_enc=okm[:16], k_hmac=okm[16:]:
    info=""         -> HMAC(k_hmac, nonce)[32]  REJECTED
    info=""         -> HMAC(k_hmac, nonce)[16]  REJECTED
    info="SNTL/2.0" -> HMAC(k_hmac, nonce)[32]  REJECTED

Server self-limits to ~2 auth guesses per connection (nonce is per-connection), so this tries
TRIES_PER_CONN candidates per connection and opens a fresh connection for the next pair, up to
`num_connections`. Stops immediately on AUTH_OK. Resumable via `start_index`.
"""
import socket
import struct
import hmac
import hashlib
import sys
from Crypto.Cipher import AES
from Crypto.Util import Counter

HOST, PORT = "103.49.131.90", 9000
TEAM = b"LNR-93BED1401D"
SEED = b"KumoSec-Sentinel-v2.3-KeyDerivation-Seed-2026"
# Server closes the socket after ONE bad auth proof, so one real guess per connection.
TRIES_PER_CONN = 1


# ---------------------------------------------------------------- framing
def crc16(d: bytes, init: int = 0xFFFF) -> int:
    c = init
    for b in d:
        c ^= b << 8
        for _ in range(8):
            c = ((c << 1) ^ 0x1021) & 0xFFFF if c & 0x8000 else (c << 1) & 0xFFFF
    return c


def mk(cmd: int, payload: bytes, flags: int = 0, rsv: int = 0) -> bytes:
    hdr = b"SNTL" + bytes([2, cmd, flags, rsv]) + struct.pack(">H", len(payload))
    f = hdr + struct.pack(">H", crc16(hdr)) + payload
    return f + b"\x00" * (76 - len(f)) if len(f) < 76 else f


def rd(s: socket.socket):
    """Small-frame reader for the handshake (CHALLENGE / AUTH reply)."""
    s.settimeout(4)
    try:
        b = s.recv(512)
    except socket.timeout:
        return None, b"", b""
    if not b:
        return "CLOSED", b"", b""
    if len(b) < 12:
        return None, b, b
    ln = struct.unpack(">H", b[8:10])[0]
    return b[5], b[12:12 + ln], b


def read_all(s: socket.socket, first_to: float = 4.0, idle_to: float = 0.8) -> bytes:
    """Accumulate a possibly-large frame (CONFIG_DATA) until the socket goes idle."""
    s.settimeout(first_to)
    chunks = []
    try:
        while True:
            c = s.recv(4096)
            if not c:
                break
            chunks.append(c)
            s.settimeout(idle_to)
    except socket.timeout:
        pass
    return b"".join(chunks)


# ---------------------------------------------------------------- crypto
def _extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt or b"\x00" * 32, ikm, hashlib.sha256).digest()


def _expand(prk: bytes, info: bytes, n: int) -> bytes:
    okm, t, i = b"", b"", 1
    while len(okm) < n:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
        i += 1
    return okm[:n]


def hkdf(ikm: bytes, salt: bytes, info: bytes, n: int = 32) -> bytes:
    return _expand(_extract(salt, ikm), info, n)


def candidates(nonce: bytes):
    """Ordered (label, k_enc, k_hmac, payload, flags).

    Round-10: RAW SHA256(secret||msg) "MAC" — the author's signature move (Nightwatch used
    SHA256(secret||payload) and CALLED it HMAC). All prior 76 attempts used real hmac.new(); this
    class was never tried. Proof = bare 32B SHA256(...). k_enc for phase-4 = canonical HKDF[:16].
    """
    N, T, P = nonce, TEAM, b"SNTL/2.0"

    def S(*parts):
        h = hashlib.sha256()
        for p in parts:
            h.update(p)
        return h.digest()

    okm = hkdf(SEED, N, b"")               # canonical HKDF
    ke, kh = okm[:16], okm[16:32]
    okm2 = hkdf(SEED, b"", N)              # idiom-2
    kh2 = okm2[16:32]

    specs = [
        ("SHA256(seed || nonce)", ke, kh, S(SEED, N), 0x00),
        ("SHA256(k_hmac || nonce)  [canon kh]", ke, kh, S(kh, N), 0x00),
        ("SHA256(nonce || seed)", ke, kh, S(N, SEED), 0x00),
        ("SHA256(nonce || k_hmac)  [canon kh]", ke, kh, S(N, kh), 0x00),
        ("SHA256(seed || nonce || seed)", ke, kh, S(SEED, N, SEED), 0x00),
        ("SHA256(k_hmac || nonce || k_hmac)", ke, kh, S(kh, N, kh), 0x00),
        ("SHA256(k_enc || nonce)", ke, kh, S(ke, N), 0x00),
        ("SHA256(okm32 || nonce)", ke, kh, S(okm, N), 0x00),
        ("SHA256(k_hmac || nonce)  [idiom2 kh]", okm2[:16], kh2, S(kh2, N), 0x00),
        ("SHA256(seed || nonce || team)", ke, kh, S(SEED, N, T), 0x00),
    ]
    return specs


def try_phase4(s: socket.socket, nonce: bytes, ke: bytes, kh: bytes) -> bool:
    """On AUTH_OK: pull config and brute the AES-128-CTR IV/key offline (free)."""
    s.sendall(mk(0x10, b""))
    raw = read_all(s)
    if len(raw) < 12 or raw[:4] != b"SNTL":
        print("    [phase4] unexpected CONFIG reply:", raw[:40])
        return False
    ln = struct.unpack(">H", raw[8:10])[0]
    enc = raw[12:12 + ln]
    print(f"    [phase4] CONFIG_DATA cmd=0x{raw[5]:02x} len={ln} ({len(enc)} recvd)")

    def ctr(key, iv_int):
        return AES.new(key, AES.MODE_CTR,
                       counter=Counter.new(128, initial_value=iv_int))

    attempts = []
    for kname, key in (("k_enc", ke), ("k_hmac", kh)):
        attempts.append((f"{kname} IV=nonce", key, enc, int.from_bytes(nonce, "big")))
        attempts.append((f"{kname} IV=zero", key, enc, 0))
        if len(enc) > 16:
            attempts.append((f"{kname} IV=prepended", key, enc[16:],
                             int.from_bytes(enc[:16], "big")))
    for label, key, ct, ivint in attempts:
        dec = ctr(key, ivint).decrypt(ct)
        print(f"    [phase4] {label}: {dec[:64]!r}")
        if b"Lun4R" in dec:
            flag = dec[dec.index(b"Lun4R"):].split(b"}")[0] + b"}"
            print("\n[FLAG]", flag.decode(errors="replace"))
            print("[full]", dec.decode(errors="replace"))
            return True
    return False


def run_connection(start: int, cands) -> str:
    """One connection: HELO, then up to TRIES_PER_CONN candidates. Returns status."""
    s = socket.create_connection((HOST, PORT), timeout=6)
    try:
        s.sendall(mk(0x01, TEAM))
        cmd, pl, _ = rd(s)
        if cmd != 0x02:
            print(f"[!] HELO failed: cmd={cmd} pl={pl[:40]!r}")
            return "helo_fail"
        nonce = pl[:16]
        print(f"[+] nonce={nonce.hex()}")
        live = candidates(nonce)  # recompute proofs for THIS nonce
        for idx in range(start, min(start + TRIES_PER_CONN, len(live))):
            label, ke, kh, payload, flags = live[idx]
            s.sendall(mk(0x03, payload, flags=flags))
            c, p, _ = rd(s)
            if c == "CLOSED":
                print(f"    #{idx} {label} -> connection closed by server")
                return "closed"
            if c == 0x04:
                print(f"[+] AUTH_OK  #{idx}: {label}")
                ok = try_phase4(s, nonce, ke, kh)
                return "flag" if ok else "auth_ok_no_flag"
            print(f"    #{idx} {label} -> 0x{c:02x} {p[:48]!r}")
        return "exhausted_pair"
    finally:
        s.close()


def diag():
    """Cheap intel: HELO, then dump the COMPLETE raw CHALLENGE frame (no auth guess spent)."""
    s = socket.create_connection((HOST, PORT), timeout=6)
    try:
        s.sendall(mk(0x01, TEAM))
        raw = read_all(s)
        print(f"[diag] raw CHALLENGE frame: {len(raw)} bytes")
        print("  hex:", raw.hex())
        if len(raw) >= 12 and raw[:4] == b"SNTL":
            ver, cmd, flags, rsv = raw[4], raw[5], raw[6], raw[7]
            ln = struct.unpack(">H", raw[8:10])[0]
            crc = struct.unpack(">H", raw[10:12])[0]
            payload = raw[12:12 + ln]
            print(f"  ver=0x{ver:02x} cmd=0x{cmd:02x} flags=0x{flags:02x} "
                  f"rsv=0x{rsv:02x} len={ln} crc=0x{crc:04x}")
            print(f"  crc_ok={crc == crc16(raw[0:10])}")
            print(f"  payload({len(payload)}B): {payload.hex()}")
            print(f"  trailing after declared payload: {raw[12 + ln:].hex()!r}")
        else:
            print("  (not an SNTL frame)")
    finally:
        s.close()


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "diag":
        diag()
        return
    start = int(sys.argv[1]) if len(sys.argv) > 1 else 0
    conns = int(sys.argv[2]) if len(sys.argv) > 2 else 1
    cands = candidates(b"\x00" * 16)  # just for the count/labels
    print(f"[*] {len(cands)} ranked candidates total. Plan: {conns} connection(s), "
          f"starting at #{start} ({TRIES_PER_CONN}/conn).")
    for label, *_ in cands:
        print("      -", label)
    print()
    idx = start
    for conn in range(conns):
        if idx >= len(cands):
            print("[*] ran out of candidates.")
            break
        print(f"=== connection {conn + 1}/{conns} : candidates #{idx}..#{idx + TRIES_PER_CONN - 1} ===")
        status = run_connection(idx, cands)
        if status == "flag":
            return
        if status == "helo_fail":
            print("[!] stopping: HELO failed.")
            return
        idx += TRIES_PER_CONN
    print(f"\n[*] done. No AUTH_OK yet. Next resume index: {idx}")


if __name__ == "__main__":
    main()
