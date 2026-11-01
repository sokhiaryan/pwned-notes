# Lunar CTF 2026 — Finals

On-site/attack-defense style finals for **Lun4R CTF 2026**, run by **KumoSec** under the
`*.kumosec.rootriet.in` infrastructure (core host `103.49.131.90`). Flag format `Lun4R{...}`.
Team **team06** / "Piedd Piper" (engagement code `LNR-93BED1401D`).

> All credentials, private keys, VPN configs, IPs and hostnames referenced below are **ephemeral
> finals artifacts from a concluded event** and no longer live. They are kept here only to make the
> writeups reproducible as notes.

## Results

| Challenge | Category | Status | Flag |
|-----------|----------|--------|------|
| [havoc — Havok's Cosmic Rings](pwn/lunar-ctf-2026-finals/havoc/writeup.md) | pwn | ✅ Solved | `Lun4R{c0sm1c_b4rr13rs_br0k3n_4nd_h4v0k_s3cur3d}` |
| [Silent Telemetry](web/lunar-ctf-2026-finals/silent-telemetry/writeup.md) | web | ✅ Solved | `Lun4R{d3v1c3_0wn3d}` |
| [Nightwatch / ChainVault](blockchain/lunar-ctf-2026-finals/nightwatch/writeup.md) | blockchain | ✅ Solved | dynamic per-team (`/api/v1/vault/flag`) |
| [Sentinel](reverse-engineering/lunar-ctf-2026-finals/sentinel/writeup.md) | reverse | ⚠️ Protocol fully reversed, Phase-3 auth blocked | — |
| [Mooncache](hardware/lunar-ctf-2026-finals/mooncache/writeup.md) | hardware | ⚠️ Approach only (transient execution) | — |
| [KumoSec AD](active-directory/lunar-ctf-2026-finals/kumosec/writeup.md) | AD / DFIR | ⚠️ Foothold + authed recon; flags not captured | — |

## Highlights

- **havoc** — a `short`-truncation OOB read leaked the whole PIE image (recovering the binary with
  no file given), then a canary-less 48-into-32 stack overflow pivoted into an **ORW ROP** chain
  past a seccomp filter that only blocked `execve`.
- **Silent Telemetry** — a `/debug` endpoint that *says* it's disabled, re-enabled with
  `?debug=true`, dumping the flag in JSON.
- **Nightwatch / ChainVault** — chained an **unlocked-owner RPC proxy** (register our own contract
  as an auditor with no key) with a classic **CEI-violating reentrancy** drain in `settleClaim()`,
  flipping `isSolved` on-chain to release the flag.
- **Sentinel** — fully reversed the `SNTL/2.0` wire protocol and client seed from a stripped stub
  binary; the Phase-3 HMAC proof was unobtainable from any shipped artifact (0 global solves,
  same symptom as the pulled ChainVault — suspected server-side mis-deployment).

See each challenge folder for the full writeup, exploit scripts and artifacts.
