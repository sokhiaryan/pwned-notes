---
title: "KumoSec AD — Loose Ends / Signal Noise / INC-2026-0918"
ctf: "Lun4R CTF 2026 Finals"
date: 2026-10-04
category: active-directory
difficulty: hard
status: foothold + authenticated recon (flags not captured)
flag_format: "Lun4R{...}"
author: "sokhiaryan"
---

# KumoSec AD — Loose Ends / Signal Noise / INC-2026-0918

> **Status: foothold + authenticated recon.** The three linked AD/DFIR challenges share one
> 30-team domain. I obtained a valid domain foothold and completed authenticated enumeration, but
> did **not** capture the per-challenge flags within the finals window. Raw session notes:
> [`recon-notes.md`](recon-notes.md).

## The three challenges

Shared AD `lunar.ctf.kumosec` (NetBIOS `LUNAR`), reached over the team06 WireGuard VPN.

| ID | Name | Cat | Pts | Hook |
|----|------|-----|-----|------|
| LNR-17 | Loose Ends    | AD, WEB  | 300 | "API team wrapped a deployment. Not everything gets cleaned up after a release." |
| LNR-19 | Signal Noise  | AD, DFIR | 400 | "Not everything important is. Not everything irrelevant is, either." |
| LNR-20 | INC-2026-0918 | AD, DFIR | 500 | "Incident logged. Follow the evidence, recover what KumoSec missed." |

### Live hosts (all Server 2022, Build 20348)

| Host | IP | Role | Notable |
|------|-----|------|---------|
| DC01   | 10.10.10.10 | Domain Controller | SMB signing **required**; 53/88/135/139/389/445/464/593/636/3268/3269/5985/9389 |
| APP01  | 10.10.10.11 | IIS10 / ASP.NET member | 80/135/139/445/5985; signing **not** required |
| FILE01 | 10.10.10.13 | File server | 135/139/445/5985 |
| JUMP01 | 10.10.10.14 | Jump box | 135/139/445/5985 |

## Foothold — credential reuse ("the loose end")

Entry was genuinely hard: unauthenticated the domain gave up nothing — SMB null/guest, LDAP anon
bind, AXFR all disabled; no AS-REP-roastable accounts; **lockout disabled** (so spraying was clearly
the intended path), yet themed sprays (736 variants), top-10k, top-100k, and per-account mutations
across all `svc_*` accounts produced **zero** hits. APP01:80 was bare default IIS (222k-request
ffuf found only `aspnet_client` + `iisstart.htm`).

The break was **credential reuse**: the **CTFd team credentials double as a domain account**.

```
team06 : JxZgmg_L9E   ->   valid AD account in OU=Participants (team01..team30)
```

That *is* the "loose end" — the deployment handoff reused the team portal password as a directory
credential and never rotated it. (Expired event credential, kept for the writeup.)

## Authenticated recon (as `team06`)

With a valid low-priv domain cred:

- **LDAP dump:** 86 principals — ~40 humans (`first.last`), `team01..team30`, and `svc_*` service
  accounts. All strong passwords.
- **Kerberoast:** 11 SPN accounts (`svc_api/web/deploy/sql/backup/monitor/release/reporting/`
  `automation/helpdesk/inventory`), RC4 (etype 23) hashes. Ran rockyou + rule sets (best66,
  d3ad0ne, dive, OneRuleToRuleThemAll-style) — **0 cracked** (see `hc1.log`, all `*.pot` empty).
- **More hosts via LDAP:** `CA01$` (CA object; active CA `KumoSec-RootCA` on DC01, web-enroll off,
  no ESC), `MGMT01$` (10.10.10.12, filtered), and enabled targets **`SNX01$`** (pwdlastset=0) and
  **`KUMOPWN$`** — the likely Signal Noise / INC boxes.
- **ACL finding:** **team15** holds `WriteAccountRestrictions` + `AllExtendedRights` over `SNX01`
  and `KUMOPWN` (an RBCD-style edge) — team06 has no such rights. Suggests each team earns its
  control edge from another challenge.

### Loose Ends (WEB) progress

- Vhost **`api.app01.lunar.ctf.kumosec`** on APP01:80 = KumoSec API, **Windows/NTLM auth**; `team06`
  authenticates. `GET /users` (28 users+roles), `GET /deployments` (7 deployments:
  LUNAR-API/WEB/OPS/SOC/DATA/EDGE/DEV across APP01/MGMT01/FILE01). No SQLi, no write/RCE, static
  enumeration only.
- FILE01 share **`KumoSecDeployments`** exists but `team06` can't list it — needs group
  `GG-FILE-Servers` (members: `svc_backup` / `svc_inventory` / `svc_reporting`).

**Open target for Loose Ends:** read `KumoSecDeployments` on FILE01. Blocked on a privesc path to
one of those service accounts (their Kerberoast hashes did not crack).

## What stalled

- Service-account Kerberoast hashes never cracked → no obvious privesc from `team06`.
- Signal Noise / INC-2026-0918 are DFIR on `SNX01` / `KUMOPWN`, reachable only *after* gaining the
  per-team control edge (held by team15 in the snapshot we saw) or a FILE/service foothold.

Kept here as a reference on the real win — **spotting the portal↔directory credential reuse** as the
intended foothold after unauthenticated attacks are exhausted — plus the authenticated enumeration
map for the KumoSec domain.
