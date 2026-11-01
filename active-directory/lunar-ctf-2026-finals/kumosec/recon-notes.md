# KumoSec AD Engagement — LNR-17 / LNR-19 / LNR-20

Three linked challenges, shared AD `lunar.ctf.kumosec`, over team06 VPN (10.10.10.0/24).
Resource = VPN/network ONLY (confirmed: dossiers have only desc+flag; VPN zip is just configs).

| ID | Name | Cat | Pts | Hook |
|----|------|-----|-----|------|
| LNR-17 | LOOSE ENDS   | AD, WEB  | 300 | "API team wrapped a deployment. Not everything gets cleaned up after a release." |
| LNR-19 | SIGNAL NOISE | AD, DFIR | 400 | "Not everything important is. Not everything irrelevant is, either." |
| LNR-20 | INC-2026-0918| AD, DFIR | 500 | "Incident logged. Follow the evidence, recover what KumoSec missed." |

## Hosts (all Server 2022, Build 20348) — only these 4 are live
| Host | IP | Role | Open TCP |
|------|-----|------|----------|
| DC01   | 10.10.10.10 | Domain Controller | 53,88,135,139,389,445,464,593,636,3268,3269,5985,9389 (SMB signing REQUIRED) |
| APP01  | 10.10.10.11 | IIS10/ASP.NET4.0 member | 80,135,139,445,5985 (signing not req) |
| FILE01 | 10.10.10.13 | File server      | 135,139,445,5985 |
| JUMP01 | 10.10.10.14 | Jump box         | 135,139,445,5985 |
- Domain lunar.ctf.kumosec / NetBIOS LUNAR / DC01.lunar.ctf.kumosec. My VPN IP 10.20.0.33.

## Valid accounts (Kerberos-confirmed; others = PRINCIPAL_UNKNOWN)
administrator, svc_api, svc_web, svc_deploy, svc_sql, svc_backup, svc_monitor
- No AS-REP roastable (all require preauth). No human accounts matched first-name enum (convention likely first.last/flast).

## CONSTRAINTS
- Env DROPS aggressive multi-host nmap + rapid DNS (rate-limiter). Scan gently (-T2/3, low parallel). Single-host -T4 ok.
- HTTP on APP01:80 is NOT rate-limited (550 req/s fine).
- Kerberos NOT rate-limited; tolerates ~30 threads (~31/s).
- Account LOCKOUT is DISABLED (sprayed 6+5152 attempts, zero CLIENT_REVOKED on valid accts). => spraying is the intended foothold path.

## Tried / ruled out
- SMB null/guest/anon: all blocked (ACCESS_DENIED / ACCOUNT_DISABLED) on all 4 hosts.
- LDAP anon bind: disabled.
- DNS AXFR: refused. Only dc01/app01 in DNS. Web-port /24 sweep: no other web hosts.
- APP01:80: bare default IIS. 222k-req ffuf (dirs+files+exts) => only aspnet_client + iisstart.htm. No swagger/api/.git/backup/config. trace.axd=403 localOnly. IIS 8.3 tilde enum blocked (uniform 400).
- Kerberos spray themed (736 KumoSec/Lunar/deploy/api variants x7): NO hit, NO lockout.

## IN PROGRESS
- [spray-10k.out] top-10k common pw spray x7 accts, 30 threads (~25-40min). PID check: pgrep tspray.py
- [recon/*allports*] clean full -p- scan of APP01/FILE01/JUMP01 (hidden service check).

## NEXT IF SPRAY FAILS
- Enumerate human users via Kerberos (flast + first.last) -> spray them too.
- Re-examine coercion/relay (member servers signing NOT required) — but L3 VPN blocks LLMNR/NBNS poisoning.
- Reconsider web (POST endpoints / different verb).

## Post-foothold plan (./postcred.sh USER PASS)
LDAP full dump (users/desc/groups) -> Kerberoast svc_* -> FILE01 shares (SIGNAL NOISE evidence) -> JUMP01 (INC-2026-0918). BloodHound if a cred lands.

## UPDATE (session 2) — foothold still blocked after exhaustive unauth attempts
- COMPLETE account list (9): administrator + svc_{api,web,deploy,sql,backup,monitor,release,reporting}. ALL require preauth (no AS-REP roast), ALL strong passwords.
- Sprayed: themed(736) + top-10k + top-100k(partial) + per-acct mutations + author-style pattern(Lunar/Kumosec#Svc!Year, 183k, running) = NO hit.
- Cross-challenge cred reuse (Beacon#AppSvc02!2024, Sup3rS3cur3!, variants) = NO hit.
- Web: APP01:80 ONLY web in entire /24 (gentle P6 curl sweep confirms). Bare IIS. No WebDAV/vhost/tilde/compound-deploy-artifacts.
- No ADCS web, no DNS TXT leftovers, no anon SMB/LDAP, no pre-staged machine accts.
- RPC(135): standard pipes; MS-RPRN present (PrinterBug) + MS-SAMR, but need a cred.
- Teammate (manual AD) also only reached recon — whole team blocked on foothold => genuinely hard entry.
- DFIR challenges (LNR-19/20) have NO downloadable evidence => evidence is on live hosts => foothold mandatory.

## REMAINING IDEAS (not yet done)
- Deep spray still running (author-style pattern). If it hits -> postcred.sh.
- Coercion+relay: members signing NOT required, but no good relay target (single DC w/ signing required, no ADCS). Low prob.
- Possibly an UNSOLVED CTF challenge hands out the lunar AD cred (narrative chain).
- Re-examine if LOOSE ENDS web needs a specific unknown hostname binding / unknown high port (rate-limiter blocks full -p-).

## ★ FOOTHOLD FOUND (session 2) ★
**team06 : JxZgmg_L9E = valid AD account** (CTFd team creds reused as AD creds — THE "loose end"/credential reuse). 30-team SHARED AD (team01-team30 in OU=Participants). Be non-destructive.

### Authenticated recon (as team06)
- 86 users: 40 humans (first.last, roles via API), team01-30, svc_* accounts. All strong passwords (rockyou on 10 Kerberoast hashes = 0 cracked; human default-pw spray = 0).
- Kerberoasted 10 SPN accounts (recon/kerb.txt): svc_api,web,deploy,sql,backup,monitor,release,reporting,automation,helpdesk,inventory. RC4. UNCRACKED.
- MORE hosts via LDAP: CA01$ (CA object, but active CA=KumoSec-RootCA on DC01; web enroll OFF, no ESC), MGMT01$ (10.10.10.12, DOWN/filtered), retired: FILE02$/MGMT-OLD$/DEV-API$ (disabled), svc_edge (disabled), **SNX01$** (enabled,pwdlastset=0) + **KUMOPWN$** (enabled) = likely SIGNAL NOISE + INC target boxes.
- **TEAM15 has WriteAccountRestrictions+AllExtendedRights on SNX01 & KUMOPWN** (RBCD-style). team06 has NO such rights (dacledit confirms). Likely team15's earned artifact OR per-team-earned.
- team06 has NO ACL edges, NO GPO control, NO DCSync. Account Operators EMPTY. No ADCS ESC.

### WEB (LOOSE ENDS) — the API
- Vhost **api.app01.lunar.ctf.kumosec** on APP01:80 = KumoSec API, Windows-auth (NTLM). team06 authenticates OK.
  - GET /  -> {service,server,database:kumosec,status}
  - GET /users -> 28 users+roles (Web/API Dev, DBA, DevOps, SOC, Helpdesk, Cloud Ops)
  - GET /deployments -> 7 deploys (LUNAR-API/WEB/OPS/SOC/DATA/EDGE/DEV; hosts APP01/MGMT01/FILE01)
  - Params ignored (no SQLi), no write/RCE, no other endpoints found. Static enum only.
- app01.lunar.ctf.kumosec = static "KumoSec Internal Portal". lunar-edge-old/edge vhosts = fall through to default.
- FILE01 share **KumoSecDeployments** exists but team06 CANNOT read/list (need GG-FILE-Servers: svc_backup/inventory/reporting).

### TARGET for LOOSE ENDS: read KumoSecDeployments (need GG-FILE-Servers or FILE01 admin). svc passwords uncrackable => privesc path TBD.
