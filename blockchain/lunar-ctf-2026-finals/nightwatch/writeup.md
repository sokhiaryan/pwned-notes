---
title: "Nightwatch — ChainVault"
ctf: "Lun4R CTF 2026 Finals // KumoSec Red Team Operations"
date: 2026-10-03
category: blockchain
difficulty: medium-hard
flag_format: "Lun4R{...}"
author: "sokhiaryan"
---

# Nightwatch — ChainVault

## Summary

`nightwatch.kumosec.rootriet.in` hosts **KumoSec ChainVault**, a "bug bounty escrow vault" on a
private chain (chain_id `1337`) exposed through a web3 JSON-RPC proxy at `/chain/rpc`. The goal is
to flip the on-chain `isSolved` flag, which the API then reports via `GET /api/v1/vault/flag`.

Two bugs chained together:

1. **Owner impersonation via an unlocked node account.** The RPC proxy forwards
   `eth_accounts` / `eth_sendTransaction` straight to the underlying Ganache node, where the
   deployer/owner account is **unlocked**. We can send transactions *from the owner* with no
   private key, letting us call the `onlyOwner` function `AuditorRegistry.registerAuditor()` and
   register **our own attacker contract** as a trusted auditor.
2. **Reentrancy (CEI violation) in `ChainVault.settleClaim()`.** The payout is sent with a raw
   `.call{value}("")` **before** `pendingClaims[msg.sender]` is zeroed, so the attacker contract's
   `receive()` re-enters `settleClaim()` and drains the pre-funded balance down to
   `emergencyThreshold`, which sets `isSolved = true`.

## Recon

`GET /api/v1/vault/info` (from `openapi.json`, title *KumoSec ChainVault* v2.1.0) gives the
deployed addresses and endpoints:

```json
{
  "team_id": "LNR-93BED1401D",
  "network": { "chain_id": 1337, "rpc_endpoint": "/chain/rpc" },
  "contracts": {
    "auditor_registry": "0x614BB70b9AA56802036d1BaC0b667F4C45619595",
    "chain_vault":      "0xD4543Fe1ded1637768516A3Ef35614F91F715370"
  },
  "deployer": "0x90F8bf6A479f320ead074411a4B0e7944Ea8c9C1"
}
```

Useful API routes: `/api/v1/vault/info`, `/api/v1/vault/wallet` (hands you a funded throwaway
player wallet + key), `/api/v1/vault/reset` (re-provisions a fresh instance), and
`/api/v1/vault/flag` (returns the flag once `isSolved` is true). Contract sources are served from
`/contracts/{filename}` — see [`ChainVault.sol`](ChainVault.sol) and
[`AuditorRegistry.sol`](AuditorRegistry.sol).

The deployer address `0x90F8bf…` is the canonical **Ganache deterministic account #1** — a strong
hint that the node is running with default unlocked accounts behind the proxy.

## Bug 1 — owner impersonation

`AuditorRegistry.registerAuditor()` is `onlyOwner`, and `ChainVault.settleClaim()` is gated by
`auditorRegistry.isAuditor(msg.sender)`. Normally you can't become an auditor. But the proxy
forwards `eth_sendTransaction` to a node where the owner account is unlocked, so a transaction with
`from = OWNER_ADDR` and **no signature** is accepted and executed as the owner:

```python
reg_tx = registry.functions.registerAuditor(attacker_addr).build_transaction({"from": OWNER_ADDR})
reg_tx.pop("gas", None)                 # let the node estimate with its own (owner) account
reg_txh = w3.eth.send_transaction(reg_tx)   # unsigned -> node signs with the unlocked owner key
```

After this, `isAuditor(attacker) == true` and our contract may call `settleClaim()`.

## Bug 2 — reentrancy in `settleClaim()`

The vulnerable function violates checks-effects-interactions — it pays out, *then* updates state:

```solidity
function settleClaim() external onlyAuditor notInEmergency {
    uint256 amount = pendingClaims[msg.sender];
    require(amount > 0, "No pending claim to settle");
    require(address(this).balance >= amount, "Insufficient vault balance");

    (bool success, ) = payable(msg.sender).call{value: amount}("");  // <-- external call first
    require(success, "Payout transfer failed");

    pendingClaims[msg.sender] = 0;      // <-- state updated AFTER the call (too late)
    totalClaimed += amount;
    ...
}
```

Because `pendingClaims[msg.sender]` is still non-zero during the `.call`, the attacker's
`receive()` re-enters `settleClaim()` and is paid again, repeating until the vault balance reaches
`emergencyThreshold` and the contract flips into its solved/emergency state.

## Exploit

Full script: [`exploit.py`](exploit.py) · attacker contract: [`Attacker.sol`](Attacker.sol)
(sanity-check helper: [`check_owner.py`](check_owner.py)).

Flow:

1. Pull a funded player wallet from `/api/v1/vault/wallet` and connect web3 to `/chain/rpc`.
2. Deploy [`Attacker.sol`](Attacker.sol) (constructor takes the vault address), signing with the
   player key.
3. **Owner-impersonate**: `registry.registerAuditor(attacker)` sent `from` the unlocked owner.
4. Call `attacker.run(bountyId, 1 ether)`: it `depositBounty()` → `submitAuditFinding()` →
   `settleClaim()`, and `receive()` re-enters until `address(vault).balance < claimAmount + threshold`.
5. Read `getVaultStatus()` → `solved == true`, `sweep()` the drained ETH back, then
   `GET /api/v1/vault/flag`.

The reentrancy loop in the attacker's `receive()`:

```solidity
receive() external payable {
    if (draining && address(vault).balance >= claimAmount + threshold) {
        vault.settleClaim();   // re-enter before pendingClaims is zeroed
    }
}
```

Observed run:

```
[*] connected, chain_id = 1337
[+] Attacker deployed at 0x...
[+] registered attacker contract as auditor via owner impersonation
    isAuditor(attacker) = True
[+] run() tx status: 1
[*] vault status AFTER: ... solved=True
[+] VAULT SOLVED — sweeping proceeds back to wallet
```

With `isSolved == true`, `GET /api/v1/vault/flag` returns the team's dynamic `Lun4R{...}` flag.

## Flag

Dynamic per team instance — released by `GET /api/v1/vault/flag` once the vault is solved on-chain.
(Per organizer notes the flag was computed server-side as roughly
`HMAC(MASTER_SECRET, TEAM_CODE + CHALLENGE_ID)[:16]`, so it differs per team and is not reproduced
here.)

## Fix

- Apply checks-effects-interactions (zero `pendingClaims` **before** the external call) and/or a
  `nonReentrant` guard.
- Never expose a raw node RPC with unlocked accounts to untrusted clients; the proxy must whitelist
  methods and reject `from` addresses the caller can't prove ownership of.
