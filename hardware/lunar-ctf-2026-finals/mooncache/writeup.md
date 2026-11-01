---
title: "Mooncache — LUN4R-MU Chrono Engine"
ctf: "Lun4R CTF 2026 Finals"
date: 2026-10-03
category: hardware
difficulty: hard
status: approach-only (not captured)
flag_format: "Lun4R{...}"
author: "sokhiaryan"
---

# Mooncache — LUN4R-MU Chrono Engine

> **Status: approach / notes only.** This challenge was not captured during the event. These are my
> analysis notes on what the challenge is and the intended attack, kept for reference.

## Challenge

> A prototype **LUN4R-MU Chrono Engine** has been recovered from an abandoned research system. The
> processor appears to have an unusual approach to handling protected memory: an operation can fail
> architecturally, yet something about the operation may still persist.
>
> `nc 103.49.131.90 31337`

## Reading the flavor text

The description is a near-literal statement of a **transient / speculative execution side channel**
(Meltdown/Spectre family):

- *"an operation can fail architecturally"* → a load that raises a fault / is squashed (e.g. a
  protected-memory read that the architecture rejects).
- *"yet something about the operation may still persist"* → the **microarchitectural** side effect
  survives the squash: the speculatively-accessed byte has already been used to index a probe array,
  leaving a measurable footprint in the **cache**.

"Mooncache" / "Chrono Engine" = **cache** + **timing**. This is a **FLUSH+RELOAD-style covert
channel**: the secret byte is read transiently, used to touch `probe[secret * STRIDE]`, and then
recovered by timing which cache line in `probe[]` reloads fast.

## Intended approach

The service almost certainly simulates (or exposes) a tiny CPU with:

1. A protected region holding the flag that a normal (architectural) read cannot return.
2. A transient window where a faulting/mis-speculated read of that region still influences a
   cache-backed probe buffer.

Plan:

1. Enumerate the service's instruction / command interface from the `nc` prompt (opcodes for
   read, flush, timed-reload, etc.).
2. Build the Meltdown primitive: `flush(probe)` → transient `tmp = secret_byte; touch(probe[tmp*STRIDE])`
   → `for i in 256: time reload(probe[i*STRIDE])`; the fast line index = the secret byte.
3. Repeat per offset to leak the flag byte-by-byte, with repetition + majority vote to beat noise.

## Why it wasn't captured

Ran out of time to fully map the service's opcode/timing interface during the finals window. Left
here as a reference on recognizing a transient-execution challenge from its description and the
FLUSH+RELOAD recovery pattern.
