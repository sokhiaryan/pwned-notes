# Document Flow Optimizer — Writeup (in progress)

## Target summary

- Flask app (`app/main.py`) + `app/converter.py`: hardened wrapper, no command/arg
  injection. `subprocess.Popen(["/app/tools/html2pdf", url, out.pdf, "--cache", cachedir], ...)`
  with `preexec_fn` applying rlimits (CORE=0, CPU=35s, AS=100MB, FSIZE, NOFILE=256,
  NPROC=64). Both the Flask process and the `html2pdf` child run as uid 10001 `app`
  (Dockerfile does `USER app` before `gunicorn` starts — no separate priv-drop step).
  URL scheme is restricted to `http`/`https` (`converter.validate_url`).
- `tools/html2pdf`: PlutoBook 0.19.0 (github.com/plutoprint/plutobook) example
  renderer. ELF 64-bit PIE, x86-64, dynamically linked, stripped (`.symtab` gone),
  BuildID present. `Features: Curl TurboJPEG WebP`. Despite stripping, hundreds of
  demangled C++ RTTI/typeinfo strings survive in `.rodata` (visible via `strings`),
  plus 394 dynamic symbols (`nm -D`) — big help for future reversing.
- `/flag.txt` root:root 0400. `/readflag please` is setuid-root, trivial
  (`setuid(0); setgid(0); fopen("/flag.txt")`).
- **Only path to the flag: memory corruption in `html2pdf` → code exec as `app` →
  run `/readflag please`.**
- CLI: `html2pdf <input> <output> [options]`. `--cache <dir>` required by the
  wrapper's invocation. Input can be a URL; **plain local paths and `file://` are
  rejected by the binary's own fetcher** ("Unsupported protocol") even when invoked
  directly outside the Flask wrapper — so the earlier assumption that `file://` is
  supported for the top-level input does not hold. (Not yet tested whether `file://`
  works for *embedded* sub-resources referenced from an http(s)-fetched page —
  worth a quick check later, but low priority since the real `/convert` endpoint
  only accepts http/https anyway.)

## Exfil insight (unchanged, still the plan)

`main.py`'s `/convert` always `send_file()`s whatever ends up at `job_dir/output.pdf`,
which is literally `argv[2]` passed to `html2pdf`. Once we have code execution, the
cleanest exfil is: run `/readflag please` and overwrite `output_path` with its
stdout before the process exits 0. Flask hands it back as the HTTP response to our
own `/convert` POST — no outbound listener/egress needed. "Delivery" is also just
"host the exploit page publicly, POST its URL to `/convert`" since that's the app's
built-in function.

## Local environment status

- Host: Apple Silicon Mac (arm64), Docker Desktop 29.4.0, daemon started manually
  (`open -a Docker`; took ~110s to come up).
- Built `dfo:target` — the provided `Dockerfile` unmodified, `--platform=linux/amd64`,
  as the byte-identical reference (Debian bookworm library versions).
- Built `dfo:debug` on top (separate `Dockerfile.debug`, root layer before dropping
  back down) adding `gdb file strace ltrace binutils procps curl netcat-traditional
  python3-pip`, then `pip install --break-system-packages pwntools pillow`.
  `dfo:target` itself is untouched, kept as the clean reference.
- Fast local iteration loop: generated a genuine benign progressive JPEG with
  Pillow (`progressive=True`, verified `0xFFC2` SOF2 marker present in the file),
  built a tiny test HTML embedding it, served both over a `python3 -m http.server`
  running *inside* the same container (`--bind 0.0.0.0`, needs ~3s to come up under
  emulation before it's reachable), and ran
  `/app/tools/html2pdf http://127.0.0.1:8000/test.html /work/out.pdf --cache /work/.cache`
  directly — produced a valid `PDF document, version 1.5, 1 pages`. Baseline confirmed.

## IMPORTANT FINDING: cross-arch debugging is broken in this setup

Tried to get `html2pdf` under live `gdb` inside the `dfo:debug` container
(`--platform=linux/amd64` on an arm64 host → runs via Docker Desktop's transparent
binfmt_misc QEMU user-mode emulation). Two approaches, both failed:

1. **Live ptrace attach** (`gdb -batch -ex starti --args html2pdf ...`):
   ```
   warning: Could not trace the inferior process.
   warning: ptrace: Function not implemented
   During startup program exited with code 127.
   ```
   `ptrace()` is not implemented for guest processes under this binfmt-transparent
   QEMU setup. `/usr/bin/qemu-x86_64` is not even a real file inside the container
   (it's injected by the Docker Desktop VM's binfmt_misc registration from outside
   the container's rootfs — `ls`/`file` on it report "No such file or directory"),
   so we can't fall back to explicitly invoking `qemu-x86_64 -g <port>` for a
   gdbstub either, at least not without extra plumbing.

2. **Postmortem core-dump analysis** (crash a process, `ulimit -c unlimited`,
   `gdb <binary> <corefile>`): the *mechanism* works — `ulimit -c unlimited` +
   crashing `python3 -c "import ctypes; ctypes.string_at(0)"` inside the container
   does produce `Segmentation fault (core dumped)` and a `core` file (155MB for a
   python3 core, plausible). But the resulting core file is **not usable** — gdb
   reports:
   ```
   warning: malformed note - filename area is too big
   warning: Can't open file ... during file-backed mapping note processing
   warning: Selected architecture i386:x86-64 is not compatible with reported
            target architecture i386
   warning: Couldn't find general-purpose registers in core file.
   #0  <unavailable> in ?? ()
   ```
   QEMU linux-user's own core-dump writer is a known-incomplete implementation
   (broken `NT_FILE` note, wrong reported machine type) — this is a QEMU
   limitation, not something we can fix by changing gdb flags.

**Conclusion: neither live gdb nor core-dump postmortem analysis of the real
x86-64 `html2pdf` binary is currently possible on this Apple Silicon host via
Docker Desktop.** We can still run the binary and observe black-box behavior
(exit codes — 139 = SIGSEGV, valid PDF or not, timing), which is enough to detect
*that* something crashed, but not to see registers/backtraces/memory to root-cause
*why*.

This needs a decision on how to proceed (see chat) — options are: get a native
x86-64 Linux box (VPS/cloud VM) for real gdb work against the exact shipped
binary; do the bug-hunting/fuzzing phase against a natively-built (arm64) copy of
upstream PlutoBook 0.19.0 instead (full gdb/ASan support, no emulation, likely
reproduces a portable C++ logic bug just as well) and only reach for x86-64 once
we need exact addresses/ROP gadgets for the real weaponization; or stay black-box
(crash/no-crash signal only) on the emulated binary for now.
