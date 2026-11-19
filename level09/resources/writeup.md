# Snowcrash — Level 09

**Objective:** escalate from `level09` to `flag09`.
**Class:** hardcoded secret in a setuid binary, recoverable via `strings`.

---

## 1. Reconnaissance

```bash
id
# uid=1010(level09) gid=1012(level09) groups=...,4008(da5id)
```

New group `da5id`. Find what it owns:

```bash
find / -group da5id 2>/dev/null
# /opt/snowcrash/level09/da5id
```

```bash
ls -la /opt/snowcrash/level09/
# -r-sr-x--- 1 flag09 da5id ... da5id
```

`da5id` is setuid **flag09**, group-executable by `da5id` (which we're in). Running it runs as `flag09`.

```bash
file da5id
# setuid ELF 64-bit LSB pie executable, not stripped
```

**Not stripped** means the symbol table is intact — helpful for disassembly, but for a challenge like this we don't even need it.

---

## 2. Behaviour

```bash
./da5id
# Usage: ./da5id <token>

./da5id 1
# Token does not meet policy requirements.

./da5id hhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhh
# Token format error.
```

The program takes a token argument and validates it against some policy. Short tokens fail policy; very long tokens fail "format" (likely a length ceiling in the format check).

---

## 3. Vulnerability — hardcoded secret in `.rodata`

`strings` reveals every printable run in the binary's data. Any program that validates a *secret* hardcoded in the binary will show it here:

```bash
strings da5id
```

Relevant excerpts:

```
Usage: %s <token>
Rate limit exceeded.
Token format error.
checking byte %d...
accepted fp=%08x
rejected at byte %u fp=%08x
Invalid token.
/home/flag09/.flag
access error
TOKEN ACCEPTED.
Flag: %s
Token contains non-printable characters.
Token does not meet policy requirements.
Iheartpwnage                     ← the secret
```

`Iheartpwnage` appears **between** the user-facing error strings and the compiler metadata — exactly where a hardcoded string constant lands in `.rodata`.

Two additional confirmations:

- The format/policy messages say `checking byte %d...`, meaning the validator loops byte-by-byte. A 12-character string (`Iheartpwnage`) will produce `checking byte 0` through `checking byte 11`.
- The success message is `Flag: %s` with the flag read from `/home/flag09/.flag`.

---

## 4. Exploit

```bash
./da5id Iheartpwnage
```

Output:

```
checking byte 0...
checking byte 1...
...
checking byte 11...
TOKEN ACCEPTED.
Flag: s19q3m3u4toaequegh8ahpicel
```

The flag is `/home/flag09/.flag`, read by the setuid binary running as `flag09`.

---

## 5. Why this works

- The token check compares against a **compile-time constant** stored in the binary's read-only data.
- `strings` (or `objdump -s -j .rodata`, or `grep -a`, or a disassembler) recovers that constant.
- Any user who can execute the binary can also read it, so the "secret" is not secret — it's a string constant that ships with the program.
- The setuid bit elevates the execution context to `flag09`, so the successful branch reads the flag and prints it to us.

This is a **secret-in-binary** vulnerability, not a memory corruption. No exploit code, no crash, no reverse-engineering of control flow required — `strings` is enough.

---

## 6. Root cause

The authentication secret is embedded in the client-side binary. Anything the client can read, the attacker can read. There is no cryptographic protection — the token is compared as a plaintext string.

---

## 7. Remediation

- **Never embed secrets in executables distributed to untrusted users.** A binary is not a place to keep a password.
- If a binary must check a secret, do it against a **hash** stored server-side, and rate-limit / lock out after failures. Even then, an offline attacker can brute-force a low-entropy string like `Iheartpwnage`.
- Prefer **public-key** challenge-response: the binary holds only a public key; the secret is a private key that never leaves the server.
- Strip symbols and hide constants where possible (defense in depth), but do not rely on this — `strings` defeats it trivially.
- Do not read the flag from a path the binary can open *because it's setuid*. If the flag needs to be protected, protect it with filesystem permissions and don't pass it through an attacker-controllable program.

---

## 8. Lessons

- **`strings` is step one on any unknown binary.** For challenges that check a password, a token, or a key — 90% of the time the answer is in `.rodata`.
- **"Not stripped" is a hint, not the point.** Even a stripped binary exposes its string constants; the symbol table is just easier to navigate.
- **Prior knowledge is a shortcut, not a substitute.** Recognizing `Iheartpwnage` from another CTF is fine, but the writeup must show the *reproducible* path — `strings` — so the exploit is auditable and general.
- **Setuid binaries that check a secret against a hardcoded string are always trivially broken.** The privilege boundary (setuid to `flag09`) doesn't protect the secret, because the secret is in the program itself, not behind any access control.