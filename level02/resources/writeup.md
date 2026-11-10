# Level 02 — kourier

Same opening as before — `find / -user flag02` and look at what comes back:

```
/proc/560/...
/sys/fs/cgroup/system.slice/kourier.service/memory.pressure
/tmp/kourier_delivery.tmp
/home/flag02
```

Two things worth noting: the cgroup path names the service (`kourier.service`), and there's a temp file owned by flag02 sitting in `/tmp`. Check the service first:

```
$ systemctl status kourier.service

● kourier.service - Snow Crash level02 — Kourier delivery daemon
     Active: active (running)
   Main PID: 560 (kourier)
      CGroup: └─560 /opt/snowcrash/level02/kourier
```

No password in `ExecStart` this time — the level01 trick doesn't repeat. The binary runs with no arguments.

## Two ways to find the flag

### Path 1 — read the temp file directly

```
$ cat /tmp/kourier_delivery.tmp
qi0mauch9ahksha8b6dfe3p0kq
```

The daemon writes its token to that file at startup and leaves it there. Since the file is world-readable, that's it. Done.

### Path 2 — strings on the binary

If the temp file had been unreadable, `strings` on the binary gives it away just as easily:

```
$ strings /opt/snowcrash/level02/kourier
...
/tmp/kourier_delivery.tmp
open %s: %s
qi0mauch9ahksha8b6dfe3p0kq
write %s: %s
...
```

The credential is sandwiched between the file path it's written to and the error format string for a failed write. The binary opens the tmp file, writes this string to it as a "delivery proof", and that string is compiled into `.rodata` in plaintext. Same root cause as level00.

```
$ su level03
Password: qi0mauch9ahksha8b6dfe3p0kq
level03@snowcrash:~$ id
uid=1004(level03) gid=1006(level03) groups=1006(level03),988(burbclave),1001(levelgroup)
```

---

**Flag** `qi0mauch9ahksha8b6dfe3p0kq`

The most direct path was just `cat /tmp/kourier_delivery.tmp` — the daemon handed the secret over in a world-readable file. The `strings` approach would have worked without the running service at all. Either way the binary should never store a credential in plaintext, whether in `.rodata` or in a tmp file with open permissions.

One thing to flag for level03: the new shell is in group `burbclave` (a Snow Crash novel reference — franchise suburb). That group membership is likely going to matter.
