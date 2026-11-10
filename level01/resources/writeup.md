# Level 01 — gargoyle

Home directory README:

```
$ cat README
Gargoyles never stop collecting.
```

Same drill as before — look for anything owned by `flag01`:

```
$ find / -user flag01 2>/dev/null
/proc/594/...
/proc/594/task/594/...
...
/sys/fs/cgroup/system.slice/gargoyle.service/memory.pressure
/home/flag01
```

There's a process owned by flag01 running (PID 594), which is already interesting. But what really stands out is this path:

```
/sys/fs/cgroup/system.slice/gargoyle.service/memory.pressure
```

That's a cgroup entry — meaning the kernel is tracking a service called `gargoyle.service`. The binary in `/opt/snowcrash/level01/gargoyle` is running as a systemd service under `flag01`. That's worth checking:

```
$ systemctl status gargoyle.service

● gargoyle.service - Snow Crash level01 — Gargoyle data collector
     Loaded: loaded (/etc/systemd/system/gargoyle.service; enabled)
     Active: active (running) since Mon 2026-11-09 04:32:40 UTC; 25min ago
    Process: 557 ExecStart=/opt/snowcrash/level01/gargoyle kooda7puivaav1idi4f57q8iq0
   Main PID: 594 (kworker/0:1H)
```

There it is — the password is being passed as a command-line argument to the binary. `systemctl status` shows the full `ExecStart` line including every argument, so anyone on the system can read it.

The process is also calling itself `kworker/0:1H` to blend in with real kernel threads (that's `prctl(PR_SET_NAME)` — a trick you see in rootkits). `ps` might have been slightly confusing without that context, but `systemctl` doesn't care about the name masquerade and shows the real invocation.

Verifying it works:

```
$ ./gargoyle kooda7puivaav1idi4f57q8iq0
$ # exits cleanly, daemon spawned
```

```
$ su level02
Password: kooda7puivaav1idi4f57q8iq0
level02@snowcrash:~$
```

---

**Flag** `kooda7puivaav1idi4f57q8iq0`

The key was the cgroup path in the `find` output — `/sys/fs/cgroup/system.slice/gargoyle.service/` told us exactly what service to look at. After that, `systemctl status` handed over the password in plain text. Never pass secrets as CLI arguments; they show up in process listings, `/proc/<pid>/cmdline`, and service status output for anyone to read.
