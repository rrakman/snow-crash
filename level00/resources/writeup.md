# Level 00 — hiro

SSH into the box on port 4242, land as `level00`. The home directory has one file:

```
$ cat README
Hiro Protagonist. Last of the freelance hackers. Or so he thinks.
```

Cute. Classic Snow Crash reference. Nothing else here, so the first instinct is to look for anything owned by `flag00`:

```
$ find / -user flag00 2>/dev/null
/home/flag00
/opt/snowcrash/level00/hiro
```

`/home/flag00` is off-limits (permission denied). But `/opt/snowcrash/level00/hiro` is interesting:

```
-r-sr-x--- 1 flag00 level00  27K  hiro
```

SUID binary owned by `flag00`, executable by our group. Running it:

```
$ ./hiro
[*] Checking credentials...
[*] Access granted — welcome, flag00

flag00@snowcrash:~$ cat .flag
cat: permission denied
```

So it drops us into a shell as `flag00`, but it's locked down — `cat` is blocked, `sudo` needs a TTY, `su` fails, and the session times out on its own. The flag is right there in `/home/flag00/.flag` but we can't read it this way.

Since we can't get the flag through the shell, let's look at the binary itself. `strings` on a SUID binary is often the first thing worth trying:

```
$ strings /opt/snowcrash/level00/hiro
```

There's a lot of output — library names, format strings, function names — but buried in there is this:

```
>@f2av5il02puano7naaf6adaf3a
```

That string lives in a custom ELF section called `.flag_data` (visible if you check the section headers). The `>@` at the start looks like sentinel bytes the binary uses internally. Strip those off and you've got the flag.

```
$ su level01
Password: f2av5il02puano7naaf6adaf3a
level01@snowcrash:~$
```

---

**Flag** `f2av5il02puano7naaf6adaf3a`

The whole restricted shell setup was window dressing — the secret was sitting in the binary's data section in plaintext the whole time. If you're ever dealing with a SUID binary and can't get anywhere at runtime, `strings` is always worth a shot before going deeper.
