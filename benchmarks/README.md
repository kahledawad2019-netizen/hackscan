# Benchmark

`run.py` scores HackScan, Bandit, Semgrep CE and CodeQL on the labeled suite in `suite/`
and writes [`RESULTS.md`](RESULTS.md) (and `RESULTS.json`, which a test compares with the
current engine so the published HackScan numbers cannot go stale). `apps.py` scans
known-vulnerable public apps and writes [`APPS.md`](APPS.md).

```bash
uv run python benchmarks/run.py                       # all tools
uv run python benchmarks/run.py --tools hackscan,bandit
uv run python benchmarks/apps.py --list-unreviewed    # needs network (downloads the apps)
```

Bandit and Semgrep run in isolated environments through `uvx` at pinned versions
(`bandit[sarif]==1.9.4`, `semgrep==1.180.0` with the `p/python` registry ruleset).
CodeQL needs the CLI on `PATH` or `CODEQL=<path to codeql>` (the results use the
`codeql-bundle-v2.27.2` release with `python-security-extended`). On Windows the harness
points CodeQL's Python extractor at the current interpreter, so the `py` launcher is not
needed. A tool that cannot run is shown as skipped, never as zero findings.

## The suite

Small but realistic Flask, Django, FastAPI and CLI modules covering the four classes
HackScan targets: SQL injection, command injection, code injection and weak
cryptography. Each sink statement is labeled on its first line:

- `# vuln: <class>`: untrusted input (request data, route parameters, `sys.argv`,
  `input()`) reaches it, directly, through other functions, other files, containers or
  object state;
- `# safe: <class>`: a trap that pattern matchers flag but no untrusted input reaches:
  parameterized queries, `int()` conversion, `shlex.quote`, argument lists without a
  shell, allow-list guards, constants, `ast.literal_eval`, `usedforsecurity=False`, and
  functions only ever called with constants.

### Label assumptions

- Command-line arguments and `input()` are untrusted, like request data (the program may
  run with arguments chosen by someone else, e.g. from a web hook or a cron line built
  from user data).
- Injection labels are about injecting a *command, query or code*. Argument injection
  into an argument list without a shell (`subprocess.run(["tail", name])` with
  `name = "-f"`) is out of scope, so such calls are `safe`.
- `shlex.quote` with `shell=True` is `safe`: the shell is POSIX (`tar`, `zfs` and
  `systemctl` are POSIX programs). On Windows `cmd.exe` it would not be.
- Allow-list guards (`if x not in ALLOWED: return/raise`) and `int()` conversion make a
  value safe for every class; a value used only with constants is safe even when it
  arrives through a parameter.
- Weak cryptography has no source: `vuln` means a broken or fast algorithm used for a
  security purpose (password hashing with MD5/SHA-1 even when salted, DES, RC4, ECB
  mode); `safe` means a strong construction (scrypt, HMAC-SHA256, AES-GCM) or a
  declared non-security use (`usedforsecurity=False`).

It deliberately includes cases HackScan misses (taint stored on `self` and used in
another method, weak ciphers such as DES/RC4/ECB, `compile()` of user input) and traps
it cannot prove safe (allow-list guards, constant-only callers, dict lookups).

## Scoring

Every tool's SARIF output goes through HackScan's importer, so all tools are classified
the same way (rule id, then CWE). Tools report a flow at different points (the sink,
where the query string is built, the source), so scoring is per function: each function
holds at most one labeled sink.

- TP: a function with a `vuln` label and at least one report of that class;
- FN: a function with a `vuln` label and none;
- FP: a function (or module-level code) with reports of a class but no `vuln` label of
  that class. Reports in other classes are ignored.

HackScan is scored twice: all open findings (candidates and confirmed), and confirmed
findings only (what `--fail-on` with a confidence filter, or a reviewer working
top-down, would act on first).

## Known-vulnerable apps

`apps.py` downloads [vulpy](https://github.com/fportantier/vulpy),
[PyGoat](https://github.com/adeyosemanputra/pygoat) and
[DVPWA](https://github.com/anxolerd/dvpwa) (all MIT) at pinned commits into
`benchmarks/.cache/` (only `.py` files are extracted; nothing is executed), runs every
tool and reduces reports to (file, function, class) keys. Each key any tool reported has
a verdict and a note in [`apps_review.json`](apps_review.json), judged with the label
assumptions above, plus two rules for findings outside the suite's patterns: Flask
`debug=True` is a code-execution finding only when bound to a non-loopback address, and
import-level warnings are false positives. A vulnerability reported at two keys (a shell
helper and the view that builds its command) is counted once. Relative recall divides by
all distinct vulnerabilities found by any tool, since nobody has a complete list.

## Caveats

- The suite was written by the same team as HackScan. It includes HackScan's known
  weaknesses on purpose, but it is small (about 50 labeled sinks) and should be read as a
  sanity check, not a definitive ranking. A scan of real, known-vulnerable applications
  complements it.
- Each tool runs one standard configuration: Bandit with all checks and no severity or
  confidence filter, Semgrep CE with the `p/python` registry ruleset, CodeQL with the
  `python-security-extended` suite (broader than its default suite), HackScan without
  options. Other configurations would give other numbers. For Bandit this includes
  import-level warnings
  (`B404 import subprocess`, `B413 import pycrypto`), which count as false positives at
  module level. Semgrep CE runs `p/python` without Pro (cross-file) analysis.
- CodeQL's default threat model only covers remote sources, so the suite's command-line
  and `input()` flows are not reported (enabling `--threat-model=local` did not change
  the result in 2.27.2). Its Django sources need a URL configuration, so the suite's
  Django views are routed in `suite/sqli/urls.py` as a real project would be.
- The app verdicts are the authors' judgment; the notes make each one checkable.
