# HackScan

**A Python security scanner that checks what it reports.** HackScan finds injection
sinks with its own AST engine, then runs a flow-sensitive taint analysis to decide, per
finding, whether a modelled flow from untrusted input to the sink is established (see
[Meaning of confirmation](#meaning-of-confirmation)). It can also ingest Semgrep, Bandit,
CodeQL and Gitleaks results, merge duplicates across tools, and emit one SARIF report.

```text
$ hackscan scan app/
HIGH     confirmed  views.py:10:9  HS-SQLI-001  [score 100]
    SQL query is built with string formatting/concatenation.
    | cursor.execute("SELECT * FROM sales WHERE year = " + year)
    > Modelled flow: untrusted request data (`request.GET`) at line 8.
    > Confirmed: A modelled flow from a recognized untrusted source to this sink is established under HackScan's documented analysis assumptions. This does not establish runtime reachability or exploitability.
```

## Why another scanner?

| | HackScan |
|---|---|
| **Verdicts, not just matches** | Every injection candidate is **confirmed** (a modelled flow from an untrusted source is established, with a trace: see [Meaning of confirmation](#meaning-of-confirmation)), **suppressed** (constant or sanitized on every modelled path), or left as a **candidate** for review. |
| **Sound suppression** | A finding is only dismissed if *every* path is safe. Branches, loops (`break`/`continue`), `try`/`except`/`finally`, aliasing and mutation of lists/dicts, closures and `:=` are modeled. A differential fuzzer executes thousands of random programs to check that no dismissed sink ever receives attacker input. |
| **Across functions and files** | A sink fed by a function parameter is confirmed when a caller anywhere in the scanned code passes untrusted data (directly or through other functions), or when a called function returns it; the trace names the source file and line. |
| **Framework-aware** | Sources: Flask `request.*`, Django/DRF/Starlette/FastAPI request objects (incl. `self.request`), route-handler parameters, `input()`, `sys.argv`. |
| **One report from many tools** | Imports Semgrep, Bandit, CodeQL (SARIF) and Gitleaks; deduplicates by vulnerability class and location, keeping every tool as provenance. |
| **Fixes you can apply** | Mechanical, validated fix suggestions: parameterized queries (driver-aware placeholders), argument lists instead of shell strings, `ast.literal_eval`, SHA-256 for non-password digests (a password hash gets guidance instead: Argon2, scrypt, bcrypt or PBKDF2, with a migration). Each is an exact edit that re-parses; ambiguous cases get no fix rather than a wrong one. |
| **Optional local-LLM triage** | `--llm` asks a local Ollama model about remaining candidates. Its assessment is attached to the finding (it never confirms one), and it may only suppress by citing a line that HackScan verifies itself (an allow-list guard, constant or sanitizer that holds on every path). Code is treated as untrusted data; secrets are redacted. |
| **CI-ready** | SARIF 2.1.0 (validated against the OASIS schema) for GitHub code scanning, `--fail-on` exit codes, stable fingerprints that survive code moves. |

## Install

```bash
pip install hackscan        # or: uv tool install hackscan / pipx install hackscan
```

Python 3.10–3.13, any OS. No network access and no LLM needed (`--llm` is opt-in).

## Usage

```bash
hackscan scan .                                   # text report
hackscan scan . --format sarif -o hackscan.sarif  # for GitHub code scanning
hackscan scan . --fail-on high                    # exit 1 on open high/critical findings
hackscan scan . --format json --show-suppressed   # everything, machine-readable
hackscan scan . --with bandit,semgrep,gitleaks    # also run these tools if installed
hackscan scan . --import codeql=results.sarif     # merge a report you already have
hackscan scan . --show-fixes                      # include fix suggestions as diffs
hackscan scan . --llm --model qwen2.5-coder:7b    # triage candidates with local Ollama
hackscan rules                                    # list rules
```

| Option | Meaning |
|---|---|
| `--severity`, `--min-confidence` | Report filters. |
| `--fail-on SEV` | Exit 1 if an open (candidate/confirmed) finding is at least `SEV`. Suppressed findings never count. `never` turns off a threshold set in `.hackscan.yml`. |
| `--ignore GLOB` | Skip paths (`tests/*`, `**/migrations/**`, `legacy`). `.venv`, `node_modules`, `build`, ... are always skipped. |
| `--with TOOLS` / `--import FMT=FILE` | Run external tools / import reports (`sarif`, `semgrep`, `bandit`, `codeql`, `gitleaks`). A missing or failing tool is a warning unless `--strict-tools`. |
| `-o FILE` | Write the report to `FILE`. Never overwrites anything except a previous HackScan report. |
| `--plugins DIR` | Load custom rules (see below). |
| `--allow-incomplete` | Do not exit 2 when some files cannot be analyzed (they are still listed). |
| `--no-taint` | Pattern matching only. |
| `--show-fixes` / `--no-fix` | Print suggested fixes as diffs / do not generate fixes (fixes are also in JSON and SARIF `fixes`). |
| `--llm`, `--model`, `--ollama-host` | Opt-in LLM triage of candidates via Ollama (default `http://localhost:11434`). |
| `--llm-max`, `--llm-timeout`, `--llm-no-suppress` | LLM budget (default 20 findings, 60 s/request); let the LLM annotate (it never confirms) but never suppress. |
| `--color auto\|always\|never` | Rich terminal output; `auto` uses it only on an interactive terminal (not in CI, pipes or with `NO_COLOR`). |
| `--jobs N` | Worker processes (default: automatic). |

Exit codes: `0` OK, `1` `--fail-on` threshold reached, `2` usage/config/plugin error or
an **incomplete scan** (a file could not be parsed or read, or an `--import` report
could not be loaded; use `--allow-incomplete` to accept). A `--with` tool that is missing
or exits with an error is a warning, or exit `2` with `--strict-tools`. An incomplete scan is never reported as a pass, and SARIF marks it with
`executionSuccessful: false`.

### Configuration

`.hackscan.yml` files are discovered from the filesystem root down to the scanned
directory and merged (nearest wins; `ignore` lists accumulate). CLI options override them.

```yaml
ignore: [tests/*, "**/migrations/**"]
severity: medium
min-confidence: 40
fail-on: high
with: [bandit]
import:
  codeql: codeql-results.sarif
plugins: security/rules
llm: false
llm-model: qwen2.5-coder:7b
```

### LLM triage

`--llm` sends each remaining *candidate* (never confirmed or suppressed findings) with
its surrounding function to a local Ollama model and asks for a verdict:

- **true positive**: the finding stays a *candidate* with the model's assessment attached
  (+15 score); only HackScan's own analysis confirms. A suggested fix is kept only if the
  patched file parses and a re-scan shows the finding gone and nothing new.
- **false positive**: only accepted if the model cites a line that HackScan verifies runs
  on every path and makes the value safe: an allow-list guard (`if x not in {...}: return`,
  `if not x.isdigit(): raise`, or `if not x.isdecimal(): raise`), a constant, or a
  class-appropriate sanitizer. `isnumeric()`, `isalnum()`, `isalpha()`, and
  `isidentifier()` do not qualify. Otherwise the reasoning is attached as a note and
  the finding stays open.
- Code is fenced with a random per-request token and treated as untrusted data; replies
  must match a JSON schema; secret-looking values are redacted; answers are cached.

Use a non-reasoning instruct or coder model. Measured on a CPU-only laptop (~30 s per
finding): `qwen3:4b-instruct-2507` judged a real injection, a bypassable length check and
an allow-list guard correctly; `qwen2.5-coder:3b` never suppressed but also missed the
allow-list guard (larger models do better). Reasoning models such as `deepseek-r1` often
spend their whole output budget thinking, which HackScan reports as "no answer" and
leaves the finding open. In the same test both small models obeyed a comment in the
scanned code telling them to answer "false positive"; the deterministic evidence check
rejected it and the finding stayed open. That check, not the model, decides suppression.

### Suppressing a finding

```python
os.system(cmd)  # hackscan: ignore[HS-CMDI-001]
```

Suppressed findings stay in SARIF output (as `suppressions`) so they remain auditable;
use `--sarif-omit-suppressed` when uploading to GitHub, which does not honor them.

Secrets are never echoed: findings of class `secret` (from any tool) have generic
messages and redacted snippets, and values reported by Gitleaks are scrubbed from all
output, including warnings.

## Benchmark

**Labeled suite.** Flask, Django, FastAPI and CLI code with 26 vulnerable sinks and 24
look-alike safe traps (SQL, command and code injection, weak crypto), scored per function;
each tool runs the configuration in its Version column (Bandit: all checks; Semgrep CE:
the `p/python` ruleset; CodeQL: `python-security-extended`; HackScan: no options)
([methodology and caveats](benchmarks/README.md), [full results](benchmarks/RESULTS.md)):

| Tool | Version | TP | FP | FN | Precision | Recall | F1 |
|---|---|---:|---:|---:|---:|---:|---:|
| HackScan | 0.4.0 | 23 | 7 | 3 | 77% | 88% | 82% |
| HackScan (confirmed only) | 0.4.0 | 17 | 3 | 9 | 85% | 65% | 74% |
| Bandit | bandit[sarif]==1.9.4 | 24 | 19 | 2 | 56% | 92% | 70% |
| Semgrep CE | semgrep==1.180.0 (p/python sha256:31c1dfa46e8d) | 16 | 6 | 10 | 73% | 62% | 67% |
| CodeQL | CodeQL 2.27.2 (codeql/python-queries@1.8.12, security-extended) | 20 | 1 | 6 | 95% | 77% | 85% |

**Known-vulnerable apps.** [vulpy](https://github.com/fportantier/vulpy),
[PyGoat](https://github.com/adeyosemanputra/pygoat) and
[DVPWA](https://github.com/anxolerd/dvpwa) at pinned commits; every report reviewed by
hand. There is no complete ground truth, so recall is relative to the 21 distinct
vulnerabilities any tool found ([details](benchmarks/APPS.md)):

| Tool | Reports | TP | FP | Vulns found | Precision | Relative recall |
|---|---:|---:|---:|---:|---:|---:|
| HackScan | 17 | 15 | 2 | 15 | 88% | 71% |
| HackScan (confirmed only) | 6 | 6 | 0 | 6 | 100% | 29% |
| Bandit | 32 | 16 | 16 | 16 | 50% | 76% |
| Semgrep CE | 12 | 11 | 1 | 11 | 92% | 52% |
| CodeQL | 15 | 15 | 0 | 14 | 100% | 67% |

CodeQL is the most precise; Bandit finds a little more but about half of its reports are
noise. HackScan sits in between: higher recall than CodeQL and Semgrep, higher
precision than Bandit. Its misses are weak ciphers (DES, RC4, ECB, unauthenticated
modes), which its rule does not cover yet, and flows it does not follow (`self`
attributes, ambiguous module names). Its false positives are sinks it cannot prove safe (allow-list
guards, functions only called with constants). The suite is small and written by
HackScan's authors, so treat both tables as a sanity check rather than a ranking.

## Rules

| Rule | Detects | Severity |
|---|---|---|
| `HS-SQLI-001` | Non-constant SQL reaching DB-API `execute*`, Django `raw`, SQLAlchemy `text`, pandas `read_sql` | high |
| `HS-CMDI-001` | Non-constant commands reaching `os.system`, `os.popen`, `subprocess.*(shell=True)`, ... | high |
| `HS-CODEI-001` | Non-constant input to `eval`, `exec`, `compile` | high |
| `HS-CRYPTO-001` | MD5/SHA-1 (unless `usedforsecurity=False`); PostgreSQL MD5 authentication verifiers | low; high on credential data (CWE-916) and for the verifiers |

Sanitizers recognized: numeric/UUID conversions (all classes), `psycopg` `sql.Identifier`
/`sql.Literal` (SQL). `shlex.quote` is POSIX-only, so quoted commands are kept as
low-confidence candidates rather than suppressed. That verdict needs the command to start with
a literal name from the same list of inert programs that command fixes use (plus `echo`, but
not `printf`, whose shell builtin can evaluate a variable name; not `sh -c`, `ssh`, `xargs`,
`tar`, interpreters, ...) and command text without shell syntax that starts or groups commands
(`;`, `|`, `&`, `$(...)`, redirections, braces): a quoted value in the program position, or a
program name assembled at runtime, gets none; nor does a call that may pick another shell
(`executable=`, options passed with `**`).

### Custom rules

```python
# security/rules/pickle_rule.py
from hackscan.core.models import Severity
from hackscan.plugins import Match, RulePlugin


class PickleLoads(RulePlugin):
    rule_id = "ACME-PICKLE-001"  # the HS- prefix is reserved
    name = "pickle-loads"
    description = "pickle.loads on untrusted data"
    severity = Severity.HIGH
    cwe = ("CWE-502",)

    def check(self, node, ctx):
        if "pickle.loads" in ctx.call_names(node):
            yield Match(node, "pickle.loads call")
```

## GitHub Actions

The repository is a composite action (available from v0.3.0). It installs HackScan, writes
SARIF, uploads it to GitHub Code Scanning and then fails the job if the `fail-on` threshold
was hit, so findings appear in the Security tab even on a failing run.

```yaml
permissions:
  contents: read
  security-events: write   # needed for the Code Scanning upload
  actions: read            # needed for the upload in private repositories

jobs:
  hackscan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: kahledawad2019-netizen/hackscan@v0.4.2
        with:
          path: src
          fail-on: high
```

| Input | Default | Meaning |
|---|---|---|
| `path` | `.` | File or directory to scan |
| `version` | *(empty)* | HackScan version from PyPI; empty installs the action's own checkout |
| `fail-on` | `high` | Fail at this severity or above; empty passes `--fail-on never` (HackScan 0.3.0+), so findings never fail the job but crashes and errors still do |
| `args` | *(empty)* | Extra CLI arguments, word-split without globbing; pass only trusted values |
| `sarif-file` | `hackscan.sarif` | Report path |
| `upload-sarif` | `true` | Upload to Code Scanning (skip it for fork pull requests, whose token is read-only) |

Outputs: `sarif-file` and `exit-code` (0, 1 = threshold hit, 2 = error). The action sets up
Python 3.12 on the runner. Without the action:

```yaml
- run: pipx install hackscan
- run: hackscan scan . --format sarif --sarif-omit-suppressed -o hackscan.sarif --fail-on high
- uses: github/codeql-action/upload-sarif@v4
  if: always()
  with:
    sarif_file: hackscan.sarif
```

## pre-commit

```yaml
repos:
  - repo: https://github.com/kahledawad2019-netizen/hackscan
    rev: v0.4.2
    hooks:
      - id: hackscan
```

The hook runs `hackscan scan . --fail-on high` once per commit that touches Python files. It
scans the whole repository (the CLI takes a single path), so `.hackscan.yml` `ignore` globs
apply as usual.

## Meaning of confirmation

Every JSON and SARIF report names this contract (`hackscan-confirmation-v1`): JSON as
`tool.confirmation_contract` and a `confirmation_basis` per finding (`modelled-flow` for a
confirmed finding, `assumed-flow` for a candidate whose possible flow is assumed), SARIF as
the `confirmationBasis` / `confirmationContract` properties and the verdict sentence in the
result message. The bracketed number in text output is a heuristic ranking score (0-100),
not a probability or a measure of exploitability. Report consumers should tolerate added
fields and read `status` / `confirmation_basis` rather than parse display text.

**What `confirmed` means.** For injection findings, `confirmed` means HackScan establishes
an abstract source-to-sink dependency using its supported operation models and function
links, with no unresolved assumed-flow step on the supporting dependency. The dependency
must survive the sink-specific sanitizer and quoting checks. Confirmation is evidence
within this static model. It does not prove that an execution reaches the sink, that the
call succeeds, that attacker-controlled characters survive unchanged, or that an injection
vulnerability is exploitable. A candidate, or the absence of a confirmation, is not
evidence of safety.

**Library, builtin and source assumptions.** Recognized sources are treated as untrusted
according to the active source definitions and source-recognition heuristics; HackScan
assumes those APIs have their expected behaviour and does not establish their runtime
implementation or deployment configuration. Library and builtin models apply to the
documented call forms and argument roles. An explicit callback or custom implementation
that can replace the result (`json.loads(s, cls=...)`, a function as `re.sub`'s
replacement) is outside the default data-preservation model. Unmodelled calls, unsupported
object flows and unresolved aliases contribute assumed flow and cannot alone establish a
confirmation.

**Replacement detection.** A library model, a linked function or a binding that scanned code
may replace contributes assumed flow. Detection covers only these syntactic forms; detected
facts apply across all analyzed files, regardless of execution order:

| Form | Example | Treated as replaced |
|---|---|---|
| Attribute assignment or deletion (except on a method's own `self`/`cls`) | `json.loads = f`, `helpers.ident = f` | that name, in any module |
| `setattr`/`delattr` with a constant name (any spelling or alias) | `setattr(m, "ident", f)` | that name |
| A module object used other than to read or call one of its attributes | `m = json`, `f(json)`, `vars(json)`, `json.__dict__[k] = v`, `setattr(json, name, f)` | every name of that module |
| `sys.modules` written, or used other than for lookups and membership | `sys.modules[name] = m`, `mods = sys.modules`, `sys.modules.copy()` | that module, or any module |
| A module of computed name written directly | `import_module(n).__dict__[k] = v`, `setattr(import_module(n), k, v)` | any module |
| This module's `globals()`/`vars()`/`locals()` used other than for lookups and membership | `globals()[k] = v`, `globals().copy()`, `f(globals())` | this module's names and every module it imports |
| A write, import or namespace helper used as a value | `ops = [setattr]` | any module (a getter: this module and its imports) |
| A behaviour attribute stored, or set by constant name | `ident.__code__ = g.__code__` (`__defaults__`, `__kwdefaults__`, `__dict__`, `__class__`, `__call__`) | that function (an object of unknown origin: any) |
| A function's `__globals__` written | `ident.__globals__[k] = v` | the module defining it (through re-exports) |
| A scanned module imported instead of a library module | `json.py` at a source root | that library's models |
| A caller's own binding set from outside | `app.json = ...`, `app.__dict__["go"] = ...` | models and links reached through that name in `app` |

Computed imports keep a boundary: computing or performing an import alone does not
invalidate every model; a recognized write or escape of the returned module does. Not
detected (replacement through these may be missed): a module of computed name handed to
other code that writes it; behaviour changes through an alias (`alias = ident;
alias.__code__ = ...`) or a re-exported spelling (`bridge.parse.__code__ = ...`);
`fn.__setattr__(...)`, `object.__setattr__(fn, ...)`, a computed-name `setattr` on a
function, changes to the contents of `__kwdefaults__`; a function handed to other code
(`patch(json.loads)`); bound readers or views of a namespace (`lookup = globals().get`,
`globals().keys().mapping`); comparisons with a namespace (`globals() == x`); replacing a
library model's internals (`json.JSONDecoder.decode = ...`); and any code outside the
analyzed files.

**Static approximations.** Containers and aliases are summarized and can merge data from
different elements or states. Attribute and expression handling can retain dependencies
from metadata, discarded operands, or values that are not ultimately selected (`[q, "x"][1]`,
`q[:0]`). Destructive container operations may leave earlier dependencies in the summary.
HackScan does not establish exact runtime behaviour for short-circuiting, dead code,
assignment-expression evaluation order, asynchronous execution, or `finally` interactions;
call signatures and successful execution are not generally validated. These approximations
can produce a confirmed abstract dependency where no runtime source-to-sink flow occurs.
Sanitizer credit can also be retained across supported identity operations or function
boundaries in ways that miss a confirmation. The report identifies the active knowledge
configuration; interpret a confirmation using this contract and the model coverage of that
scan.

## Limitations

- Taint analysis follows calls across functions and files only to *confirm* findings: a
  sink fed by a parameter is confirmed when some caller in the scanned code passes
  untrusted data, or when a called function returns it. It never suppresses a finding
  (callers outside the scan are unknown). Only undecorated module-level functions bound
  once are linked (same module, `import`/`from ... import`, relative imports and
  re-exports); methods, nested functions, decorated functions, modules with a star
  import, `*args`/`**kwargs` call sites and module names that match more than one file
  are not followed. Sources are not tracked through object attributes or globals. Through
  a call HackScan neither models nor links, the flow is *assumed*: the finding stays a
  candidate and the call is named in its evidence.
- Findings in a function (or module) that itself uses `:=` are never suppressed, only
  confirmed or left as candidates: an assignment expression can rebind a name in the
  middle of an expression, which the statement-level analysis does not order. Sinks in
  the body of a generator expression are never suppressed either (it runs later), nor
  are values produced by one, except by a generator that `str.join` consumes right away.
  Module-level constants are trusted only when bound exactly once and the module never
  writes its namespace dynamically (`globals()`, `vars()`, `exec`, `eval`, `__dict__`,
  star imports); `global`/`nonlocal` names are never trusted.
- Mutable objects (lists, dicts, sets) are tracked by variable name. Mutation through
  direct aliases, method calls (`d.get(k).append(x)`), bound methods
  (`add = parts.append`), conditional receivers and comprehension items is modeled. A
  constant or sanitized list stored in a local container by a container method or item
  store (`rows.append(parts)`, `rows += [parts]`, `d[k] = parts`) is linked to it, so a
  later change through either name is seen through the other. An element of a list, set,
  dict or tuple display written as a literal, an f-string, or a tuple or operator of such
  is not a mutable object, so passing it on does not change the container (a name, a call
  or an attribute may be any object, a list included).
  Aliases created in less direct ways (stored in another object's attribute and mutated
  through it later, returned from a helper, reached through `getattr`) may be missed, so a
  constant suppression involving such code deserves review.
- A sanitizer counts only through a name that cannot be something else in the same file:
  one import or definition, no assignment to an attribute of that name, no `setattr` /
  `delattr`. Replacing a sanitizer at runtime in other ways (from another file, or in the
  same file through an alias of `setattr`, `__setattr__`, `__dict__` writes and the like)
  is not modeled. The same holds for the pure library functions whose text result is a
  constant when every argument is one: `os.path.join`, `os.path.normpath`, `os.fspath`,
  `urllib.parse.unquote`, `html.unescape`, `re.sub` and the base64/binascii decoders (not
  `os.path.abspath` or `os.path.expanduser`, which read the working directory and the
  environment, and not `pathlib` paths, whose methods read the file system; a path built
  from untrusted text still carries it).
- Sanitizer credit computed in one function is reused by its callers and callees, so a
  transformation in another function that undoes it (slicing a shell-quoted argument,
  for example) can leave such a finding a candidate instead of confirming it.
- Numbers from `int()`, `float()`, `len()` and similar count as safe in SQL text, and SQL
  token boundaries are not modeled: text whose structure a runtime number decides is not
  detected, such as a `-` right before a possibly negative number (`"n -" + str(int(x))`
  can form a `--` comment), a fragment repeated a runtime number of times (`"-" * int(x)`),
  or a separator repeated between a runtime number of items. Bound query parameters avoid
  all of these.
- Python only. Imported tools may cover other languages; their findings are passed through.
- Fix suggestions are deliberately conservative: many vulnerable lines get none. Command
  fixes (argument lists) are only offered for programs whose arguments are inert data
  (`cat`, `ls`, `grep`, `head`, ...): many others run operands or options as
  commands (`sh -c`, `npx PKG`, `git -c alias=!cmd`, `tar --to-command`). They are also
  not offered when a value directly follows a flag; put `--` before operands to get one.
  A value starting with `-` can still be read as an option, so review command fixes. No
  fix is offered for a call that contains a secret, or for SQL containing comments.
- SQL fixes are not offered for unquoted values inside parentheses, double-quoted
  identifiers, or SQL text containing backslashes, `$`, backticks or brackets;
  redaction of values that coincide with identifiers or tool metadata is best-effort.
- String and bytes literals assigned to secret-looking names (`api_key`, `password`, `token`, ...)
  are masked in snippets, the LLM context and fix diffs. Their values are also removed
  from imported messages and evidence before output or LLM triage when the value is
  secret-like (at least eight characters with a digit or symbol, or at least sixteen
  characters). Known secrets in proposed fixes cause the fix to be omitted. Imported
  findings for files that cannot be parsed have no source snippet.

## Development

```bash
uv sync --group dev
uv run pytest
uv run ruff check . && uv run ruff format --check .
```

See [PROJECT.md](PROJECT.md) for the design, milestones and decision log.

## License

MIT
