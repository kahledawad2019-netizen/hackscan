# HackScan

**A Python security scanner that verifies what it reports.** HackScan finds injection
sinks with its own AST engine, then runs a flow-sensitive taint analysis to decide, per
finding, whether untrusted input really reaches it. It can also ingest Semgrep, Bandit,
CodeQL and Gitleaks results, merge duplicates across tools, and emit one SARIF report.

```text
$ hackscan scan app/
HIGH     confirmed  views.py:10:9  HS-SQLI-001  [100%]
    SQL query is built with string formatting/concatenation.
    | cursor.execute("SELECT * FROM sales WHERE year = " + year)
    > Untrusted request data (`request.GET`) at line 8.
    > Untrusted input reaches the sink.
```

## Why another scanner?

| | HackScan |
|---|---|
| **Verdicts, not just matches** | Every injection candidate is **confirmed** (untrusted source reaches it, with a trace), **suppressed** (provably constant or sanitized on every path), or left as a **candidate** for review. |
| **Sound suppression** | A finding is only dismissed if *every* path is safe. Branches, loops (`break`/`continue`), `try`/`except`/`finally`, aliasing and mutation of lists/dicts, closures and `:=` are modeled. A differential fuzzer executes thousands of random programs to check that no dismissed sink ever receives attacker input. |
| **Across functions and files** | A sink fed by a function parameter is confirmed when a caller anywhere in the scanned code passes untrusted data (directly or through other functions), or when a called function returns it; the trace names the source file and line. |
| **Framework-aware** | Sources: Flask `request.*`, Django/DRF/Starlette/FastAPI request objects (incl. `self.request`), route-handler parameters, `input()`, `sys.argv`. |
| **One report from many tools** | Imports Semgrep, Bandit, CodeQL (SARIF) and Gitleaks; deduplicates by vulnerability class and location, keeping every tool as provenance. |
| **Fixes you can apply** | Mechanical, validated fix suggestions: parameterized queries (driver-aware placeholders), argument lists instead of shell strings, `ast.literal_eval`, SHA-256. Each is an exact edit that re-parses; ambiguous cases get no fix rather than a wrong one. |
| **Optional local-LLM triage** | `--llm` asks a local Ollama model about remaining candidates. It can confirm, but may only suppress by citing a line that HackScan verifies itself (an allow-list guard, constant or sanitizer that holds on every path). Code is treated as untrusted data; secrets are redacted. |
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
| `--llm-max`, `--llm-timeout`, `--llm-no-suppress` | LLM budget (default 20 findings, 60 s/request); let the LLM confirm/annotate but never suppress. |
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

- **true positive**: the finding becomes *confirmed* (+15 confidence); a suggested fix is
  kept only if the patched file parses and a re-scan shows the finding gone and nothing new.
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
| HackScan | 0.3.0 | 23 | 7 | 3 | 77% | 88% | 82% |
| HackScan (confirmed only) | 0.3.0 | 18 | 2 | 8 | 90% | 69% | 78% |
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
| HackScan | 18 | 15 | 3 | 15 | 83% | 71% |
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
| `HS-CRYPTO-001` | MD5/SHA-1 (unless `usedforsecurity=False`) | low |

Sanitizers recognized: numeric/UUID conversions (all classes), `psycopg` `sql.Identifier`
/`sql.Literal` (SQL). `shlex.quote` is POSIX-only, so quoted commands are kept as
low-confidence candidates rather than suppressed.

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
      - uses: kahledawad2019-netizen/hackscan@v0.3.0
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
    rev: v0.3.0
    hooks:
      - id: hackscan
```

The hook runs `hackscan scan . --fail-on high` once per commit that touches Python files. It
scans the whole repository (the CLI takes a single path), so `.hackscan.yml` `ignore` globs
apply as usual.

## Limitations

- Taint analysis follows calls across functions and files only to *confirm* findings: a
  sink fed by a parameter is confirmed when some caller in the scanned code passes
  untrusted data, or when a called function returns it. It never suppresses a finding
  (callers outside the scan are unknown). Only undecorated module-level functions bound
  once are linked (same module, `import`/`from ... import`, relative imports and
  re-exports); methods, nested functions, decorated functions, modules with a star
  import, `*args`/`**kwargs` call sites and module names that match more than one file
  are not followed. Sources are not tracked through object attributes or globals. The
  result of a call is assumed to carry its arguments, so a helper that sanitizes them
  (`def clean(x): return int(x)`) does not prevent a confirmation.
- Findings in a function (or module) that itself uses `:=` are never suppressed, only
  confirmed or left as candidates: an assignment expression can rebind a name in the
  middle of an expression, which the statement-level analysis does not order. Sinks in
  the body of a generator expression are never suppressed either (it runs later), nor
  are values produced by one. Module-level constants are trusted only when bound exactly
  once and the module never writes its namespace dynamically (`globals()`, `vars()`,
  `exec`, `eval`, `__dict__`, star imports); `global`/`nonlocal` names are never trusted.
- Mutable objects (lists, dicts, sets) are tracked by variable name. Mutation through
  direct aliases, method calls (`d.get(k).append(x)`), bound methods
  (`add = parts.append`), conditional receivers and comprehension items is modeled;
  aliases created in less direct ways (stored in another object's attribute or in a
  container and mutated through it later, returned from a helper, reached through
  `getattr`) may be missed, so a constant suppression involving such code deserves review.
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
