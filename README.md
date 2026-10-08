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
| **Framework-aware** | Sources: Flask `request.*`, Django/DRF/Starlette/FastAPI request objects (incl. `self.request`), route-handler parameters, `input()`, `sys.argv`. |
| **One report from many tools** | Imports Semgrep, Bandit, CodeQL (SARIF) and Gitleaks; deduplicates by vulnerability class and location, keeping every tool as provenance. |
| **CI-ready** | SARIF 2.1.0 (validated against the OASIS schema) for GitHub code scanning, `--fail-on` exit codes, stable fingerprints that survive code moves. |

## Install

```bash
pip install hackscan        # or: uv tool install hackscan / pipx install hackscan
```

Python 3.10–3.13, any OS. No network access and no LLM needed.

## Usage

```bash
hackscan scan .                                   # text report
hackscan scan . --format sarif -o hackscan.sarif  # for GitHub code scanning
hackscan scan . --fail-on high                    # exit 1 on open high/critical findings
hackscan scan . --format json --show-suppressed   # everything, machine-readable
hackscan scan . --with bandit,semgrep,gitleaks    # also run these tools if installed
hackscan scan . --import codeql=results.sarif     # merge a report you already have
hackscan rules                                    # list rules
```

| Option | Meaning |
|---|---|
| `--severity`, `--min-confidence` | Report filters. |
| `--fail-on SEV` | Exit 1 if an open (candidate/confirmed) finding is at least `SEV`. Suppressed findings never count. |
| `--ignore GLOB` | Skip paths (`tests/*`, `**/migrations/**`, `legacy`). `.venv`, `node_modules`, `build`, ... are always skipped. |
| `--with TOOLS` / `--import FMT=FILE` | Run external tools / import reports (`sarif`, `semgrep`, `bandit`, `codeql`, `gitleaks`). A missing or failing tool is a warning unless `--strict-tools`. |
| `--plugins DIR` | Load custom rules (see below). |
| `--allow-incomplete` | Do not exit 2 when some files cannot be analyzed (they are still listed). |
| `--no-taint` | Pattern matching only. |
| `--jobs N` | Worker processes (default: automatic). |

Exit codes: `0` OK, `1` `--fail-on` threshold reached, `2` usage/config/plugin error or
an **incomplete scan** (a file could not be parsed or read; use `--allow-incomplete` to
accept). An incomplete scan is never reported as a pass, and SARIF marks it with
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
```

### Suppressing a finding

```python
os.system(cmd)  # hackscan: ignore[HS-CMDI-001]
```

Suppressed findings stay in SARIF output (as `suppressions`) so they remain auditable.

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

```yaml
- run: pipx install hackscan
- run: hackscan scan . --format sarif --sarif-omit-suppressed -o hackscan.sarif --fail-on high
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: hackscan.sarif
```

## Limitations

- Taint analysis is intra-procedural: values arriving through function parameters are
  candidates, not confirmations (inter-procedural analysis is on the roadmap).
- Python only. Imported tools may cover other languages; their findings are passed through.

## Development

```bash
uv sync --group dev
uv run pytest
uv run ruff check . && uv run ruff format --check .
```

See [PROJECT.md](PROJECT.md) for the design, milestones and decision log.

## License

MIT
