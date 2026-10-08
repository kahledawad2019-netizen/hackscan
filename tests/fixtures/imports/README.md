# Importer fixtures

`project/` is a tiny vulnerable Flask app; the reports below describe it.

| File | Origin |
|---|---|
| `bandit.sarif` | **Recorded**: `bandit -r . -f sarif` (via `uvx --from "bandit[sarif]"`) run inside `project/`. |
| `semgrep.sarif` | Hand-written to Semgrep OSS's SARIF shape (driver `Semgrep OSS`, CWE in rule tags). Includes a result outside the scan root. |
| `codeql.sarif` | Hand-written to CodeQL's SARIF shape (`%SRCROOT%` base id, `security-severity`, `external/cwe/...` tags, no `endLine`). |
| `gitleaks.json` | Hand-written to Gitleaks' JSON report shape. The token is fake. |

Semgrep, CodeQL and Gitleaks were not available on the development machine; replace these
with recorded outputs when they are (the tests only rely on documented fields).
