# HackScan

Python SAST orchestrator and verifier.

- Own AST + taint engine for SQL injection, command injection and code injection
- Imports findings from Semgrep, Bandit, CodeQL (SARIF) and Gitleaks, and dedupes them
- Taint-based confirmation, optional local-LLM (Ollama) triage and fix suggestions
- SARIF 2.1.0 output for GitHub Code Scanning

> Status: pre-alpha (M0 — core contracts). See [PROJECT.md](PROJECT.md) for the plan.

## Development

```bash
uv sync --group dev
uv run pytest
uv run ruff check . && uv run ruff format --check .
```
