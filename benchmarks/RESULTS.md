# Benchmark results

Generated 2026-10-09 by `benchmarks/run.py` on `benchmarks/suite/`: 26 vulnerable sinks and 24 safe traps across 9 files (sqli, cmdi, codei, weak_crypto).

| Tool | Version | TP | FP | FN | Precision | Recall | F1 |
|---|---|---:|---:|---:|---:|---:|---:|
| HackScan | 0.3.0 | 23 | 7 | 3 | 77% | 88% | 82% |
| HackScan (confirmed only) | 0.3.0 | 18 | 2 | 8 | 90% | 69% | 78% |
| Bandit | bandit[sarif]==1.9.4 | 24 | 19 | 2 | 56% | 92% | 70% |
| Semgrep CE | semgrep==1.180.0 (p/python sha256:31c1dfa46e8d) | 16 | 6 | 10 | 73% | 62% | 67% |
| CodeQL | CodeQL 2.27.2 (codeql/python-queries@1.8.12, security-extended) | 20 | 1 | 6 | 95% | 77% | 85% |

Per class (TP / FP / FN):

| Tool | sqli | cmdi | codei | weak_crypto |
|---|---:|---:|---:|---:|
| HackScan | 8 / 3 / 0 | 6 / 3 / 0 | 6 / 1 / 0 | 3 / 0 / 3 |
| HackScan (confirmed only) | 7 / 1 / 1 | 5 / 1 / 1 | 6 / 0 / 0 | 0 / 0 / 6 |
| Bandit | 8 / 5 / 0 | 6 / 11 / 0 | 5 / 2 / 1 | 5 / 1 / 1 |
| Semgrep CE | 4 / 2 / 4 | 4 / 3 / 2 | 3 / 1 / 3 | 5 / 0 / 1 |
| CodeQL | 8 / 1 / 0 | 3 / 0 / 3 | 3 / 0 / 3 | 6 / 0 / 0 |
