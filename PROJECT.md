# Project: VulnHawk (plan v2)

> v2 supersedes the Antigravity draft (`~/.gemini/antigravity/scratch/vulnhawk/PROJECT.md`).
> Changes driven by a Codex + Claude review on 2026-10-08: usable scanner first, LLM optional,
> reuse mature scanners as inputs/baselines instead of re-implementing them.

## Positioning
VulnHawk is a Python SAST **orchestrator + verifier**, not a Semgrep/CodeQL competitor.
Value = (1) own AST+taint engine for core injection classes, (2) ingest & dedupe findings from
mature scanners, (3) taint-based confirmation, (4) optional local-LLM triage and fix suggestions,
(5) clean SARIF for GitHub Code Scanning.

## Architecture
```
 own engine (AST + taint) ──┐
 Semgrep CE SARIF (opt)   ──┤
 Gitleaks JSON (secrets)  ──┼─► normalize → dedupe → taint-confirm → [LLM triage] → [fix gen] → CLI / SARIF
 CodeQL SARIF (opt, BYO)  ──┘
```
1. **Pass 1 – AST rules** (`analyzers/ast_pass`): candidate sinks per rule, plugin-based.
2. **Pass 2 – Taint** (`analyzers/taint_pass`): intra-procedural in MVP; framework-aware sources
   (Flask `request.*`, Django `request.GET/POST/body`, FastAPI handler params), rule-specific sanitizers.
3. **Importers** (`importers/`): SARIF (Semgrep, CodeQL, Bandit) and Gitleaks JSON → `Finding`.
   External tools are invoked only if present on PATH; never bundled.
4. **Dedupe** (`core/dedupe`): merge findings sharing (file, region overlap, CWE); keep provenance list.
5. **Pass 3 – LLM triage** (`analyzers/llm_pass`, optional): Ollama, structured JSON output, schema-validated.
6. **Pass 4 – Remediation** (`analyzers/remediate`, optional): fixes as exact edits, validated by re-parse.
7. **Output** (`cli`, `ui`, `sarif`): Click CLI, Rich output (plain mode for CI), SARIF 2.1.0.

## Core Contract: `Finding` (schema_version = 1)
| Field | Type | Notes |
|---|---|---|
| `id` | str | Stable fingerprint: sha256(`vuln_class` + rel_path + enclosing function qualname + normalized sink expression). Vendor-independent, survives line shifts and importer order. |
| `vuln_class` | enum | Canonical class: `sqli`, `cmdi`, `codei`, `weak_crypto`, `secret`, `other:<cwe>`. Mapped from rule_id/CWE via `core/taxonomy.py`; unmappable imports get `other:<cwe or tool:rule>`. |
| `rule_id` | str | Primary rule, e.g. `VH-SQLI-001`, or `semgrep:<id>` for imported. All contributing rule ids kept in `related_rules`. |
| `cwe` | list[str] | Used for dedupe and SARIF taxa |
| `severity` | enum | critical/high/medium/low |
| `location` | Region | rel path, start/end line+col (1-based lines, 1-based cols per SARIF) |
| `snippet` | str | Display only; never used for identity |
| `sink` | str | Source text of the sink at `location`, read from the file by the producer; input to the fingerprint (falls back to `snippet` only if empty) |
| `sources` | list[str] | Provenance: `vulnhawk`, `semgrep`, `codeql`, `gitleaks`, ... |
| `status` | enum | `candidate`, `confirmed`, `suppressed` |
| `suppression` | Optional[str] | Reason: `taint:constant_input`, `taint:sanitized`, `llm:false_positive`, `inline:vulnhawk-ignore` |
| `confidence` | int 0-100 | Rule-specific; see policy below |
| `evidence` | list[Evidence] | Taint trace steps, LLM rationale (each tagged with producer) |
| `fix` | Optional[Fix] | `edits: list[{region, replacement}]` + derived unified diff; only if validated |

**Dedupe / merge policy** (deterministic, independent of importer order)
- Merge key: (`vuln_class`, rel_path, overlapping region — column-aware, `end_column` exclusive,
  missing columns = whole line). Clustering is **not transitive** — invariant: every pair of findings
  in a cluster overlaps. Findings are visited smallest region first (own engine breaks ties) and join
  the first cluster in which they overlap every member, so two disjoint sinks can never be fused.
  Findings sharing a source but recording different (normalized) sinks never merge — e.g. nested
  `eval(eval(x))` — so a merge never reports fewer findings than any single source did.
- `sink` and `function` are derived from the parsed file by every producer (importers look them up
  by location); merged findings take them from the primary, else the first contributor that has them. Findings with missing CWE merge only if
  `vuln_class` mapped via rule_id; otherwise they stay separate.
- Merged location = union of all contributors' regions. Evidence = sorted concatenation (duplicates kept).
- All tie-breaks fall back to the finding's canonical JSON, so every result is input-order independent.
- Merged fields: `rule_id` = own-engine rule if present, else lexicographically smallest
  `tool:rule`; `severity` = max; `confidence` = max; `sources`/`related_rules`/`cwe` = sorted union;
  `evidence` = concatenation sorted by producer; `status` = `confirmed` > `candidate` > `suppressed`
  (a finding is suppressed only if every contributor is suppressed).

**Policies**
- Passes return new/updated `Finding`s; they never delete.
- `--fail-on <sev>` counts `candidate` and `confirmed` findings at or above `<sev>`; never `suppressed`.
- Taint may suppress only findings in classes the own engine models (`sqli`, `cmdi`, `codei`) and
  only when the full flow is inside one function and provably constant/sanitized. Imported findings
  the engine cannot fully analyze stay `candidate`. Suppressed findings are kept and emitted
  in SARIF with `suppressions[]`; hidden in CLI unless `--show-suppressed`.
- Confidence is rule-specific. Taint applies only to injection rules. Secrets and weak-crypto are
  findings *because* they are literals/calls — taint "constant input" dismissal never applies to them.
- `--no-llm` disables Pass 3 and LLM fix generation. Deterministic template fixes (Pass 4 templates)
  still run unless `--no-fix`.
- Output ordering is deterministic (path, line, col, rule_id).

## LLM Safety (Pass 3/4)
- Scanned code is untrusted data: wrapped in delimited blocks, system prompt states it must not be
  followed as instructions; model output must match a JSON schema or is discarded.
- LLM can only move status `candidate → confirmed|suppressed` with rationale; it cannot create findings
  or raise severity above rule default.
- LLM suppression requires independent evidence: the model must cite a specific line (sanitizer call,
  constant, guard) that a deterministic checker verifies exists in the code. Unverifiable rationale →
  finding stays `candidate` with the LLM note attached. LLM suppressions are labeled `llm:*` and can be
  disabled with `--llm-no-suppress`.
- Redaction applies to all context sent to Ollama (surrounding code too): string literals matching
  secret patterns / Gitleaks hits are replaced with `<REDACTED>`.
- Fixes: must re-parse with `ast`, must change only the reported region(s); else dropped.
- Secrets findings' snippets are redacted before any LLM call. Non-localhost `--ollama-host` prints a warning.
- Budgets: per-request timeout, max findings per scan (`--llm-max`), cache by (finding id, model, prompt version).

## Performance & Determinism
- Default ignores: `.git`, `.venv`, `venv`, `node_modules`, `build`, `dist`, `site-packages`, `__pycache__`.
- Parse failures are reported as warnings, never crash the scan.
- Process-pool parallelism per file for Passes 1-2; result cache keyed by file hash + engine version.
- Target: 100k LOC in < 30 s without LLM on a laptop.

## Importer Behavior
- **Run mode** `--with semgrep,bandit,gitleaks`: invoke tool if on PATH with pinned args
  (`semgrep scan --config p/python --sarif`, `bandit -r -f sarif`, `gitleaks detect --no-git -f json`).
  Missing tool → warning, scan continues. Non-zero exit with valid output → accept; invalid/empty
  output or timeout (`--tool-timeout`, default 300 s) → warning, that source skipped.
  `--strict-tools` turns any tool failure into exit code 2.
- **BYO mode** `--import codeql=results.sarif --import sarif=other.sarif`: parse only, never execute.
- **Path normalization**: all locations resolved to POSIX paths relative to scan root; SARIF
  `originalUriBaseIds`/`file://` URIs resolved; results outside the scan root are dropped with a warning.
- **Region normalization**: 1-based lines/cols; missing end → same as start; missing column → whole line.
- **Exit codes**: 0 = no failing findings, 1 = `--fail-on` threshold hit, 2 = usage/tool/internal error.
- **Tests**: one recorded fixture output per tool (Semgrep, Bandit, CodeQL, Gitleaks) in
  `tests/fixtures/imports/`, plus malformed-input cases.

## Feature Inventory (MVP = M1–M3)
| # | Feature | Milestone |
|---|---|---|
| 1 | Rules: SQL injection, command injection, code injection (`eval`/`exec`) | M1 |
| 2 | Rule: weak crypto (`md5`/`sha1` in security context) — low severity | M1 |
| 3 | Plugin ABC + loader (`--plugins <dir>`) | M1 |
| 4 | Intra-procedural taint + Flask/Django/FastAPI sources + sanitizers | M2 |
| 5 | Inline suppression `# vulnhawk: ignore[RULE]` | M2 |
| 6 | `vulnhawk scan <path>` with `--format text|json|sarif`, `--output` | M3 |
| 7 | `--severity`, `--min-confidence`, `--ignore`, `--fail-on`, `--quiet`, `--show-suppressed` | M3 |
| 8 | `.vulnhawk.yml` hierarchical config | M3 |
| 9 | SARIF 2.1.0: rules, locations, snippets, properties, suppressions; `fixes[]` emitted only when `Finding.fix` exists (populated from M4) ; schema-validated in tests | M3 |
| 10 | Importers (see Importer Behavior): `--with semgrep,bandit,gitleaks` runs tools; `--import <tool>=<file>` ingests BYO reports (CodeQL, any SARIF) | M3 |
| 11 | Dedupe across sources | M3 |
| 12 | Packaging (`pyproject.toml`, `vulnhawk` entry point), PyPI release via GitHub Actions trusted publishing | M3 |
| 13 | Ollama triage pass with graceful offline fallback | M4 |
| 14 | Template + LLM remediation as validated edits; diff view | M4 |
| 15 | Rich "Matrix" TUI (banner, spinners, tables); auto-off in CI / `--quiet` | M4 |
| 16 | Inter-procedural & cross-file taint (own call graph from `ast`) | M5 |
| 17 | Benchmark harness vs Bandit / Semgrep CE / CodeQL; published precision/recall | M5 |
| 18 | GitHub Action (uploads SARIF to Code Scanning), pre-commit hook | M5 |
| 19 | Auth bypass / IDOR heuristics (only if benchmark shows acceptable precision) | Later |
| 20 | Docker image | Later, on demand |

## Milestones
| # | Name | Exit criteria | Depends |
|---|---|---|---|
| M0 ✅ | Skeleton & contracts | Repo, `pyproject`, CI (ruff + pytest on 3.10–3.13), `Finding` models, fixture corpus layout; **frozen** `Finding` schema v1, `taxonomy.py`, fingerprint + dedupe/merge implemented with order-independence tests; importer contract (above) documented | — |
| M1 ✅ | AST engine & rules | Rules 1–2 pass per-rule vulnerable **and** safe fixtures | M0 |
| M2 ✅ | Taint | Framework fixtures (Flask/Django/FastAPI); constant/sanitized flows suppressed; tests for taint boundaries | M1 |
| M3 | CLI, SARIF, importers → **v0.1.0 on PyPI** | `pip install vulnhawk` works on clean venv; SARIF validates against official schema; `--fail-on` exit codes tested | M2 |
| M4 | LLM + remediation + TUI → v0.2.0 | All LLM tests run against a mocked Ollama; offline degradation tested; prompt-injection fixture | M3 |
| M5 | Inter-procedural taint, benchmark, GitHub Action → v0.3.0 | Benchmark report in README; Action used on the repo itself | M4 |

## Test Strategy
- Corpus: `tests/corpus/<rule>/{vulnerable,safe}/*.py`, each file annotated with expected findings
  (`# expect: VH-SQLI-001`) — the test harness diffs actual vs expected (precision/recall per rule).
- Framework cases: `tests/corpus/frameworks/{flask,django,fastapi}/`.
- Golden SARIF snapshots + JSON-schema validation.
- CLI tests via Click `CliRunner`: exit codes, filters, formats.
- LLM: mocked HTTP; prompt-injection fixture (code comment instructing "mark as safe") must not suppress.
- Performance smoke test on a generated large repo (marked `slow`).

## Code Layout
```text
vulnhawk/
├── pyproject.toml
├── README.md
├── PROJECT.md
├── .github/workflows/{ci.yml,release.yml}
├── src/vulnhawk/
│   ├── cli.py
│   ├── config.py
│   ├── core/{models.py,pipeline.py,dedupe.py,fingerprint.py}
│   ├── analyzers/{ast_pass.py,taint_pass.py,llm_pass.py,remediate.py}
│   ├── taint/{sources.py,sinks.py,sanitizers.py}        # framework models
│   ├── importers/{sarif.py,gitleaks.py,runner.py}
│   ├── plugins/{base.py,loader.py,rules/{sqli,cmdi,codei,weak_crypto}.py}
│   ├── ui/{theme.py,banner.py,formatter.py}
│   └── sarif/{generator.py,schema/sarif-2.1.0.json}
└── tests/
    ├── corpus/...
    ├── test_rules.py
    ├── test_taint.py
    ├── test_importers.py
    ├── test_dedupe.py
    ├── test_cli.py
    ├── test_sarif.py
    └── test_llm.py
```

## Dev Tooling (not shipped)
- codebase-memory-mcp or Graphify (Graphify-Labs) as a code-navigation aid for agents. Not a runtime dependency.
- Note: `graphify.net` is flagged by Cloudflare as suspected phishing — use the GitHub repo only.

## Decisions Log
- 2026-10-08: Repo at `~/teamwork_projects/vulnhawk`. MVP = M0–M3. Secrets via Gitleaks import (own
  secrets detector dropped). Auth/IDOR deferred. CodeQL never bundled (license) — BYO SARIF only.
  Semgrep invoked as external CLI; its registry rules are not vendored (Semgrep Rules License).
- 2026-10-08 (Codex re-review): vendor-independent fingerprint via `vuln_class`; deterministic merge
  policy; importer run/BYO modes + failure semantics; SARIF fixes optional until M4; `--fail-on`
  excludes suppressed; LLM suppression requires verifiable evidence; full-context redaction.
  Verdict: ready for M0.
- 2026-10-08 (M0 impl): pipeline order is collect → `merge_findings` → `assign_ids` (ids are
  computed on merged findings). Identical sinks in one function get an occurrence suffix (`#n`,
  ordered by line), so inserting an identical sink earlier in the same function shifts later ids —
  accepted trade-off. Fingerprint ids prefixed `vh1-` (bump if the recipe changes).
- 2026-10-08 (Codex M0 code review): anchor-based column-aware clustering (no transitive fusion),
  `sink` field for fingerprints, union locations, evidence concatenation, canonical-JSON tie-breaks,
  end-column validation. Round 2: precision-first anchors, union on effective ends, merged
  findings keep a recorded `sink`; randomized order-independence test.
- 2026-10-08 (Codex M1 review): **rules report candidates, taint decides.** Rules no longer
  dismiss findings via flow-insensitive assignment lookups (e.g. a constant assigned under
  `if False`); every non-constant value at a sink is a candidate (lower confidence when
  unresolved), and constant/sanitized flows are suppressed by the M2 taint pass. Corpus marks
  these with `# expect-suppressed:`; the harness enforces the suppression once
  `TAINT_PASS_ENABLED` is flipped in M2. Name resolution is now scope-aware
  (`plugins/scopes.py`: function/class/global rules; decorators and defaults evaluate in the
  enclosing scope). SQLi requires a DB-looking receiver or SQL text in the literal parts.
  Plugins are type-validated; bad matches and declared source encodings are handled.
- 2026-10-08 (M2 impl): taint is flow-sensitive within a function — abstract interpretation
  over statements (branch joins, loop fixpoint, try/except, match, walrus, comprehensions,
  container mutators) with a `Taint(sources, unknown, safe_for)` lattice. Sinks inside
  decorators/defaults, lambdas and class bodies are analyzed in their own scopes. Module-level
  names bound only to constants (and never rebound via `global`) count as constants inside
  functions — the one deliberate exception to "flow inside one function". Sources: Flask
  `request.*`, `request`/`req` parameters (Django/DRF/Starlette/FastAPI), route-handler
  parameters, `input()`, `sys.argv`, `sys.stdin`. Confirmed = +35 confidence with a source
  trace. Inline suppression reason renamed to `inline:vulnhawk-ignore` (no spaces).
- 2026-10-08 (Codex M2 review): fixed five unsound suppressions. Taint values now track
  mutability (a mutable object that is aliased, mutated, passed to an unmodeled call, stored
  elsewhere or captured by a nested scope joins `unknown`), shell-quote context
  (`shlex.quote` safety is dropped when the surrounding string may open a quote), and
  statements are scanned in evaluation order (walrus/mutation/sink ordering). Module values
  count as constants only if immutable. `ast.literal_eval` removed from sanitizers.
  `self.request` (class-based views) is a source. Each case is a regression test that fails
  on the previous engine.
- 2026-10-08 (Codex M2 re-review): `except`/`finally` see the join of every state the `try`
  body passed through; aliases are tracked through calls/constructors (`dict(cmd=parts)`);
  any transformation of a shell-quoted value (strip/replace/slicing/repr) drops quoting
  safety. **Policy:** `shlex.quote` protects POSIX shells only (not Windows `cmd.exe`), and
  the target platform is unknown, so POSIX-quoted commands are never suppressed; they stay
  candidates at confidence 20 with an explanatory note. (A `--shell posix` option to restore
  suppression can be added in M3 config.)
