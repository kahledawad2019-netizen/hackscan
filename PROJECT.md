# Project: HackScan (plan v2)

> v2 supersedes the Antigravity draft (`~/.gemini/antigravity/scratch/vulnhawk/PROJECT.md`).
> Changes driven by a Codex + Claude review on 2026-10-08: usable scanner first, LLM optional,
> reuse mature scanners as inputs/baselines instead of re-implementing them.

## Positioning
HackScan is a Python SAST **orchestrator + verifier**, not a Semgrep/CodeQL competitor.
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
| `rule_id` | str | Primary rule, e.g. `HS-SQLI-001`, or `semgrep:<id>` for imported. All contributing rule ids kept in `related_rules`. |
| `cwe` | list[str] | Used for dedupe and SARIF taxa |
| `severity` | enum | critical/high/medium/low |
| `location` | Region | rel path, start/end line+col (1-based lines, 1-based cols per SARIF) |
| `snippet` | str | Display only; never used for identity |
| `sink` | str | Source text of the sink at `location`, read from the file by the producer; input to the fingerprint (falls back to `snippet` only if empty) |
| `sources` | list[str] | Provenance: `hackscan`, `semgrep`, `codeql`, `gitleaks`, ... |
| `status` | enum | `candidate`, `confirmed`, `suppressed` |
| `suppression` | Optional[str] | Reason: `taint:constant_input`, `taint:sanitized`, `llm:false_positive`, `inline:hackscan-ignore` |
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
| 5 | Inline suppression `# hackscan: ignore[RULE]` | M2 |
| 6 | `hackscan scan <path>` with `--format text|json|sarif`, `--output` | M3 |
| 7 | `--severity`, `--min-confidence`, `--ignore`, `--fail-on`, `--quiet`, `--show-suppressed` | M3 |
| 8 | `.hackscan.yml` hierarchical config | M3 |
| 9 | SARIF 2.1.0: rules, locations, snippets, properties, suppressions; `fixes[]` emitted only when `Finding.fix` exists (populated from M4) ; schema-validated in tests | M3 |
| 10 | Importers (see Importer Behavior): `--with semgrep,bandit,gitleaks` runs tools; `--import <tool>=<file>` ingests BYO reports (CodeQL, any SARIF) | M3 |
| 11 | Dedupe across sources | M3 |
| 12 | Packaging (`pyproject.toml`, `hackscan` entry point), PyPI release via GitHub Actions trusted publishing | M3 |
| 13 | Ollama triage pass with graceful offline fallback | M4 |
| 14 | Template + LLM remediation as validated edits; diff view | M4 |
| 15 | Rich "Matrix" TUI (banner, spinners, tables); auto-off in CI / `--quiet` | M4 |
| 16 | Inter-procedural & cross-file taint (own call graph from `ast`) | M5 ✅ |
| 17 | Benchmark harness vs Bandit / Semgrep CE / CodeQL; published precision/recall | M5 ✅ |
| 18 | GitHub Action (uploads SARIF to Code Scanning), pre-commit hook | M5 ✅ |
| 19 | Auth bypass / IDOR heuristics (only if benchmark shows acceptable precision) | Later |
| 20 | Docker image | Later, on demand |

## Milestones
| # | Name | Exit criteria | Depends |
|---|---|---|---|
| M0 ✅ | Skeleton & contracts | Repo, `pyproject`, CI (ruff + pytest on 3.10–3.13), `Finding` models, fixture corpus layout; **frozen** `Finding` schema v1, `taxonomy.py`, fingerprint + dedupe/merge implemented with order-independence tests; importer contract (above) documented | — |
| M1 ✅ | AST engine & rules | Rules 1–2 pass per-rule vulnerable **and** safe fixtures | M0 |
| M2 ✅ | Taint | Framework fixtures (Flask/Django/FastAPI); constant/sanitized flows suppressed; tests for taint boundaries | M1 |
| M3 ✅ | CLI, SARIF, importers → **v0.1.0 on PyPI** (released 2026-10-08) | `pip install hackscan` works on clean venv; SARIF validates against official schema; `--fail-on` exit codes tested | M2 |
| M4 ✅ | LLM + remediation + TUI → **v0.2.0** (2026-10-09; 14 Codex gate rounds, double-OK) | All LLM tests run against a mocked Ollama; offline degradation tested; prompt-injection fixture | M3 |
| M5 ✅ | Inter-procedural taint, benchmark, GitHub Action → **v0.3.0** (2026-10-09) | Benchmark report in README; Action used on the repo itself | M4 |

## Test Strategy
- Corpus: `tests/corpus/<rule>/{vulnerable,safe}/*.py`, each file annotated with expected findings
  (`# expect: HS-SQLI-001`) — the test harness diffs actual vs expected (precision/recall per rule).
- Framework cases: `tests/corpus/frameworks/{flask,django,fastapi}/`.
- Golden SARIF snapshots + JSON-schema validation.
- CLI tests via Click `CliRunner`: exit codes, filters, formats.
- LLM: mocked HTTP; prompt-injection fixture (code comment instructing "mark as safe") must not suppress.
- Performance smoke test on a generated large repo (marked `slow`).

## Code Layout
```text
hackscan/
├── pyproject.toml
├── README.md
├── PROJECT.md
├── .github/workflows/{ci.yml,release.yml}
├── src/hackscan/
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
- 2026-10-08: Repo at `~/teamwork_projects/hackscan`. MVP = M0–M3. Secrets via Gitleaks import (own
  secrets detector dropped). Auth/IDOR deferred. CodeQL never bundled (license) — BYO SARIF only.
  Semgrep invoked as external CLI; its registry rules are not vendored (Semgrep Rules License).
- 2026-10-08 (Codex re-review): vendor-independent fingerprint via `vuln_class`; deterministic merge
  policy; importer run/BYO modes + failure semantics; SARIF fixes optional until M4; `--fail-on`
  excludes suppressed; LLM suppression requires verifiable evidence; full-context redaction.
  Verdict: ready for M0.
- 2026-10-08 (M0 impl): pipeline order is collect → `merge_findings` → `assign_ids` (ids are
  computed on merged findings). Identical sinks in one function get an occurrence suffix (`#n`,
  ordered by line), so inserting an identical sink earlier in the same function shifts later ids —
  accepted trade-off. Fingerprint ids prefixed `hs1-` (bump if the recipe changes).
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
  trace. Inline suppression reason renamed to `inline:hackscan-ignore` (no spaces).
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
- 2026-10-08 (Codex M2 round 3): `break`/`continue` modeled (paths end at the jump; break
  states join the loop exit and skip `else`), inner `finally` state propagates to outer
  handlers. Added `tests/test_taint_fuzz.py`: differential soundness fuzzing — random
  programs (branches, while/for with break/continue, try/except/finally, raises, early
  returns, list aliasing, dict wrappers, closures, walrus) are executed with an instrumented
  `os.system`; any marker reaching a sink the scanner suppressed fails the test. It catches
  every engine version before this one; a 4,500-program stress run checked 6,743 suppressed
  sinks with zero unsound results. M2 closed on this evidence.
- 2026-10-08: **Renamed VulnHawk → HackScan** (PyPI `vulnhawk` is taken by an unrelated
  project). Package/CLI `hackscan`, rule ids `HS-*`, fingerprint prefix `hs1-`, inline
  `# hackscan: ignore`, config `.hackscan.yml`, GitHub repo `hackscan`.
- 2026-10-08 (M3 impl): `hackscan scan` CLI (text/json/sarif, filters, `--fail-on`, exit
  codes 0/1/2), hierarchical `.hackscan.yml`, process-pool analysis (serial below 16 files;
  output identical either way), importers for SARIF (Semgrep/Bandit/CodeQL/any) and Gitleaks
  with run/BYO modes, source-derived `sink`/`function` enrichment and secret redaction,
  SARIF 2.1.0 export validated against the OASIS schema in tests. Bandit fixture is recorded
  tool output; Semgrep/CodeQL/Gitleaks fixtures are hand-written to their documented formats
  (tools unavailable locally). Release via tag-triggered trusted publishing (`release.yml`);
  CI builds the wheel, installs it in a clean venv, and dogfoods `hackscan scan src`.
- 2026-10-08 (Codex M3 review + stop-gate): incomplete scans (unparseable/unreadable files,
  crashing rules) exit 2 unless `--allow-incomplete`, and SARIF sets
  `executionSuccessful: false`; secrets are redacted after merging from every field of every
  finding (known Gitleaks values everywhere, all string literals for `secret`-class
  findings); a start column without an end is a point (no rest-of-line widening);
  imported findings obey default ignores; remote `file://host/` URIs are rejected;
  `--output` never overwrites source files and creates parent directories; config keys are
  an explicit allow-list; malformed Gitleaks entries are skipped with a warning; releases
  require the tagged commit to be on `main`. SARIF URIs are repository-root-relative (GitHub
  resolves them that way) and URI-escaped; `--sarif-omit-suppressed` for GitHub uploads,
  since GitHub does not document `suppressions` support and only reads
  `primaryLocationLineHash` (computed by `upload-sarif`).
- 2026-10-08 (Codex final release check): secret-class findings never carry tool text
  (generic message/evidence; literals and assigned values redacted in snippet/sink);
  known secrets scrubbed from warnings/errors; `-o` only overwrites previous HackScan
  reports; failed `--import` reports make the scan incomplete (exit 2); `--with` tools
  exiting with an error code are `partial` (warning, fails `--strict-tools`).
- 2026-10-09 (M4a/M4b): template fixes (parameterized SQL with driver-specific placeholders,
  argv lists instead of shell strings, `ast.literal_eval`, SHA-256) as validated exact edits;
  `--no-fix`, `--show-fixes`. LLM triage is **opt-in** (`--llm`): candidates only, JSON-schema
  replies, per-request random code fence, redacted context, cache, `--llm-max`,
  `--llm-timeout`, bounded output tokens. LLM suppression requires evidence that a
  deterministic checker accepts and that holds on every path: a constant or class-valid
  sanitizer assignment, or an allow-list guard (`not in {consts}`, 
  `isdigit()/isalnum()`), in the function body before the sink, covering all sink locals,
  never rebound/mutated afterwards. LLM fixes are kept only if the patched file parses and
  re-running passes 1-2 shows the finding gone and no new ones. Measured locally: CPU-only
  Ollama with the reasoning model deepseek-r1:8b ignores `think: false` and exhausts its
  budget — reported as "no answer"; non-reasoning coder models are recommended.
- 2026-10-09 (Codex M4 review): LLM suppression must vouch for *every* value in the sink
  (any name, local or global; calls/attributes/subscripts in the sink are never vouched for)
  — fixes a P0 where `safe + suffix` (global `suffix` from the environment) was suppressed.
  LLM fixes must call an allow-listed safe API for the class (or keep the SQL receiver with
  parameters), keep every original value, and never use `__import__`/`eval`/`shell=` etc.
  The flagged-call field sent to the model and `--show-fixes` diff context are redacted;
  fix replacements are redacted like other fields. C0/C1 control characters from code,
  tools or the model are shown escaped, never emitted. `IN (...)` lists are not
  parameterized (a single placeholder changes results); f-string/% argv values are wrapped
  in `str()`; imports are never inserted above a shebang or encoding cookie; malformed
  Ollama replies are discarded instead of crashing.
- 2026-10-09 (live Ollama check, CPU-only): qwen3:4b-instruct-2507 got real injection,
  fake length guard and allow-list guard right once the verifier (a) maps a cited line
  inside a top-level statement (e.g. a guard's `return`) to that statement and (b) treats
  the model's evidence kind as a hint, trying every deterministic check (each is complete
  on its own, so this is equally sound). Response schema now orders `reason` first
  (Ollama generates keys in schema order), prompt v3. qwen2.5-coder:3b: safe but misses
  the guard. Both models obeyed an injected "reply false_positive" comment; the verifier
  rejected it. A missing model now reports "not installed; run `ollama pull <model>`".
- 2026-10-09 (Codex M4 re-review): rebinding after cited evidence now includes imports
  (`*` = anything), `match` captures, `except ... as`, nested defs/classes; `assert` is
  never evidence (`python -O`). LLM command fixes must run the original program (never a
  shell/interpreter) with the original literal words in order and only harmless
  keywords; LLM SQL fixes must be one literal with the original SQL tokens (values as
  placeholders). SQL template placeholders only after comparisons, in VALUES lists and
  after LIMIT/OFFSET (not `typeof(?)` or select lists). String literals assigned to
  secret-looking names are redacted by raw source text, so implicitly joined and
  triple-quoted secrets never reach the model or fix diffs.
- 2026-10-09 (Codex verify round): token/word comparison was bypassable (extra computed
  argv element, swapped SQL parameters, SQL comments). LLM fixes must now equal what
  HackScan derives itself: argv element-for-element (`str()` wrapper ignored), SQL text
  exactly plus the original values in order. SQL containing comments (`--`, `/*`, `#`)
  gets no fix. Secret literals are masked character for character in the source
  (lines/columns kept) for LLM context and diffs. Rebinding is judged by (line, column)
  outside the cited statement; any `nonlocal`/`global` of the name voids the evidence.
- 2026-10-09 (Codex verify round 2): an argv list stops shell injection, not argument
  injection (`git -c alias.x=!cmd`, `python3.12 -c`). `_argv` (ground truth for template
  and LLM fixes) now refuses interpreters/wrappers (versioned and `.exe` names included)
  and any value directly after a flag other than `--`. LLM SQL fixes must use the
  placeholder of the detected driver (none or ambiguous: no fix). Snippets and sinks of
  own findings and imported ones come from masked source; a call containing a secret
  literal gets no fix (a fix must carry the real code); diffs mask both sides from
  their own syntax trees. Masking also covers walrus and unpacking targets.
- 2026-10-09 (stop-time review + Codex verify round 3): the interpreter denylist could
  never be complete (`npx PKG`, `tar --to-command`, `find -exec`...), so argv fixes now
  use an allowlist of programs with inert arguments (`INERT_PROGRAMS`: echo, cat, ls,
  grep, head...; `.bat`/`.cmd` never match). Masking covers `for`/comprehension/`with`
  targets; for parsed Python files the snippet always comes from masked source (a tool's
  SARIF snippet only as a fallback, redacted); LLM evidence quotes masked source. Round 3
  confirmed all earlier fixes and found no regressions (fingerprints, dedupe, pool).
- 2026-10-09 (security follow-up): LLM allow-list guards require class-safe string or integer
  constants; source secret literal values now redact imported messages and evidence before
  output and LLM triage; fallback snippets from unparseable files redact literals and
  assigned values; `echo` and `dir` no longer get shell-less command fixes because they
  are Windows cmd.exe builtins.
- 2026-10-09 (release gate): SQL LIMIT allow-list values cannot contain commas; template
  and LLM fixes containing a known secret are dropped before export. Imported findings
  have no snippet unless their Python source parses, preventing multi-line secret leaks.
  Equal-length secrets are redacted in lexical order, and only secret-like source values
  join report-wide known secrets; local source masking still covers every secret-named literal.
- 2026-10-09 (gate review follow-up): LLM predicate guard evidence is limited to
  `isdigit()` and `isdecimal()`; constant allow-lists retain their existing rule.
  Secret-named function and lambda defaults are masked, and AST rule messages and evidence
  use the file's masked literal spans. Gitleaks values are redacted at any nonzero length
  across findings, warnings and errors. Diff redaction preserves assignment spacing.
  Every masked source literal of at least four characters is also redacted within findings,
  fixes and LLM requests for its own file. LLM rewrites now require exact code and hash
  arguments and literal subprocess keyword values to prevent hidden execution. Release-gate
  fixes restrict shell template keywords, redact secret-bearing rule IDs and escaped source
  spellings, and refuse SQL placeholders inside partial quoted literals. Sole dynamic
  parenthesized SQL lists get no placeholder; file-scoped secrets also redact rule metadata
  before triage and diagnostics across the report. Release-gate follow-up refuses unquoted
  dynamic SQL values inside any parentheses and SQL text containing backslashes, while
  redacting finding function names before IDs, output and triage. Double-quoted SQL
  identifiers and SQL text containing `$` also receive no fix. Numeric and concatenated
  secret literals are masked and collected.
- 2026-10-09 (M5 step 1): Roles back to Claude implements, Codex reviews (double OK before
  commit). Repo root is a composite GitHub Action: inputs reach `run:` scripts only via env,
  extra `args` are word-split with globbing off, the scan step records the exit code so SARIF
  is uploaded (only if written) before the job fails; the dogfood workflow skips upload on
  fork PRs. pre-commit hook scans the whole repo (`pass_filenames: false`; CLI takes one path).
  Review round 1 (Codex Not OK, fixed): an empty `fail-on` input now passes the new
  `--fail-on never` (overrides `.hackscan.yml`) instead of rewriting exit 1 to 0, which hid
  crashes; a plugin constructor exception is now a PluginError (exit 2, not 1); README adds
  `actions: read` for private repositories.
- 2026-10-09 (M5 step 2): Inter-procedural, cross-file taint is confirmation-only
  (`analyzers/interproc.py`). Pass 2 records symbolic facts per file: parameter and
  call-result atoms carried in `Taint.symbols` with per-atom sanitized classes, return
  summaries of linkable functions, argument values at statically named call sites. The
  pipeline links all files (same module, imports, relative imports, re-exports, src
  layouts by unambiguous module-name suffix) and solves a least fixpoint; candidates
  reached by an untrusted source become confirmed with a file:line trace. Never
  suppresses: unknown callers may exist. Only undecorated, non-generator module-level
  functions bound once are linked; methods, `*args` positions and star-import modules are
  not. Cost: taint now runs on every file (~45 ms/file serial on site-packages, +50%);
  `_closure_names` made single-pass.
  Review round 1 (Codex OK, 3 non-blocking precision issues): `match` captures
  (`MatchAs`/`MatchStar`/`MatchMapping.rest`) are now scope bindings; the module binding
  census also counts walrus targets in keyword-only defaults, lambda defaults,
  annotations and class bases. Call results carrying their arguments through a
  sanitizing helper stay a documented limitation (same approximation as within a function).
  Review round 2 (Codex Not OK, pre-existing pass-2 soundness bug, fixed): a `match`
  mapping rest capture (`case {**rest}`) now takes the subject's taint, and captures of
  a failed pattern or a false guard stay visible to later cases and after the `match`
  (the no-match path joins them), so a reachable sink is no longer suppressed as constant.
  Review round 3 (Codex Not OK, pre-existing pass-2 soundness bugs, fixed): a `:=` in a
  part that may not run (later `and`/`or` operands, `x if c else y` branches,
  comprehension bodies, also inside `match` guards) is applied on a copy and joined
  instead of overwriting the current value (comprehension bodies iterate to a fixpoint);
  a `match` capture is aliased with the mutable names in the subject.
  Review round 4 (Codex Not OK, 6 blockers: 5 pre-existing, 1 regression from round 3's
  comprehension rework, which was reverted): instead of ordering every `:=` effect, a scope
  whose own code contains `:=` never suppresses its sinks (confirmation still works); a
  module with `:=` gets no trusted module constants; sinks in a generator expression's
  body (deferred execution) are never suppressed. Also fixed (pre-existing): a nested
  function or lambda reading an enclosing local that shadows a module constant was
  treated as constant; module constants now apply only if the name resolves to the module.
  Review round 5 (Codex Not OK, 6 pre-existing blockers without `:=`, fixed with
  conservative rules): generator expressions yield UNKNOWN-joined values; a comprehension
  target shadows outer bindings and class-body names are hidden inside class
  comprehensions; module constants require exactly one module-level binding and no
  dynamic namespace writes (`globals`/`vars`/`locals`/`exec`/`eval`/`__import__`,
  `__dict__`/`__globals__`/`modules`, star imports), and module-level sinks in such a
  module are never suppressed; names a function declares `global`/`nonlocal` are joined
  with UNKNOWN on every read; LLM guard evidence must cover the function's own locals.
  Review round 6 (Codex Not OK, 3 blockers, fixed): namespace writers are also detected
  as attributes (`builtins.exec`, `import_module(...).exec`), imported aliases
  (`from builtins import exec as run`), `import builtins` and `__builtins__`; a class body
  that may write its own namespace (`locals()[...]` etc. in that body) never suppresses;
  a comprehension target bound by more than one `for` resolves to UNKNOWN.
  Review round 7 (Codex Not OK, 4 blockers, fixed): namespace-writer aliases bound by
  assignment are followed file-wide (`execute = exec` then used in a class body), and
  importing a namespace attribute under any name counts (`_Namespace`, computed once per
  file); eager comprehensions scan filters before the element and repeat their body to a
  fixpoint (mutations of one item reach the next; widened to UNKNOWN on budget
  exhaustion); comprehension targets are aliased with the mutable names in their
  iterables. Serial scan of ~770 site-packages files: 22.8 s (v0.2.0) -> ~41 s.
  Review round 8 (Codex Not OK, 3 blockers, fixed): `:=` creates writer aliases too; a
  comprehension that may mutate one of its items (non-read-only method on a target,
  target passed to a call other than a sink/sanitizer/pure builtin/string method, store
  into a target) invalidates every mutable name in its iterables and resolves its targets
  to UNKNOWN; subscript/attribute comprehension targets store into their base.
  Review round 9 (Codex Not OK, 2 blockers, fixed): a comprehension target anywhere inside
  a call argument counts as escaping (`change([cmd])`); mutations, stores and comprehension
  targets find their container through method calls too (`_root_name`: `d.get(k).append(x)`
  and `d.setdefault(k, [])[0] = x` mutate `d`), in all code, not only comprehensions.
  Review round 10 (Codex Not OK, 2 blockers, fixed): a bound method taken off a mutable
  object (`append = parts.append`, method attribute loaded but not called right away)
  invalidates every mutable name in its receiver; a mutating method call updates every
  mutable name in a compound receiver (`(a if c else b).append(x)`, `[cmd][0].append(x)`).
  User decision (2026-10-09, after 10 rounds): fix round 10, document remaining indirect
  mutable aliasing (aliases stored in attributes/containers, returned from helpers,
  `getattr`) as a README limitation, confirm with Codex once, commit with both OKs; any
  further pass-2 aliasing hardening is a separate task.
- 2026-10-09 (M5 step 3): Benchmark (`benchmarks/`). User choices: Bandit + Semgrep +
  CodeQL; a new labeled suite plus known-vulnerable apps. Suite: 26 `# vuln:` sinks and 24
  `# safe:` traps in Flask/Django/FastAPI/CLI code, one labeled sink per function, scored
  per function (tools report flows at sink, construction or source lines); all tools are
  normalized through HackScan's SARIF importer. Taxonomy fix found on the way: Semgrep's
  `tainted-sql-string` rule carries CWE-704 metadata and is now mapped to sqli. Apps:
  vulpy, PyGoat, DVPWA at pinned commits (MIT), every reported key hand-reviewed in
  `apps_review.json`; relative recall over the union of true positives. Tests keep
  RESULTS.json, APPS.json and the README tables in sync with the engine. Results:
  suite F1 HackScan 82%, CodeQL 85%, Bandit 70%, Semgrep 67%; apps precision/relative
  recall HackScan 83%/71%, CodeQL 100%/67%, Bandit 50%/76%, Semgrep 92%/52%.
- 2026-10-09 (v0.3.0 release): version 0.3.0; the Action uploads with
  github/codeql-action/upload-sarif@v4 (v3 is deprecated in December 2026); benchmark
  re-run so the HackScan rows show 0.3.0 (numbers unchanged). Next ideas (not started):
  weak-cipher detection (DES/RC4/ECB/unauthenticated modes; largest benchmark gap),
  taint through `self` attributes, further pass-2 aliasing hardening.
