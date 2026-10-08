# Test corpus

Labeled Python files used to measure precision and recall per rule.

```
corpus/<vuln_class>/vulnerable/*.py   # every sink line carries an expectation
corpus/<vuln_class>/safe/*.py         # must produce zero open findings
corpus/frameworks/{flask,django,fastapi}/*.py
```

## Annotation format

Put the expectation on the line the finding should be reported at:

```python
cursor.execute(f"SELECT * FROM users WHERE id = {uid}")  # expect: VH-SQLI-001
```

- `# expect: <RULE> [<RULE> ...]` — open (candidate/confirmed) findings starting on this line;
  repeat a rule id for multiple findings (e.g. nested `eval(eval(x))`).
- `# expect: <RULE>!` — additionally requires the taint pass to *confirm* it
  (an untrusted source reaches the sink).
- `# expect-suppressed: <RULE> <reason>` — finding kept but suppressed, e.g.
  `# expect-suppressed: VH-SQLI-001 taint:constant_input` (also `taint:sanitized`,
  `inline:vulnhawk-ignore`).
- Any finding on a line without an annotation counts as a false positive.

Corpus files are data, not code under test: they are excluded from ruff and never imported.
