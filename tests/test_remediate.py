from __future__ import annotations

import shlex
import sqlite3
import textwrap
from pathlib import Path

import pytest

from hackscan.analyzers.ast_pass import analyze_source
from hackscan.analyzers.remediate import apply_edits, fix_diff, generate_fixes
from hackscan.config import HackScanConfig
from hackscan.core.models import Region, Status
from hackscan.core.pipeline import scan
from hackscan.importers.common import SourceIndex
from hackscan.plugins.loader import builtin_plugins

CORPUS = Path(__file__).parent / "corpus"


def fixes_for(tmp_path: Path, code: str):
    source = textwrap.dedent(code)
    (tmp_path / "m.py").write_text(source, encoding="utf-8")
    findings = analyze_source(source, "m.py", builtin_plugins()).findings
    return source, generate_fixes(findings, SourceIndex(tmp_path))


def fixed_source(tmp_path: Path, code: str) -> tuple[str, str]:
    source, findings = fixes_for(tmp_path, code)
    (f,) = [f for f in findings if f.fix is not None]
    return source, apply_edits(source, f.fix.edits)


# -- SQL injection ---------------------------------------------------------------------------


def test_sqli_fstring_becomes_parameterized_and_is_safe(tmp_path: Path):
    _, new = fixed_source(
        tmp_path,
        """
        import sqlite3

        def find(cur, name):
            return cur.execute(f"SELECT id FROM users WHERE name = '{name}'").fetchall()
        """,
    )
    assert "WHERE name = ?', (name,))" in new
    namespace: dict = {}
    exec(compile(new, "m.py", "exec"), namespace)
    db = sqlite3.connect(":memory:")
    db.execute("CREATE TABLE users (id INTEGER, name TEXT)")
    db.executemany("INSERT INTO users VALUES (?, ?)", [(1, "alice"), (2, "bob")])
    cur = db.cursor()
    assert namespace["find"](cur, "alice") == [(1,)]
    assert namespace["find"](cur, "x' OR '1'='1") == []  # payload is just a value now


@pytest.mark.parametrize(
    ("query", "expected"),
    [
        (
            '"SELECT * FROM t WHERE a = %s AND b = %s" % (x, y)',
            "'SELECT * FROM t WHERE a = ? AND b = ?', (x, y)",
        ),
        ('"SELECT * FROM t WHERE a = " + x', "'SELECT * FROM t WHERE a = ?', (x,)"),
        ('"SELECT * FROM t WHERE a IN (" + x + ")"', "'SELECT * FROM t WHERE a IN (?)', (x,)"),
        ('f"SELECT * FROM t LIMIT {n}"', "'SELECT * FROM t LIMIT ?', (n,)"),
    ],
)
def test_sqli_forms(tmp_path: Path, query: str, expected: str):
    _, new = fixed_source(
        tmp_path, f"import sqlite3\n\ndef f(cur, x, y, n):\n    cur.execute({query})\n"
    )
    assert expected in new


def test_sqli_psycopg_uses_format_placeholders(tmp_path: Path):
    _, new = fixed_source(
        tmp_path,
        'import psycopg2\n\ndef f(cur, x):\n    cur.execute(f"DELETE FROM t WHERE id = {x}")\n',
    )
    assert "'DELETE FROM t WHERE id = %s', (x,)" in new


@pytest.mark.parametrize(
    "code",
    [
        # identifier positions cannot be parameters
        'import sqlite3\ndef f(cur, t):\n    cur.execute(f"SELECT * FROM {t}")\n',
        'import sqlite3\ndef f(cur, o):\n    cur.execute("SELECT * FROM t ORDER BY " + o)\n',
        # LIKE wildcards around the value
        'import sqlite3\ndef f(cur, q):\n    cur.execute("SELECT * FROM t WHERE n LIKE \'%" + q + "%\'")\n',
        # value glued into a larger quoted string
        "import sqlite3\ndef f(cur, q):\n    cur.execute(f\"SELECT * FROM t WHERE n = 'x{q}'\")\n",
        # unknown driver / ambiguous drivers
        'def f(cur, x):\n    cur.execute(f"SELECT * FROM t WHERE a = {x}")\n',
        'import sqlite3, psycopg2\ndef f(cur, x):\n    cur.execute(f"SELECT * FROM t WHERE a = {x}")\n',
        # format spec / conversion changes the value
        'import sqlite3\ndef f(cur, x):\n    cur.execute(f"SELECT * FROM t WHERE a = {x!r}")\n',
        # already has parameters
        'import sqlite3\ndef f(cur, x, p):\n    cur.execute(f"SELECT * FROM t WHERE a = {x}", p)\n',
    ],
)
def test_sqli_no_fix_when_unsafe_or_ambiguous(tmp_path: Path, code: str):
    _, findings = fixes_for(tmp_path, code)
    assert findings and all(f.fix is None for f in findings)


# -- command injection ---------------------------------------------------------------------


def test_os_system_becomes_argument_list(tmp_path: Path):
    source, new = fixed_source(
        tmp_path, 'import os\n\ndef ping(host):\n    return os.system("ping -c 1 " + host)\n'
    )
    assert "return subprocess.call(['ping', '-c', '1', host])" in new
    assert new.startswith("import os\nimport subprocess\n")
    # Same argv the shell would have produced for benign input:
    assert shlex.split("ping -c 1 " + "example.com") == ["ping", "-c", "1", "example.com"]


def test_shell_true_drops_shell(tmp_path: Path):
    _, new = fixed_source(
        tmp_path,
        'import subprocess\n\ndef f(name):\n    subprocess.run(f"cat {name}", shell=True, check=True)\n',
    )
    assert "subprocess.run(['cat', name], check=True)" in new


@pytest.mark.parametrize(
    "cmd",
    [
        '"ls " + d + " | wc -l"',  # pipe: needs a shell
        '"echo \\"" + x + "\\""',  # quoting
        '"tar -czf backup-" + x + ".tgz"',  # value glued to text
        'f"rm {x}*"',  # glob
        "x",  # fully dynamic command
    ],
)
def test_cmdi_no_fix_for_shell_syntax(tmp_path: Path, cmd: str):
    _, findings = fixes_for(tmp_path, f"import os\n\ndef f(d, x):\n    os.system({cmd})\n")
    assert findings and all(f.fix is None for f in findings)


# -- code injection / weak hashing -------------------------------------------------------


def test_eval_becomes_literal_eval(tmp_path: Path):
    _, new = fixed_source(tmp_path, '"""Module."""\n\ndef f(s):\n    return eval(s)\n')
    assert new.startswith('"""Module."""\nimport ast\n')
    assert "return ast.literal_eval(s)" in new


def test_eval_with_namespaces_and_exec_get_no_fix(tmp_path: Path):
    _, findings = fixes_for(tmp_path, "def f(s, g):\n    eval(s, g)\n    exec(s)\n")
    assert all(f.fix is None for f in findings)


def test_md5_becomes_sha256(tmp_path: Path):
    _, new = fixed_source(
        tmp_path, "import hashlib\n\ndef f(d):\n    return hashlib.md5(d).hexdigest()\n"
    )
    assert "hashlib.sha256(d).hexdigest()" in new


def test_from_import_md5_gets_no_fix(tmp_path: Path):
    _, findings = fixes_for(tmp_path, "from hashlib import md5\n\ndef f(d):\n    return md5(d)\n")
    assert findings and all(f.fix is None for f in findings)


# -- invariants -------------------------------------------------------------------------------


def test_fixed_code_no_longer_triggers_the_rule(tmp_path: Path):
    code = textwrap.dedent(
        """
        import hashlib
        import os
        import sqlite3

        def a(cur, uid):
            cur.execute(f"SELECT * FROM users WHERE id = {uid}")

        def b(host):
            os.system("ping -c 1 " + host)

        def c(expr):
            return eval(expr)

        def d(data):
            return hashlib.md5(data).hexdigest()
        """
    )
    source, findings = fixes_for(tmp_path, code)
    assert all(f.fix is not None for f in findings)
    for f in findings:
        new = apply_edits(source, f.fix.edits)
        after = analyze_source(new, "m.py", builtin_plugins()).findings
        assert not [
            g for g in after if g.rule_id == f.rule_id and g.status is not Status.SUPPRESSED
        ]


def test_every_corpus_fix_parses_and_touches_only_its_call():
    result = scan(CORPUS, HackScanConfig())
    fixed = [f for f in result.findings if f.fix is not None]
    assert len(fixed) >= 10
    for f in fixed:
        source = (CORPUS / f.location.path).read_text(encoding="utf-8")
        new = apply_edits(source, f.fix.edits)
        compile(new, f.location.path, "exec")
        main_edit = f.fix.edits[-1]
        assert main_edit.region == f.location  # the reported call, nothing else
        assert all(e.region.start_line == e.region.end_line for e in f.fix.edits[:-1])
        assert fix_diff(source, f.fix, f.location.path).startswith(f"--- a/{f.location.path}")


def test_suppressed_findings_get_no_fix():
    result = scan(CORPUS, HackScanConfig())
    assert not [f for f in result.findings if f.status is Status.SUPPRESSED and f.fix]


def test_no_fix_flag_disables_fixes():
    result = scan(CORPUS, HackScanConfig(fixes=False))
    assert all(f.fix is None for f in result.findings)


def test_apply_edits_rejects_overlaps():
    from hackscan.core.models import FixEdit

    edits = (
        FixEdit(Region("a.py", 1, 1, 1, 5), "x"),
        FixEdit(Region("a.py", 1, 3, 1, 8), "y"),
    )
    with pytest.raises(ValueError):
        apply_edits("abcdefghij\n", edits)
