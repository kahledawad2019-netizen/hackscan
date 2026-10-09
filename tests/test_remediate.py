from __future__ import annotations

import ast
import shlex
import sqlite3
import textwrap
from dataclasses import replace
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
    ("query", "literal"),
    [
        ("f\"SELECT id FROM t WHERE note LIKE 'abc%' AND id = {x}\"", "abc%"),
        ("\"SELECT id FROM t WHERE note = '100%%' AND id = %s\" % x", "100%"),
    ],
)
@pytest.mark.parametrize(("module", "placeholder"), [("psycopg2", "%s"), ("sqlite3", "?")])
def test_sqli_literal_percent_uses_driver_escape(
    tmp_path: Path, query, literal, module, placeholder
):
    _, new = fixed_source(tmp_path, f"import {module}\ndef f(cur, x):\n    cur.execute({query})\n")
    execute = next(
        node
        for node in ast.walk(ast.parse(new))
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "execute"
    )
    sql = execute.args[0].value
    escaped_literal = literal.replace("%", "%%") if placeholder == "%s" else literal
    assert (
        sql
        == f"SELECT id FROM t WHERE note {'LIKE' if literal == 'abc%' else '='} '{escaped_literal}' AND id = {placeholder}"
    )
    if placeholder == "%s":
        assert sql % ("'v'",) == (
            f"SELECT id FROM t WHERE note {'LIKE' if literal == 'abc%' else '='} '{literal}' AND id = 'v'"
        )
        with pytest.raises(ValueError, match="unsupported format character"):
            sql.replace("%%", "%") % ("'v'",)


def test_sqli_percent_decimal_has_no_template_fix(tmp_path: Path):
    _, findings = fixes_for(
        tmp_path,
        'import sqlite3\ndef f(cur, x):\n    cur.execute("SELECT id FROM t WHERE id = %d" % x)\n',
    )
    assert findings and all(f.fix is None for f in findings)


def test_sqli_percent_decimal_changes_sqlite_result_when_bound():
    db = sqlite3.connect(":memory:")
    db.execute("CREATE TABLE t (id INTEGER)")
    db.execute("INSERT INTO t VALUES (1)")
    x = 1.9
    assert db.execute("SELECT id FROM t WHERE id = %d" % x).fetchall() == [(1,)]  # noqa: UP031
    assert db.execute("SELECT id FROM t WHERE id = ?", (x,)).fetchall() == []
    db.close()


@pytest.mark.parametrize("spacing", ["", "  "])
def test_sqli_refuses_sole_dynamic_parenthesized_list(tmp_path: Path, spacing: str):
    _, findings = fixes_for(
        tmp_path,
        "import sqlite3\ndef f(cur, x):\n"
        f'    cur.execute("INSERT INTO t(a,b) VALUES ({spacing}" + x + "{spacing})")\n',
    )
    assert findings and all(f.fix is None for f in findings)


@pytest.mark.parametrize(
    "query",
    [
        '"INSERT INTO t VALUES (" + x + ", 1)"',
        'f"INSERT INTO t VALUES (1, {x})"',
        'f"SELECT * FROM t WHERE (a = {x})"',
    ],
)
def test_sqli_refuses_unquoted_values_inside_parentheses(tmp_path: Path, query: str):
    _, findings = fixes_for(tmp_path, f"import sqlite3\ndef f(cur, x):\n    cur.execute({query})\n")
    assert findings and all(f.fix is None for f in findings)


def test_sqli_refuses_mysql_backslash_escaped_quote(tmp_path: Path):
    code = r"""import pymysql
def f(cur, x):
    cur.execute("SELECT * FROM t WHERE note = '\\' AND id = " + x + "'")
"""
    _, findings = fixes_for(tmp_path, code)
    assert findings and all(f.fix is None for f in findings)


@pytest.mark.parametrize(
    ("query", "has_fix"),
    [
        ('f"SELECT 1 AS `label = {uid}`"', False),
        ('f"SELECT [label = {uid}]"', False),
        ('f"SELECT * FROM t WHERE id = {uid}"', True),
    ],
)
def test_sqli_quoted_identifiers_refuse_template_fix(tmp_path: Path, query: str, has_fix: bool):
    _, findings = fixes_for(
        tmp_path, f"import sqlite3\ndef f(cur, uid):\n    cur.execute({query})\n"
    )
    assert findings and any(f.fix is not None for f in findings) is has_fix


def test_sqli_comparison_after_parentheses_in_literal_still_gets_fix(tmp_path: Path):
    _, new = fixed_source(
        tmp_path,
        "import sqlite3\ndef f(cur, x):\n"
        "    cur.execute(f\"SELECT * FROM t WHERE note = '(' AND id = {x}\")\n",
    )
    assert "WHERE note = '" in new
    assert "' AND id = ?" in new
    assert ", (x,))" in new


def test_sqli_refuses_separate_unquoted_values(tmp_path: Path):
    _, findings = fixes_for(
        tmp_path,
        "import sqlite3\ndef f(cur, x, y):\n"
        '    cur.execute("INSERT INTO t(a,b) VALUES (" + x + ", " + y + ")")\n',
    )
    assert findings and all(f.fix is None for f in findings)


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


@pytest.mark.parametrize(
    "code",
    [
        'import os\ndef f(value):\n    subprocess = Wrapper()\n    os.system(f"ls -- {value}")\n',
        'import os\ndef f(value, subprocess):\n    os.system(f"ls -- {value}")\n',
        'import os\nsubprocess = object()\ndef f(value):\n    os.system(f"ls -- {value}")\n',
        'import os\nfrom mylib import subprocess\ndef f(value):\n    os.system(f"ls -- {value}")\n',
        'import os\nimport subprocess\ndef f(value):\n    subprocess = Wrapper()\n    os.system(f"ls -- {value}")\n',
        'import os\ndef f(value):\n    def subprocess():\n        pass\n    os.system(f"ls -- {value}")\n',
        'import os\nfrom mylib import *\ndef f(value):\n    os.system(f"ls -- {value}")\n',
    ],
)
def test_os_system_refuses_shadowed_subprocess(tmp_path: Path, code: str):
    _, findings = fixes_for(tmp_path, code)
    assert findings and all(f.fix is None for f in findings)


@pytest.mark.parametrize("prefix", ["import os\n", "import os\nimport subprocess\n"])
def test_os_system_accepts_safe_subprocess_name(tmp_path: Path, prefix: str):
    source, findings = fixes_for(
        tmp_path, prefix + 'def f(value):\n    os.system(f"ls -- {value}")\n'
    )
    (fix,) = [f.fix for f in findings if f.fix is not None]
    new = apply_edits(source, fix.edits)
    assert "subprocess.call(['ls', '--', str(value)])" in new
    assert new.count("import subprocess\n") == 1


@pytest.mark.parametrize(
    "binding",
    [
        "str = eval\n",
        "from mylib import *\n",
    ],
)
def test_os_system_refuses_unsafe_introduced_str(tmp_path: Path, binding: str):
    _, findings = fixes_for(
        tmp_path, "import os\n" + binding + 'def f(value):\n    os.system(f"ls -- {value}")\n'
    )
    assert findings and all(f.fix is None for f in findings)


def test_os_system_refuses_existing_name_called_as_builtin(tmp_path: Path):
    _, findings = fixes_for(
        tmp_path,
        'import os\nstr = eval\ndef f(value):\n    os.system(f"ls -- {value} {str}")\n',
    )
    assert findings and all(f.fix is None for f in findings)


def test_os_system_refuses_local_shadowed_str(tmp_path: Path):
    _, findings = fixes_for(
        tmp_path,
        'import os\ndef f(value):\n    str = repr\n    os.system(f"ls -- {value}")\n',
    )
    assert findings and all(f.fix is None for f in findings)


@pytest.mark.parametrize(("conversion", "has_fix"), [("d", False), ("s", True)])
def test_os_system_percent_conversion_fix(tmp_path: Path, conversion: str, has_fix: bool):
    source, findings = fixes_for(
        tmp_path,
        f'import os\n\ndef f(n):\n    os.system("ls %{conversion}" % n)\n',
    )
    assert findings
    fixes = [f.fix for f in findings if f.fix is not None]
    assert bool(fixes) is has_fix
    if has_fix:
        assert "subprocess.call(['ls', str(n)])" in apply_edits(source, fixes[0].edits)


def test_shell_true_drops_shell(tmp_path: Path):
    _, new = fixed_source(
        tmp_path,
        'import subprocess\n\ndef f(name):\n    subprocess.run(f"cat {name}", shell=True, check=True)\n',
    )
    assert "subprocess.run(['cat', str(name)], check=True)" in new  # f-string calls str()


@pytest.mark.parametrize(
    ("extra", "safe"),
    [
        ('executable="/bin/sh"', False),
        ('env={"PATH": "/tmp"}', False),
        ("timeout=seconds()", False),
        ("check=True, timeout=5, stdout=subprocess.PIPE", True),
        ("check=enabled", True),
    ],
)
def test_shell_template_only_preserves_safe_keywords(tmp_path: Path, extra: str, safe: bool):
    code = (
        "import subprocess\n\ndef f(path):\n"
        f'    subprocess.run(f"cat {{path}}", shell=True, {extra})\n'
    )
    source, findings = fixes_for(tmp_path, code)
    assert findings
    fixes = [f.fix for f in findings if f.fix is not None]
    if safe:
        assert len(fixes) == 1
        assert f"subprocess.run(['cat', str(path)], {extra})" in apply_edits(source, fixes[0].edits)
    else:
        assert not fixes


def test_shell_template_rejects_extra_positional_args(tmp_path: Path):
    _, findings = fixes_for(
        tmp_path,
        'import subprocess\n\ndef f(path):\n    subprocess.run(f"cat {path}", None, shell=True)\n',
    )
    assert findings and all(f.fix is None for f in findings)


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


def test_eval_refuses_star_import(tmp_path: Path):
    _, findings = fixes_for(tmp_path, "from mylib import *\ndef f(s):\n    return eval(s)\n")
    assert findings and all(f.fix is None for f in findings)


def test_eval_refuses_shadowed_ast(tmp_path: Path):
    _, findings = fixes_for(tmp_path, "def f(s):\n    ast = object()\n    return eval(s)\n")
    assert findings and all(f.fix is None for f in findings)


def test_eval_refuses_rebound_ast_import(tmp_path: Path):
    _, findings = fixes_for(tmp_path, "import ast\nast = object()\ndef f(s):\n    return eval(s)\n")
    assert findings and all(f.fix is None for f in findings)


def test_weak_crypto_refuses_rebound_hashlib_import(tmp_path: Path):
    _, findings = fixes_for(
        tmp_path, "import hashlib\nhashlib = wrapper\ndef f(data):\n    return hashlib.md5(data)\n"
    )
    assert findings and all(f.fix is None for f in findings)


def test_nested_eval_only_fixes_inner_call(tmp_path: Path):
    _, findings = fixes_for(tmp_path, "def f(x):\n    return eval(eval(x))\n")
    by_sink = {f.sink: f for f in findings}
    assert by_sink["eval(eval(x))"].fix is None
    inner = by_sink["eval(x)"].fix
    assert inner is not None
    assert any(edit.replacement == "ast.literal_eval(x)" for edit in inner.edits)


def test_command_containing_eval_gets_no_fix(tmp_path: Path):
    _, findings = fixes_for(tmp_path, 'import os\n\ndef f(x):\n    os.system("ls " + eval(x))\n')
    by_sink = {f.sink: f for f in findings}
    assert by_sink['os.system("ls " + eval(x))'].fix is None


def test_nested_builtin_sink_blocks_fix_even_when_omitted_from_findings(tmp_path: Path):
    source = "def f(x):\n    return eval(eval(x))\n"
    (tmp_path / "m.py").write_text(source, encoding="utf-8")
    findings = analyze_source(source, "m.py", builtin_plugins()).findings
    outer = next(f for f in findings if f.sink == "eval(eval(x))")
    (result,) = generate_fixes([outer], SourceIndex(tmp_path))
    assert result.fix is None


def test_suppressed_nested_finding_from_any_rule_blocks_fix(tmp_path: Path):
    source = "def f(x):\n    return eval(str(x))\n"
    (tmp_path / "m.py").write_text(source, encoding="utf-8")
    (outer,) = analyze_source(source, "m.py", builtin_plugins()).findings
    inner = replace(
        outer,
        rule_id="external:rule",
        location=Region("m.py", 2, 17, 2, 23),
        status=Status.SUPPRESSED,
        suppression="test",
    )
    result = generate_fixes([outer, inner], SourceIndex(tmp_path))
    assert result[0].fix is None


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


# -- Codex M4 review regressions -------------------------------------------------------


def test_in_list_is_not_parameterized(tmp_path: Path):
    code = 'import sqlite3\ndef f(cur, ids):\n    cur.execute("SELECT * FROM t WHERE a IN (" + ids + ")")\n'
    _, findings = fixes_for(tmp_path, code)
    assert findings and all(f.fix is None for f in findings)
    db = sqlite3.connect(":memory:")  # why: IN (?) with "1,2" would match nothing
    db.execute("CREATE TABLE t (a INTEGER)")
    db.executemany("INSERT INTO t VALUES (?)", [(1,), (2,)])
    assert len(db.execute("SELECT * FROM t WHERE a IN (" + "1,2" + ")").fetchall()) == 2
    assert db.execute("SELECT * FROM t WHERE a IN (?)", ("1,2",)).fetchall() == []


def test_fstring_argv_values_are_stringified_and_run(tmp_path: Path):
    import subprocess

    _, new = fixed_source(tmp_path, 'import os\n\ndef f(n):\n    return os.system(f"cat {n}")\n')
    assert "subprocess.call(['cat', str(n)])" in new
    namespace: dict = {}
    calls = []
    exec(compile(new, "m.py", "exec"), namespace)
    namespace["subprocess"] = type(
        "S", (), {"call": staticmethod(lambda argv: calls.append(argv) or 0)}
    )
    namespace["f"](3)  # an int used to raise TypeError inside subprocess
    assert calls == [["cat", "3"]] and all(isinstance(a, str) for a in calls[0])
    assert subprocess  # real module untouched


@pytest.mark.parametrize("program", ["echo", "dir"])
def test_cmd_builtins_get_no_shellless_fix(tmp_path: Path, program: str):
    _, findings = fixes_for(
        tmp_path, f'import os\n\ndef f(x):\n    os.system(f"{program} {{x}}")\n'
    )
    assert findings and all(f.fix is None for f in findings)


def test_import_insertion_keeps_shebang_and_coding_cookie(tmp_path: Path):
    _, new = fixed_source(
        tmp_path, "#!/usr/bin/env python3\n# -*- coding: utf-8 -*-\ndef f(s):\n    return eval(s)\n"
    )
    lines = new.splitlines()
    assert lines[0] == "#!/usr/bin/env python3"
    assert lines[1] == "# -*- coding: utf-8 -*-"
    assert lines[2] == "import ast"


def test_crlf_file_fix_keeps_line_endings(tmp_path: Path):
    source = "import hashlib\r\n\r\ndef f(d):\r\n    return hashlib.md5(d).hexdigest()\r\n"
    (tmp_path / "m.py").write_bytes(source.encode())
    findings = analyze_source(source, "m.py", builtin_plugins()).findings
    (f,) = generate_fixes(findings, SourceIndex(tmp_path))
    new = apply_edits(source, f.fix.edits)
    assert "hashlib.sha256(d)" in new and new.count("\r\n") == source.count("\r\n")


def test_multiline_call_fix(tmp_path: Path):
    code = 'import sqlite3\n\ndef f(cur, uid):\n    cur.execute(\n        f"SELECT * FROM t WHERE id = {uid}"\n    )\n'
    _, new = fixed_source(tmp_path, code)
    compile(new, "m.py", "exec")
    assert "cur.execute('SELECT * FROM t WHERE id = ?', (uid,))" in new


# -- Codex M4 re-review: placeholders only where binding keeps the meaning -------------


@pytest.mark.parametrize(
    "query",
    [
        'f"SELECT typeof({x})"',
        'f"SELECT a, {x} FROM t"',
        'f"SELECT * FROM t WHERE f({x}) = 1"',
        # Codex verify round: a comment that fakes a value position
        'f"SELECT typeof(/* VALUES ( */{x})"',
        'f"SELECT typeof(-- = \\n{x})"',
        'f"SELECT * FROM t WHERE id = {x} -- note"',
    ],
)
def test_no_placeholder_in_function_calls_or_select_lists(tmp_path: Path, query):
    code = f"import sqlite3\ndef f(cur, x):\n    cur.execute({query})\n"
    _, findings = fixes_for(tmp_path, code)
    assert findings and all(f.fix is None for f in findings)


def test_typeof_changes_meaning_when_bound():
    db = sqlite3.connect(":memory:")
    assert db.execute("SELECT typeof(" + "1" + ")").fetchone() == ("integer",)
    assert db.execute("SELECT typeof(?)", ("1",)).fetchone() == ("text",)


@pytest.mark.parametrize(
    ("query", "expected"),
    [
        ("f\"INSERT INTO t VALUES ('{a}', '{b}')\"", "'INSERT INTO t VALUES (?, ?)', (a, b)"),
        ("f\"INSERT INTO t VALUES ('x,y', '{b}')\"", "\"INSERT INTO t VALUES ('x,y', ?)\", (b,)"),
        (
            "f\"SELECT * FROM t WHERE a IN ('{a}', '{b}')\"",
            "'SELECT * FROM t WHERE a IN (?, ?)', (a, b)",
        ),
        ('f"SELECT * FROM t LIMIT {a}, {b}"', "'SELECT * FROM t LIMIT ?, ?', (a, b)"),
    ],
)
def test_quoted_lists_and_limit_still_parameterized(tmp_path: Path, query, expected):
    code = f"import sqlite3\ndef f(cur, a, b):\n    cur.execute({query})\n"
    _, new = fixed_source(tmp_path, code)
    assert expected in new


@pytest.mark.parametrize(
    ("query", "expected"),
    [
        ("f\"SELECT x FROM t WHERE note = 'a={v}'\"", None),
        ("f\"SELECT x FROM t WHERE note = '{v}'\"", "WHERE note = ?', (v,)"),
        ("f\"SELECT x FROM t WHERE a = 'x' AND b = {v}\"", "WHERE a = 'x' AND b = ?\", (v,)"),
    ],
)
def test_sql_template_respects_quoted_literal_boundaries(tmp_path: Path, query, expected):
    source, findings = fixes_for(
        tmp_path, f"import sqlite3\ndef f(cur, v):\n    cur.execute({query})\n"
    )
    assert findings
    fixes = [f.fix for f in findings if f.fix is not None]
    if expected is None:
        assert not fixes
    else:
        assert len(fixes) == 1
        assert expected in apply_edits(source, fixes[0].edits)


@pytest.mark.parametrize(
    ("query", "expected"),
    [
        ("f\"SELECT 1 WHERE 'foo''' = '{x}'''\"", None),
        ("f\"SELECT 1 WHERE a = '{x}'''\"", None),
        ('"SELECT 1 WHERE a = \'" + x + "\'" + "\'\'"', None),
        ("f\"SELECT 1 WHERE a = '''{x}'\"", None),
        ("f\"SELECT 1 WHERE a = '{x}'\"", "SELECT 1 WHERE a = ?"),
        ("f\"SELECT 1 WHERE a = '{x}' AND b = 'y'\"", "SELECT 1 WHERE a = ? AND b = 'y'"),
    ],
)
def test_sql_template_only_binds_entire_single_quoted_literal(tmp_path: Path, query, expected):
    source, findings = fixes_for(
        tmp_path, f"import sqlite3\ndef f(cur, x):\n    cur.execute({query})\n"
    )
    assert findings
    fixes = [f.fix for f in findings if f.fix is not None]
    if expected is None:
        assert not fixes
    else:
        assert len(fixes) == 1
        assert expected in apply_edits(source, fixes[0].edits)


@pytest.mark.parametrize(
    "query",
    [
        "f'SELECT * FROM t WHERE a = \"{v}\"'",
        "f'SELECT * FROM t WHERE a = \"pre{v}\"'",
        "f'''SELECT * FROM t WHERE note = 'a\"b' AND a = \"{v}\"'''",
        'f"SELECT $q$id={v}$q$"',
        'f"SELECT $$id={v}$$"',
        'f"SELECT * FROM t WHERE note = $q$literal$q$ AND a = {v}"',
    ],
)
def test_sql_template_refuses_identifiers_and_dollar_text(tmp_path: Path, query: str):
    _, findings = fixes_for(tmp_path, f"import sqlite3\ndef f(cur, v):\n    cur.execute({query})\n")
    assert findings and all(f.fix is None for f in findings)


@pytest.mark.parametrize(
    "query",
    [
        "f\"SELECT * FROM t WHERE a = '{v}'\"",
        'f"SELECT * FROM t WHERE a = {v}"',
        'f"""SELECT * FROM t WHERE note = "a\'b" AND a = \'{v}\'"""',
    ],
)
def test_sql_template_keeps_value_positions(tmp_path: Path, query: str):
    _, new = fixed_source(tmp_path, f"import sqlite3\ndef f(cur, v):\n    cur.execute({query})\n")
    assert "a = ?" in new and "(v,)" in new


# -- Codex verify round 2: argv must not hand the value to code or an option -----------


@pytest.mark.parametrize(
    "command",
    [
        '"git -c " + p + " pwn"',  # git -c alias.pwn=!cmd runs a command
        '"python3.12 -c " + p',  # interpreter, versioned name
        '"/usr/bin/env " + p',  # wrapper that runs its argument
        '"sh -c " + p',
        '"C:/Tools/pwsh.exe -Command " + p',
        'f"tar -xf {p}"',  # value right after a flag: may be its argument
        "p",  # dynamic program
    ],
)
def test_no_argv_fix_for_interpreters_or_option_arguments(tmp_path: Path, command):
    code = f"import os\n\ndef f(p):\n    os.system({command})\n"
    _, findings = fixes_for(tmp_path, code)
    assert findings and all(f.fix is None for f in findings)


def test_value_after_end_of_options_is_fixed(tmp_path: Path):
    _, new = fixed_source(tmp_path, 'import os\n\ndef f(p):\n    os.system(f"ls -l -- {p}")\n')
    assert "subprocess.call(['ls', '-l', '--', str(p)])" in new
