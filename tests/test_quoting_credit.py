"""Sanitizer credit soundness: context-sensitive quoting (shlex.quote) survives only plain
text building, sanitizer names must be stable, and quoting helpers without a sound
guarantee (datasette's escape_sqlite) never justify a suppression."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from hackscan.analyzers.ast_pass import analyze_source
from hackscan.config import HackScanConfig
from hackscan.core.models import Status
from hackscan.core.pipeline import scan
from hackscan.plugins.loader import builtin_plugins

HEADER = "import os\nimport shlex\n"
BACKSLASH = chr(92)


def _cmdi(body: str):
    result = analyze_source(
        HEADER + f"def f(x, xs, flag):\n    {body}\n", "t.py", builtin_plugins()
    )
    assert not result.errors, result.errors
    (f,) = [f for f in result.findings if f.vuln_class == "cmdi"]
    return f


def _credited(f) -> bool:
    return any("POSIX quoting" in e.message for e in f.evidence)


# -- shlex.quote credit survives only plain text building ----------------------------------

SHELL_UNSAFE = {
    "augmented assignment": "cmd = 'echo \"'\n    cmd += shlex.quote(x)\n    cmd += '\"'\n    os.system(cmd)",
    "augmented printf": "cmd = shlex.quote(x)\n    cmd %= ()\n    os.system('echo ' + cmd)",
    "augmented printf, text operand": "cmd = shlex.quote(x)\n    cmd %= '-'\n    os.system('echo ' + cmd)",
    "f-string repr": 'os.system(f"echo {shlex.quote(x)!r}")',
    "f-string padding": 'os.system(f"echo {shlex.quote(x):>9}")',
    "format repr": 'os.system("echo {!r}".format(shlex.quote(x)))',
    "format index field": 'os.system("echo {0[0]}".format(shlex.quote(x)))',
    "format **kwargs": 'os.system("echo {q}".format(**{"q": shlex.quote(x)}))',
    "format unknown template": "os.system(x.format(shlex.quote(x)))",
    "printf repr": 'os.system("echo %r" % shlex.quote(x))',
    "printf list operand": 'os.system("echo %s" % [shlex.quote(x)])',
    "decoded": 'os.system("echo " + shlex.quote(x).encode().decode("unicode_escape"))',
    "str() decoding": 'os.system("echo " + str(shlex.quote(x).encode(), "unicode_escape"))',
    "bytes rendered": 'os.system("echo " + str(shlex.quote(x).encode()))',
    # q is `"` (then $(...) expands inside) or `'` (then the quoted value is unquoted).
    "decoded constant quote": (
        'q = "' + BACKSLASH * 2 + 'x22".encode().decode("unicode_escape")\n'
        '    os.system("echo " + q + shlex.quote(x) + q)'
    ),
    "repr constant quote": 'q = repr("x")[:1]\n    os.system("echo " + q + shlex.quote(x) + q)',
    "printf repr constant quote": 'q = ("%r" % "x")[:1]\n    os.system("echo " + q + shlex.quote(x) + q)',
    "format repr constant quote": 'q = "{!r}".format("x")[:1]\n    os.system("echo " + q + shlex.quote(x) + q)',
    "f-string repr constant quote": 'q = f"{\'x\'!r}"[:1]\n    os.system("echo " + q + shlex.quote(x) + q)',
    "tuple via printf": 'os.system("echo %s" % ((shlex.quote(x),),))',
    "tuple via str()": 'os.system("echo " + str((shlex.quote(x),)))',
    "tuple via f-string": 'os.system(f"echo {(shlex.quote(x),)}")',
    "loop over characters": 'out = ""\n    for c in shlex.quote(x):\n        out += c\n    os.system("echo " + out)',
    "unpacked characters": '_, *cs = shlex.quote(x)\n    os.system("echo " + "".join(cs))',
    "unpacked two characters": 'a, b = shlex.quote(x)\n    os.system("echo " + b)',
    "comprehension over characters": 'os.system("echo " + "".join([c for c in shlex.quote(x)]))',
    "join splits characters": 'os.system("echo " + " ".join(shlex.quote(x)))',
    "indexed character": 'os.system("echo " + shlex.quote(x)[0])',
    "lowered": 'os.system("echo " + shlex.quote(x).lower())',
    "repeated": 'os.system("echo " + shlex.quote(x) * 2)',
    "format padding": 'os.system("echo {:>9}".format(shlex.quote(x)))',
    # constant text that renders or decodes into a quote
    "sliced bytes rendering": 'os.system("echo " + str(b"x")[:3] + shlex.quote(x))',
    # Codex review: constants rendered with their repr (q is `'`).
    "encoded constant rendered": 'q = str("x".encode())[1]\n    os.system("echo " + q + shlex.quote(x) + q)',
    "tuple constant rendered": 'q = str(("x",))[1]\n    os.system("echo " + q + shlex.quote(x) + q)',
    "list constant rendered": 'q = str(["x"])[1]\n    os.system("echo " + q + shlex.quote(x) + q)',
    "list() rendered": 'q = str(list("x"))[1]\n    os.system("echo " + q + shlex.quote(x) + q)',
    "comprehension rendered": 'q = str([c for c in "x"])[1]\n    os.system("echo " + q + shlex.quote(x) + q)',
    "tuple via printf item": 'q = ("%s" % (("x",),))[1]\n    os.system("echo " + q + shlex.quote(x) + q)',
    "tuple variable rendered": 't = ("x",)\n    q = str(t)[1]\n    os.system("echo " + q + shlex.quote(x) + q)',
    # ... rendered by an f-string (no str() call involved)
    "list constant in an f-string": "q = f\"{['x']}\"[1]\n    os.system('echo ' + q + shlex.quote(x) + q)",
    "comprehension in an f-string": "q = f\"{[c for c in 'x']}\"[1]\n    os.system('echo ' + q + shlex.quote(x) + q)",
    "list() in an f-string": "q = f\"{list('x')}\"[1]\n    os.system('echo ' + q + shlex.quote(x) + q)",
    "tuple in an f-string": "q = f\"{('x',)}\"[1]\n    os.system('echo ' + q + shlex.quote(x) + q)",
    "bytes in an f-string": "q = f\"{'x'.encode()}\"[1]\n    os.system('echo ' + q + shlex.quote(x) + q)",
    "bytes literal in an f-string": "q = f\"{b'x'}\"[1]\n    os.system('echo ' + q + shlex.quote(x) + q)",
    # Codex review round 2: an attribute of a constant renders as anything.
    "constant attribute rendered": "q = str('x'.__class__)[7]\n    os.system('echo ' + q + shlex.quote(x) + q)",
    "constant attribute in an f-string": "q = f\"{'x'.__class__}\"[7]\n    os.system('echo ' + q + shlex.quote(x) + q)",
    # ... a backslash escapes the opening quote
    "backslash around": 'os.system("echo '
    + BACKSLASH * 2
    + '" + shlex.quote(x) + "'
    + BACKSLASH * 2
    + '")',
    "constant decoded by str()": (
        'q = str("' + BACKSLASH * 2 + 'x27".encode(), "unicode_escape")\n'
        '    os.system("echo " + q + shlex.quote(x) + q)'
    ),
}


@pytest.mark.parametrize("body", SHELL_UNSAFE.values(), ids=SHELL_UNSAFE.keys())
def test_shell_quoting_credit_needs_plain_context(body: str):
    f = _cmdi(body)
    assert f.status is not Status.SUPPRESSED
    assert not _credited(f)


SHELL_PLAIN = {
    "concatenation": 'os.system("echo " + shlex.quote(x))',
    "augmented addition": "cmd = 'echo '\n    cmd += shlex.quote(x)\n    os.system(cmd)",
    "printf %s": 'os.system("echo %s" % shlex.quote(x))',
    "printf tuple": 'os.system("echo %s %s" % (shlex.quote(x), shlex.quote(x)))',
    "format field": 'os.system("echo {}".format(shlex.quote(x)))',
    "format named field": 'os.system("echo {q}".format(q=shlex.quote(x)))',
    "f-string": 'os.system(f"echo {shlex.quote(x)}")',
    "str()": 'os.system("echo " + str(shlex.quote(x)))',
    "str() of a constant": 'os.system("echo " + str("-n") + " " + str(5) + " " + shlex.quote(x))',
    "join of a list": 'os.system("echo " + " ".join([shlex.quote(x), shlex.quote(x)]))',
    "join of a generator": 'os.system("echo " + " ".join(shlex.quote(a) for a in xs))',
    "branch join": 'os.system("echo " + (shlex.quote(x) if flag else "-"))',
}


@pytest.mark.parametrize("body", SHELL_PLAIN.values(), ids=SHELL_PLAIN.keys())
def test_shell_quoting_credit_kept_in_plain_context(body: str):
    assert _credited(_cmdi(body))


def test_module_constant_quote_drops_shell_quoting_credit():
    # A module constant keeps its shell text flag: its quotes make shlex.quote's output
    # part of a larger quoted word.
    code = 'Q = "\'"\n\ndef f(x):\n    os.system("echo " + Q + shlex.quote(x) + Q)\n'
    (f,) = analyze_source(HEADER + code, "t.py", builtin_plugins()).findings
    assert not _credited(f)
    (g,) = analyze_source(
        HEADER + code.replace('Q = "\'"', 'Q = "x"'), "t.py", builtin_plugins()
    ).findings
    assert _credited(g)  # control: credit without quotes


# -- sanitizer names must be stable ------------------------------------------------------------

REBOUND_SQL = {
    "module lambda": "int = lambda s: s\n\ndef f(cur, x):\n    cur.execute('SELECT ' + str(int(x)))\n",
    "rebound after local import": (
        "def f(cur, x):\n    from builtins import int\n    int = lambda s: s\n"
        "    cur.execute('SELECT ' + str(int(x)))\n"
    ),
    "global rebinding": (
        "import uuid\n\ndef g():\n    global uuid\n    uuid = None\n\n"
        "def f(cur, x):\n    cur.execute('SELECT ' + str(uuid.UUID(x)))\n"
    ),
    "parameter shadows": "def f(cur, x, int):\n    cur.execute('SELECT ' + str(int(x)))\n",
    "module attribute replaced": (
        "import uuid\nuuid.UUID = lambda s: s\n\ndef f(cur, x):\n    cur.execute('SELECT ' + str(uuid.UUID(x)))\n"
    ),
    "module attribute replaced via alias": (
        "import uuid\nv = uuid\nv.UUID = lambda s: s\n\n"
        "def f(cur, x):\n    cur.execute('SELECT ' + str(uuid.UUID(x)))\n"
    ),
    "setattr anywhere": (
        "import uuid\nsetattr(uuid, 'U' + 'UID', str)\n\n"
        "def f(cur, x):\n    cur.execute('SELECT ' + str(uuid.UUID(x)))\n"
    ),
}


@pytest.mark.parametrize("source", REBOUND_SQL.values(), ids=REBOUND_SQL.keys())
def test_rebound_sanitizer_name_is_not_trusted(source: str):
    (f,) = analyze_source(source, "t.py", builtin_plugins()).findings
    assert f.status is not Status.SUPPRESSED


@pytest.mark.parametrize(
    "source",
    [
        "def f(cur, x):\n    cur.execute('SELECT ' + str(int(x)))\n",
        "import uuid\n\ndef f(cur, x):\n    cur.execute('SELECT ' + str(uuid.UUID(x)))\n",
        "from builtins import int\n\ndef f(cur, x):\n    cur.execute('SELECT ' + str(int(x)))\n",
    ],
)
def test_stable_sanitizer_control(source: str):
    (f,) = analyze_source(source, "t.py", builtin_plugins()).findings
    assert f.status is Status.SUPPRESSED


REBOUND_SHELL = {
    "module attribute replaced": "shlex.quote = lambda s: s\n\ndef f(x):\n    os.system('echo ' + shlex.quote(x))\n",
    "imported name rebound": (
        "from shlex import quote\nquote = lambda s: s\n\ndef f(x):\n    os.system('echo ' + quote(x))\n"
    ),
    "global declared in a nested function": (
        "from shlex import quote\nquote = lambda s: s\n\ndef g(x):\n    from shlex import quote\n\n"
        "    def h():\n        global quote\n        os.system('echo ' + quote(x))\n\n    h()\n"
    ),
    "namespace writer": "exec('pass')\n\ndef f(x):\n    os.system('echo ' + shlex.quote(x))\n",
}


@pytest.mark.parametrize("source", REBOUND_SHELL.values(), ids=REBOUND_SHELL.keys())
def test_rebound_quoting_helper_gets_no_credit(source: str):
    (f,) = [
        f
        for f in analyze_source(HEADER + source, "t.py", builtin_plugins()).findings
        if f.vuln_class == "cmdi"
    ]
    assert not _credited(f)


def test_namespace_writer_keeps_plain_sanitizers():
    # Only the context-sensitive quoting helpers lose credit under a namespace writer.
    source = "exec('pass')\n\ndef f(cur, x):\n    cur.execute('SELECT ' + str(int(x)))\n"
    (f,) = [
        f
        for f in analyze_source(source, "t.py", builtin_plugins()).findings
        if f.vuln_class == "sqli"
    ]
    assert f.status is Status.SUPPRESSED


# -- `*args` / `**kwargs`: which value fills which field is unknown -------------------------


@pytest.mark.parametrize(
    "call",
    [
        "'SELECT {1}'.format(*u, 'a')",
        "'SELECT {x}'.format(x='a', **request.args)",
        "'SELECT {0}'.format_map(request.args)",
        "'SELECT {}{}'.format(*u)",
        "'SELECT %s %s' % (*u, 'a')",
    ],
)
def test_unknown_field_mapping_is_never_constant(call: str):
    code = (
        "from flask import request\n\ndef f(cur):\n"
        f"    u = request.args.getlist('u')\n    cur.execute({call})\n"
    )
    (f,) = [
        f
        for f in analyze_source(code, "t.py", builtin_plugins()).findings
        if f.vuln_class == "sqli"
    ]
    assert f.status is not Status.SUPPRESSED


# -- an identifier quoting helper without a sound guarantee never suppresses ---------------

ESCAPE_SQLITE = """
import re

_boring_keyword_re = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]*$")
reserved_words = set("select from where table index".split())


def escape_sqlite(s):
    if _boring_keyword_re.fullmatch(s) and (s.lower() not in reserved_words):
        return s
    return '"{}"'.format(s.replace('"', '""'))
"""


def test_escape_sqlite_leaves_keywords_bare():
    # Why the helper is no sanitizer (datasette cf113a59, reduced): any word missing from
    # its reserved list stays bare, e.g. `returning` adds a RETURNING clause.
    namespace: dict = {}
    exec(ESCAPE_SQLITE, namespace)
    assert namespace["escape_sqlite"]("returning") == "returning"
    assert namespace["escape_sqlite"]("true") == "true"


IDENTIFIER_SHAPES = {
    "concatenation": "cur.execute('SELECT * FROM ' + escape_sqlite(t))",
    "f-string": "cur.execute(f'SELECT count(*) FROM {escape_sqlite(t)}')",
    "printf": "cur.execute('SELECT * FROM %s' % escape_sqlite(t))",
    "format": "cur.execute('SELECT * FROM {}'.format(escape_sqlite(t)))",
    "keyword": "cur.execute('UPDATE a SET n = n + 1 ' + escape_sqlite(t) + ' secret')",
    "exponent": "cur.execute('SELECT a FROM t WHERE 1.' + escape_sqlite(t) + ' > 5')",
    "maybe-empty join": "cur.execute('SELECT 0 O' + ''.join('.' for _ in t) + escape_sqlite(t) + ' 1')",
}


@pytest.mark.parametrize("body", IDENTIFIER_SHAPES.values(), ids=IDENTIFIER_SHAPES.keys())
@pytest.mark.parametrize(
    "imports",
    [
        "from datasette.utils import escape_sqlite",
        "from datasette.utils import escape_sqlite as escape_sqlite",
    ],
)
def test_identifier_helper_alone_never_suppresses(imports: str, body: str):
    code = f"{imports}\nfrom flask import request\n\ndef f(cur):\n    t = request.args['t']\n    {body}\n"
    (f,) = [
        f
        for f in analyze_source(code, "t.py", builtin_plugins()).findings
        if f.vuln_class == "sqli"
    ]
    assert f.status is Status.CONFIRMED  # request data, no sanitizer on the way


def test_identifier_helper_across_files_never_suppresses(tmp_path: Path):
    files = {
        "datasette/__init__.py": "",
        "datasette/utils/__init__.py": ESCAPE_SQLITE
        + "\n\ndef count(conn, table):\n    return conn.execute(f'select count(*) from {escape_sqlite(table)}')\n",
        "datasette/app.py": (
            "from .utils import escape_sqlite\n\n"
            "def rows(conn, table):\n    return conn.execute('select * from ' + escape_sqlite(table))\n"
        ),
    }
    for rel, text in files.items():
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(textwrap.dedent(text), encoding="utf-8")
    findings = [f for f in scan(tmp_path, HackScanConfig()).findings if f.vuln_class == "sqli"]
    assert findings
    assert all(f.status is not Status.SUPPRESSED for f in findings)


def test_join_of_a_runtime_number_of_constant_items_is_not_constant():
    # datasette tests/test_plugins.py:1530 shape: one `?` per item. Conservatively not a
    # constant (as in v0.3.1): repeating other constant text can form SQL structure.
    code = (
        "def f(db, ids):\n"
        "    sql = 'select * from t where id in ({})'.format(', '.join('?' for _ in ids))\n"
        "    db.execute(sql, ids)\n"
    )
    (f,) = analyze_source(code, "t.py", builtin_plugins()).findings
    assert f.status is not Status.SUPPRESSED


# -- review round 3: rendering through methods / sliced quoting / numbers -> characters ---


def test_rendering_ground_truth():
    import shlex

    # Why these shapes lose credit: each yields a quote or turns numbers into letters.
    assert str("x".split())[1] == "'"  # noqa: SIM905 (the shape under test)
    assert shlex.quote("")[0] == "'"
    assert (65).to_bytes(1, "big").decode() == "A"
    assert "%c" % 65 == "{:c}".format(65) == f"{65:c}" == format(65, "c") == "A"  # noqa: UP031, UP032
    assert bytes([65]) == bytearray([65]) == b"A"


@pytest.mark.parametrize(
    "body",
    [
        "q = str('x'.split())[1]\n    os.system('echo ' + q + shlex.quote(x) + q)",
        "q = shlex.quote('')[0]\n    os.system('echo ' + q + shlex.quote(x) + q)",
    ],
    ids=["method result rendered", "sliced quoting output"],
)
def test_rendered_or_sliced_text_drops_quoting_credit(body: str):
    assert not _credited(_cmdi(body))


def test_sliced_quoting_output_as_module_constant():
    code = "Q = shlex.quote('')[0]\n\ndef f(x):\n    os.system('echo ' + Q + shlex.quote(x) + Q)\n"
    (f,) = analyze_source(HEADER + code, "t.py", builtin_plugins()).findings
    assert not _credited(f)


NUMBER_TO_TEXT = {
    "int.to_bytes": "cur.execute(int(x).to_bytes(8, 'big').decode())",
    "printf %c": "cur.execute('select ' + '%c' % int(x))",
    "format {:c}": "cur.execute('select ' + '{:c}'.format(int(x)))",
    "f-string :c": "cur.execute(f'select {int(x):c}')",
    "f-string nested spec": "w = 'c'\n    cur.execute(f'select {int(x):{w}}')",
    "format() builtin": "cur.execute('select ' + format(int(x), 'c'))",
    "bytes()": "cur.execute(bytes([int(x)]))",
    "bytearray()": "cur.execute(bytearray([int(x)]).decode())",
    "replace": "cur.execute('select ' + str(int(x)).replace('1', 'a'))",
    "translate": "cur.execute('select ' + str(int(x)).translate({49: 'a'}))",
    "encode with a codec": "cur.execute(b'select ' + str(int(x)).encode('utf-16'))",
    "bytes.fromhex": "cur.execute(bytes.fromhex(str(int(x))).decode())",
    "computed printf template": "t = 'select %' + 'c'\n    cur.execute(t % int(x))",
    "computed format template": "t = 'select {:' + 'c}'\n    cur.execute(t.format(int(x)))",
    "augmented printf": "q = 'select %c'\n    q %= int(x)\n    cur.execute(q)",
}


@pytest.mark.parametrize("body", NUMBER_TO_TEXT.values(), ids=NUMBER_TO_TEXT.keys())
def test_number_credit_does_not_survive_conversion_to_characters(body: str):
    code = f"def f(cur, x, w):\n    {body}\n"
    (f,) = [
        f
        for f in analyze_source(code, "t.py", builtin_plugins()).findings
        if f.vuln_class == "sqli"
    ]
    assert f.status is not Status.SUPPRESSED


NUMBER_AS_DIGITS = {
    "printf %d": "cur.execute('select %d' % int(x))",
    "f-string": "cur.execute(f'select {int(x)}')",
    "f-string :05d": "cur.execute(f'select {int(x):05d}')",
    "format {}": "cur.execute('select {}'.format(int(x)))",
    "format {:>5}": "cur.execute('select {:>5}'.format(int(x)))",
    "upper": "cur.execute('select ' + str(int(x)).upper())",
    "zfill": "cur.execute('select ' + str(int(x)).zfill(5))",
    "strip": "cur.execute('select ' + str(int(x)).strip())",
    "encode()": "cur.execute(b'select ' + str(int(x)).encode())",
}


@pytest.mark.parametrize("body", NUMBER_AS_DIGITS.values(), ids=NUMBER_AS_DIGITS.keys())
def test_number_credit_survives_digit_rendering(body: str):
    code = f"def f(cur, x):\n    {body}\n"
    (f,) = [
        f
        for f in analyze_source(code, "t.py", builtin_plugins()).findings
        if f.vuln_class == "sqli"
    ]
    assert (f.status, f.suppression) == (Status.SUPPRESSED, "taint:sanitized")


def test_number_credit_through_a_helper_does_not_survive_conversion():
    code = (
        "from flask import request\n\n"
        "def build(n):\n    return n.to_bytes(8, 'big').decode()\n\n"
        "def f(cur):\n    cur.execute(build(int(request.args['x'])))\n"
    )
    (f,) = [
        f
        for f in analyze_source(code, "t.py", builtin_plugins()).findings
        if f.vuln_class == "sqli"
    ]
    assert f.status is not Status.SUPPRESSED


@pytest.mark.parametrize(
    "body",
    [
        "cur.execute('select {:{w}}'.format(int(x), w='c'))",
        "cur.execute(bytearray([int(x)]))",
    ],
    ids=["format nested spec", "bytearray() as the query"],
)
def test_number_credit_does_not_survive_conversion_more(body: str):
    code = f"def f(cur, x):\n    {body}\n"
    (f,) = [
        f
        for f in analyze_source(code, "t.py", builtin_plugins()).findings
        if f.vuln_class == "sqli"
    ]
    assert f.status is not Status.SUPPRESSED


@pytest.mark.parametrize(
    "helper",
    [
        # the sink inside the helper: the parameter symbol carries the credit
        "def run(cur, n):\n    cur.execute(int(n).to_bytes(8, 'big').decode())\n\n"
        "def f(cur):\n    run(cur, request.args['x'])\n",
        # the converted value returned to the caller
        "def build(n):\n    return int(n).to_bytes(8, 'big').decode()\n\n"
        "def f(cur):\n    cur.execute(build(request.args['x']))\n",
    ],
    ids=["sink in the helper", "returned to the caller"],
)
def test_number_credit_on_a_parameter_does_not_survive_conversion(tmp_path: Path, helper: str):
    (tmp_path / "app.py").write_text("from flask import request\n\n" + helper, encoding="utf-8")
    (f,) = [f for f in scan(tmp_path, HackScanConfig()).findings if f.vuln_class == "sqli"]
    assert f.status is Status.CONFIRMED


# -- review round 4: attributes, field selectors and SQL objects rendered as text ---------

OBJECT_HEADER = "import uuid\nfrom psycopg2 import sql\nfrom flask import request\n\n"

RAW_DATA = {
    "uuid bytes decoded": "cur.execute('select ' + str(uuid.UUID(t).bytes, 'latin-1'))",
    "identifier strings": "cur.execute(sql.Identifier(t).strings[0])",
    "literal wrapped": "cur.execute(sql.Literal(t).wrapped)",
    "format selector wrapped": "cur.execute('select {0.wrapped}'.format(sql.Literal(t)))",
    "format selector strings": "cur.execute('select {0.strings[0]}'.format(sql.Identifier(t)))",
    "identifier via str()": "cur.execute('select ' + str(sql.Identifier(t)))",
    "identifier in an f-string": "cur.execute(f'select {sql.Identifier(t)}')",
    "literal via printf": "cur.execute('select %s' % sql.Literal(t))",
    "literal via format": "cur.execute('select {}'.format(sql.Literal(t)))",
    "format selector on a uuid": "cur.execute('select {0.bytes}'.format(uuid.UUID(t)))",
    "identifier joined": "cur.execute(' '.join([sql.Identifier(t)]))",
    "object through a variable, rendered": "i = sql.Identifier(t)\n    cur.execute(f'select {i}')",
}


@pytest.mark.parametrize("body", RAW_DATA.values(), ids=RAW_DATA.keys())
def test_sanitized_object_rendered_or_taken_apart_loses_credit(body: str):
    code = OBJECT_HEADER + f"def f(cur):\n    t = request.args['t']\n    {body}\n"
    (f,) = [
        f
        for f in analyze_source(code, "t.py", builtin_plugins()).findings
        if f.vuln_class == "sqli"
    ]
    assert f.status is not Status.SUPPRESSED


def test_uuid_bytes_at_exec_lose_credit():
    code = OBJECT_HEADER + "def f():\n    exec(uuid.UUID(request.args['t']).bytes)\n"
    (f,) = [
        f
        for f in analyze_source(code, "t.py", builtin_plugins()).findings
        if f.vuln_class == "codei"
    ]
    assert f.status is not Status.SUPPRESSED


OBJECT_AS_IS = {
    "identifier passed": "cur.execute(sql.Identifier(t))",
    "literal through a variable": "q = sql.Literal(t)\n    cur.execute(q)",
    "branch join": "cur.execute(sql.Identifier(t) if t else sql.Literal(t))",
    "uuid rendered": "cur.execute('select ' + str(uuid.UUID(t)))",
}


@pytest.mark.parametrize("body", OBJECT_AS_IS.values(), ids=OBJECT_AS_IS.keys())
def test_sanitized_object_passed_as_is_keeps_credit(body: str):
    code = OBJECT_HEADER + f"def f(cur):\n    t = request.args['t']\n    {body}\n"
    (f,) = [
        f
        for f in analyze_source(code, "t.py", builtin_plugins()).findings
        if f.vuln_class == "sqli"
    ]
    assert (f.status, f.suppression) == (Status.SUPPRESSED, "taint:sanitized")


@pytest.mark.parametrize(
    "program",
    [
        # returned by a helper (the request data is read inside it), rendered by the caller
        "def ident():\n    return sql.Identifier(request.args['t'])\n\n"
        "def f(cur):\n    cur.execute(f'select {ident()}')\n",
        # passed into a helper that renders it (positional and keyword)
        "def run(cur, i):\n    cur.execute(f'select {i}')\n\n"
        "def f(cur):\n    run(cur, sql.Identifier(request.args['t']))\n",
        "def run(cur, i):\n    cur.execute(f'select {i}')\n\n"
        "def f(cur):\n    run(cur, i=sql.Identifier(request.args['t']))\n",
    ],
    ids=["returned, then rendered", "passed in, then rendered", "passed by keyword"],
)
def test_sql_object_credit_does_not_cross_calls(tmp_path: Path, program: str):
    # Only the interprocedural flow links the request data to the sink here.
    (tmp_path / "app.py").write_text(OBJECT_HEADER + program, encoding="utf-8")
    (f,) = [f for f in scan(tmp_path, HackScanConfig()).findings if f.vuln_class == "sqli"]
    assert f.status is Status.CONFIRMED


# -- review rounds 5/6: numbers and constants shaping SQL text ----------------------------


def test_number_shaped_text_ground_truth():
    # Why these shapes matter: a runtime number decides the text's structure.
    assert "-" * 2 == "--"
    assert "n -" + str(-1) == "n --1"
    assert f"{1:->3}" == "--1"
    assert "abc"[2] == "c"


# Guaranteed: format fills, runtime indexing/slicing of constant text, runtime counts of
# constant items in comprehension joins.
NUMBER_SHAPES_TEXT = {
    "fill spec f-string": "cur.execute(f'select 1 {int(x):->9}')",
    "fill spec format": "cur.execute('select 1 {:->9}'.format(int(x)))",
    "indexed constant text": "cur.execute('select ' + 'abc'[int(x)])",
    "indexed constant text in a join": "cur.execute('select ' + ''.join('abc'[int(x)] for _ in range(3)))",
    "constant item, runtime count": "cur.execute('select 1 ' + ''.join('-' for _ in xs))",
    "filtered constant items": "cur.execute('select 1 ' + ''.join('-' for c in 'abc' if c in xs))",
    # review round 6: a text selected from a container is still a text
    "element of a tuple, then sliced": "cur.execute(('select a from t where ok = 1',)[0][: int(x)])",
    "element of a list, then indexed": "cur.execute('select ' + ['abc'][0][int(x)])",
    "container rendered, then indexed": "cur.execute('select ' + str(('a', 'b'))[int(x)])",
}


@pytest.mark.parametrize("body", NUMBER_SHAPES_TEXT.values(), ids=NUMBER_SHAPES_TEXT.keys())
def test_runtime_number_shaping_text_is_never_safe(body: str):
    code = f"def f(cur, x, xs, flag):\n    {body}\n"
    (f,) = [
        f
        for f in analyze_source(code, "t.py", builtin_plugins()).findings
        if f.vuln_class == "sqli"
    ]
    assert f.status is not Status.SUPPRESSED


# Documented limitation (README "Limitations"): HackScan does not model SQL token
# boundaries, so a sanitized number or a constant that shapes SQL text structure keeps its
# credit, as in v0.3.1. Strict xfail: if one of these starts passing, update the docs.
NUMBER_SHAPES_LIMITATION = {
    "repeated fragment": "cur.execute('select 1 ' + '-' * int(x) + ' and ok')",
    "number times text": "cur.execute('select 1 ' + int(x) * '-')",
    "augmented repetition": "q = '-'\n    q *= int(x)\n    cur.execute('select 1 ' + q)",
    "repeated list joined": "cur.execute('select 1 ' + ''.join(['-'] * int(x)))",
    "number after a dash": "cur.execute('select n -' + str(int(x)) + ' and ok')",
    "number after a dash, f-string": "cur.execute(f'select n -{int(x)} and ok')",
    "number after a dash, printf": "cur.execute('select n -%s and ok' % int(x))",
    "number after a dash, format": "cur.execute('select n -{} and ok'.format(int(x)))",
    "through an empty string": "cur.execute('select n -' + '' + str(int(x)))",
    "dash separator between numbers": "cur.execute('select ' + '-'.join([str(int(x)), str(int(x))]))",
}


@pytest.mark.xfail(
    strict=True, reason="documented limitation: SQL token boundaries are not modeled"
)
@pytest.mark.parametrize(
    "body", NUMBER_SHAPES_LIMITATION.values(), ids=NUMBER_SHAPES_LIMITATION.keys()
)
def test_number_shaped_sql_structure_limitation(body: str):
    code = f"def f(cur, x, xs, flag):\n    {body}\n"
    (f,) = [
        f
        for f in analyze_source(code, "t.py", builtin_plugins()).findings
        if f.vuln_class == "sqli"
    ]
    assert f.status is not Status.SUPPRESSED


NUMBER_SHAPES_SAFE = {
    "placeholders repeated and joined": (
        "cur.execute('select * from t where id in (' + ','.join(['?'] * len(ids)) + ')', ids)",
        "taint:sanitized",
    ),
    "placeholders repeated and sliced": (
        "cur.execute('select * from t where id in (' + ('?,' * len(ids))[:-1] + ')', ids)",
        "taint:sanitized",
    ),
    "arithmetic of numbers": (
        "cur.execute('select * from t limit %d' % (int(x) * int(y)))",
        "taint:sanitized",
    ),
    "modulo of numbers": (
        "cur.execute('select * from t limit %d' % (int(x) % int(y)))",
        "taint:sanitized",
    ),
    "literal modulo a number": (
        "cur.execute('select * from t limit %d' % (100 % int(x)))",
        "taint:sanitized",
    ),
    "difference modulo a number": (
        "cur.execute('select * from t limit %d' % ((int(x) - 1) % int(y)))",
        "taint:sanitized",
    ),
    "sum modulo a number": (
        "cur.execute('select * from t limit %d' % ((int(x) + 1) % int(y)))",
        "taint:sanitized",
    ),
    "dash then a space": ("cur.execute('select n - ' + str(int(x)))", "taint:sanitized"),
    "number then a dash": ("cur.execute(f'select {int(x)} - 1')", "taint:sanitized"),
    "constant after a dash": ("cur.execute('select n -' + str(5))", "taint:constant_input"),
    "dict allow-list": (
        "cur.execute('select ' + {'a': 'ASC', 'd': 'DESC'}[x])",
        "taint:constant_input",
    ),
    "tuple allow-list": (
        "cur.execute('select ' + ('ASC', 'DESC')[int(x)])",
        "taint:constant_input",
    ),
    "tuple slice of constants": (
        "cur.execute('select ' + ', '.join(('a', 'b', 'c')[: int(x)]))",
        "taint:constant_input",
    ),
}


@pytest.mark.parametrize(
    "body,suppression", NUMBER_SHAPES_SAFE.values(), ids=NUMBER_SHAPES_SAFE.keys()
)
def test_number_shaped_text_controls(body: str, suppression: str):
    code = f"def f(cur, x, y, ids):\n    {body}\n"
    (f,) = [
        f
        for f in analyze_source(code, "t.py", builtin_plugins()).findings
        if f.vuln_class == "sqli"
    ]
    assert (f.status, f.suppression) == (Status.SUPPRESSED, suppression)


# -- review round 7: iteration items, abs/round, programs that run their operands ---------

QUERY = "('select a from t where ok = 1',)"

ITEM_SLICED = {
    "generator item": f"cur.execute(''.join(q[: int(x)] for q in {QUERY}))",
    "loop item": f"for q in {QUERY}:\n        cur.execute(q[: int(x)])",
    "unpacked item": f"(q,) = {QUERY}\n    cur.execute(q[: int(x)])",
    "list comprehension item": f"cur.execute([q[: int(x)] for q in {QUERY}][0])",
}


@pytest.mark.parametrize("body", ITEM_SLICED.values(), ids=ITEM_SLICED.keys())
def test_item_of_a_constant_container_sliced_at_runtime_is_not_constant(body: str):
    code = f"def f(cur, x):\n    {body}\n"
    (f,) = [
        f
        for f in analyze_source(code, "t.py", builtin_plugins()).findings
        if f.vuln_class == "sqli"
    ]
    assert f.status is not Status.SUPPRESSED


def test_item_of_a_constant_container_control():
    code = "def f(cur):\n    for q in ('select 1', 'select 2'):\n        cur.execute(q)\n"
    (f,) = [
        f
        for f in analyze_source(code, "t.py", builtin_plugins()).findings
        if f.vuln_class == "sqli"
    ]
    assert (f.status, f.suppression) == (Status.SUPPRESSED, "taint:constant_input")


def test_abs_and_round_do_not_sanitize_on_their_own():
    # `__abs__` / `__round__` may return anything, e.g. the raw text they wrap.
    for builtin in ("abs", "round"):
        code = (
            "from flask import request\n\n"
            f"class Raw:\n    def __init__(self, v):\n        self.v = v\n\n"
            f"    def __{builtin}__(self, *a):\n        return self.v\n\n"
            f"def f(cur):\n    cur.execute('select ' + {builtin}(Raw(request.args['t'])))\n"
        )
        (f,) = [
            f
            for f in analyze_source(code, "t.py", builtin_plugins()).findings
            if f.vuln_class == "sqli"
        ]
        assert f.status is not Status.SUPPRESSED, builtin


@pytest.mark.parametrize("body", ["abs(int(x))", "round(float(x), 2)"])
def test_abs_and_round_keep_their_arguments_credit(body: str):
    code = f"def f(cur, x):\n    cur.execute('select * from t limit %d' % {body})\n"
    (f,) = [
        f
        for f in analyze_source(code, "t.py", builtin_plugins()).findings
        if f.vuln_class == "sqli"
    ]
    assert (f.status, f.suppression) == (Status.SUPPRESSED, "taint:sanitized")


CODE_RUNNERS = {
    "sh -c": 'os.system("sh -c " + shlex.quote(x))',
    "absolute shell path": 'os.system("/bin/bash -c " + shlex.quote(x))',
    "piped into a shell": 'os.system("echo " + shlex.quote(x) + " | sh")',
    "remote command": 'os.system("ssh host " + shlex.quote(x))',
    "interpreter": 'os.system(f"python3 -c {shlex.quote(x)}")',
    "command runner": 'os.system("xargs " + shlex.quote(x))',
    "through a variable": 'cmd = "bash -c " + shlex.quote(x)\n    os.system(cmd)',
    # bash's builtin evaluates an array subscript in the variable name
    "printf variable name": 'os.system("printf -v " + shlex.quote(x) + " 1")',
    "printf by path": 'os.system("/usr/bin/printf -v " + shlex.quote(x) + " 1")',
}


@pytest.mark.parametrize("body", CODE_RUNNERS.values(), ids=CODE_RUNNERS.keys())
def test_no_quoting_credit_for_programs_that_run_their_operands(body: str):
    assert not _credited(_cmdi(body))


@pytest.mark.parametrize(
    "body",
    ['os.system("ping -c 1 " + shlex.quote(x))', 'os.system("grep -r needle " + shlex.quote(x))'],
    ids=["ping -c (a count)", "grep operand"],
)
def test_quoting_credit_for_ordinary_programs(body: str):
    assert _credited(_cmdi(body))


# review round 9 (user decision: an allow-list of inert programs, no shell metacharacters)
NOT_INERT = {
    "tar (options can run programs)": 'os.system("tar czf backup.tgz " + shlex.quote(x))',
    "unlisted wrapper": 'os.system("chrt -f 1 " + shlex.quote(x))',
    "unlisted wrapper via shlex.join": 'os.system(shlex.join(["chrt", "-f", "1", x]))',
    "separator before": 'os.system("ls; " + shlex.quote(x))',
    "pipeline before": 'os.system("ls | " + shlex.quote(x))',
    "pipeline after": 'os.system("ls -l " + shlex.quote(x) + " | wc -l")',
    "command substitution": 'os.system("echo $(" + shlex.quote(x) + ")")',
    "glob program": 'os.system("/usr/bin/pyth*n3 -c " + shlex.quote(x))',
    "sliced prefix": 'os.system("xsh -c "[1:] + shlex.quote(x))',
    "comprehension join, program-like separator": 'os.system("echo ".join(shlex.quote(a) for a in xs))',
    "format template, field in the program word": 'os.system("ec{}ho ".format(shlex.quote(x)))',
    # derived text: the literal started with an inert program, the result does not
    "sliced inert prefix": 'os.system("echo sh -c "[5:] + shlex.quote(x))',
    "rewritten inert prefix": 'os.system("echo sh -c ".removeprefix("echo ") + shlex.quote(x))',
    "program assembled from an inert prefix": 'os.system("ls" + "blk " + shlex.quote(x))',
    "separator joined over a string": 'os.system("echo ".join("ab") + " " + shlex.quote(x))',
    "quoted value first, inert word later": 'os.system(shlex.quote(x) + " ls -l")',
    # review round 10: characters of a literal, fields in a path, inexact program names
    "character of a looped prefix": 'for c in "ls ":\n        os.system(c + shlex.quote(x))',
    "character of an unpacked prefix": 'a, b, c = "ls "\n    os.system(c + shlex.quote(x))',
    "character from a comprehension": 'os.system([c for c in "ls "][2] + shlex.quote(x))',
    "format field in the program path": 'os.system("/usr/bin/{}/ls {}".format(xs, shlex.quote(x)))',
    "shlex.join, program name with a space": 'os.system(shlex.join(["ls sh", x]))',
    "relative program path": 'os.system("./ls " + shlex.quote(x))',
    "program outside the system directories": 'os.system("/opt/tools/ls " + shlex.quote(x))',
    "differently cased name": 'os.system("LS " + shlex.quote(x))',
    # review round 11: no separator in a single-item join; only blanks separate shell words
    "single-item join": 'os.system(" ".join(["ls"]) + shlex.quote(x))',
    "single empty item joined": 'os.system(" ".join([""]) + shlex.quote(x))',
    "vertical tab after the name": 'os.system("ls' + BACKSLASH + 'x0b" + shlex.quote(x))',
    "form feed after the name": 'os.system("ls' + BACKSLASH + 'x0c" + shlex.quote(x))',
    "no-break space after the name": 'os.system("ls' + BACKSLASH + 'xa0" + shlex.quote(x))',
    # review round 12: shlex.join ends right after a single item (or a maybe empty starred
    # rest); a separator that is no literal is unknown text (and must not crash the scan)
    "single-item shlex.join": 'os.system(shlex.join(["ls"]) + shlex.quote(x))',
    "shlex.join, starred rest maybe empty": 'os.system(shlex.join(["ls", *xs]) + shlex.quote(x))',
    "variable separator": 'os.system(xs.join(["ls", shlex.quote(x)]))',
    "computed separator": 'os.system((" " * 1).join(["ls", shlex.quote(x)]))',
    "f-string separator": 'os.system(f" ".join(["ls", shlex.quote(x)]))',
    "bytes separator over text": 'os.system(b" ".join(["ls", shlex.quote(x)]))',
}


@pytest.mark.parametrize(
    "body",
    [
        'os.system("/bin/ls " + shlex.quote(x))',
        'os.system(shlex.join(["/usr/bin/grep", "-r", "needle", x]))',
        'os.system("ls' + BACKSLASH + 't" + shlex.quote(x))',
        'os.system(" ".join(["ls", shlex.quote(x)]))',
    ],
    ids=["system path", "shlex.join with a system path", "tab after the name", "two-item join"],
)
def test_quoting_credit_for_exact_inert_programs(body: str):
    assert _credited(_cmdi(body))


@pytest.mark.parametrize("body", NOT_INERT.values(), ids=NOT_INERT.keys())
def test_no_quoting_credit_outside_inert_plain_commands(body: str):
    f = _cmdi(body)
    assert f.status is not Status.SUPPRESSED
    assert not _credited(f)


# -- review round 8: quoting credit needs a literal, complete, inert program word ----------

NO_PROGRAM = {
    "joined interpreter call": 'os.system(shlex.join(["python3", "-c", x]))',
    "joined runner further in": 'os.system(shlex.join(["timeout", "5", "sh", "-c", x]))',
    "quoted program name": 'os.system(shlex.quote("python3") + " -c " + shlex.quote(x))',
    "assembled program name": 'os.system("pyth" + "on3 -c " + shlex.quote(x))',
    "joined program name": 'os.system("".join(["s", "h -c "]) + shlex.quote(x))',
    "lowercased program name": 'os.system("SH".lower() + " -c " + shlex.quote(x))',
    "quoted value is the program": "os.system(shlex.quote(x))",
    "quoted value first": 'os.system(shlex.quote(x) + " --version")',
    "program from a variable": "os.system(xs + ' ' + shlex.quote(x))",
    "placeholder first": 'os.system("%s %s" % (shlex.quote(x), shlex.quote(x)))',
    "joined runner after an unlisted wrapper": 'os.system(shlex.join(["chrt", "-f", "1", "sh", "-c", x]))',
    "maybe the quoted value first": 'os.system((shlex.quote(x) if flag else "ls ") + "-l")',
}


@pytest.mark.parametrize("body", NO_PROGRAM.values(), ids=NO_PROGRAM.keys())
def test_no_quoting_credit_without_a_literal_inert_program(body: str):
    f = _cmdi(body)
    assert f.status is not Status.SUPPRESSED
    assert not _credited(f)


@pytest.mark.parametrize(
    "body",
    [
        'os.system(shlex.join(["echo", x]))',
        'os.system(" ".join(["echo", shlex.quote(x)]))',
        'os.system(f"echo {shlex.quote(x)}")',
        'os.system("/usr/bin/echo " + shlex.quote(x))',
        "P = 'echo '\n    os.system(P + shlex.quote(x))",
    ],
    ids=["shlex.join of echo", "join of a display", "f-string", "absolute path", "constant prefix"],
)
def test_quoting_credit_with_a_literal_inert_program(body: str):
    assert _credited(_cmdi(body))


def test_quoting_credit_with_a_module_constant_program():
    code = "P = 'echo '\n\ndef f(x):\n    os.system(P + shlex.quote(x))\n"
    (f,) = analyze_source(HEADER + code, "t.py", builtin_plugins()).findings
    assert _credited(f)


# -- a sink that may name its shell: POSIX quoting proves nothing for fish, csh... ---------

CHOSEN_SHELL = {
    "executable keyword": 'subprocess.run("ls " + shlex.quote(x), shell=True, executable="/usr/bin/fish")',
    "options in bulk": 'subprocess.run("ls " + shlex.quote(x), shell=True, **xs)',
    "executable positional": 'subprocess.Popen("ls " + shlex.quote(x), -1, "/usr/bin/fish", shell=True)',
    "starred positional": 'subprocess.Popen("ls " + shlex.quote(x), *xs, shell=True)',
    "shell coroutine": 'asyncio.create_subprocess_shell("ls " + shlex.quote(x), executable="/bin/csh")',
}


def _shell_sink(body: str):
    code = f"import asyncio\nimport shlex\nimport subprocess\ndef f(x, xs):\n    {body}\n"
    result = analyze_source(code, "t.py", builtin_plugins())
    assert not result.errors, result.errors
    (f,) = [f for f in result.findings if f.vuln_class == "cmdi"]
    return f


@pytest.mark.parametrize("body", CHOSEN_SHELL.values(), ids=CHOSEN_SHELL.keys())
def test_no_quoting_credit_when_the_call_may_choose_the_shell(body: str):
    f = _shell_sink(body)
    assert f.status is not Status.SUPPRESSED
    assert not _credited(f)


def test_request_data_quoted_for_a_chosen_shell_is_confirmed():
    body = 'subprocess.run("ls " + shlex.quote(input()), shell=True, executable="/usr/bin/fish")'
    assert _shell_sink(body).status is Status.CONFIRMED


@pytest.mark.parametrize(
    "body",
    [
        'subprocess.run("ls " + shlex.quote(x), shell=True, check=True)',
        'subprocess.Popen("ls " + shlex.quote(x), -1, shell=True)',
    ],
    ids=["other keywords", "buffer size"],
)
def test_quoting_credit_with_the_default_shell(body: str):
    assert _credited(_shell_sink(body))
