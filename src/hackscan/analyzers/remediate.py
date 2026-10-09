"""Pass 4 (templates): deterministic fix suggestions as exact, validated edits.

A fix is only attached when it is mechanical and safe to apply as-is:
- the rewritten file must still parse;
- edits touch only the reported call (plus, if needed, one inserted import line);
- the rewrite must preserve meaning for the pattern it handles. Anything ambiguous
  (SQL identifiers, LIKE wildcards, shell syntax, unknown DB driver) gets no fix: the
  finding keeps its message, and the reviewer decides.

Fixes are suggestions for open findings; suppressed findings never get one.
"""

from __future__ import annotations

import ast
import difflib
import re
from collections.abc import Callable
from dataclasses import replace

from hackscan.core.models import Finding, Fix, FixEdit, Region, Status
from hackscan.core.taxonomy import CMDI, CODEI, SQLI, WEAK_CRYPTO
from hackscan.importers.common import SourceIndex
from hackscan.plugins.base import FileContext, first_arg, keyword
from hackscan.plugins.loader import builtin_plugins

PRODUCER = "template"

# -- driver placeholder styles --------------------------------------------------------------

QMARK_MODULES = ("sqlite3", "aiosqlite")
FORMAT_MODULES = (
    "psycopg2",
    "psycopg",
    "pymysql",
    "MySQLdb",
    "mysql.connector",
    "django.db",
    # asyncpg uses $1-style placeholders: deliberately no template
)
# A placeholder is only valid where SQL expects a *value* and binding keeps its meaning:
# after a comparison, in a quoted VALUES/IN element, or after LIMIT/OFFSET.
# Not inside function calls
# (`typeof(?)` sees text where the inlined value was a number) nor after a bare comma
# (`SELECT a, ?` selects a constant, not a column).
_VALUE_POSITION_RE = re.compile(
    r"(=|<|>|<=|>=|<>|!=|\blike|\blimit|\boffset|\blimit\s+[^\s,()]+\s*,"
    r"|\b(?:values|in)\s*\((?:[^()'\"]|'[^']*'|\"[^\"]*\")*)\s*$",
    re.I,
)
SQL_COMMENTS = ("--", "/*", "#")  # `#` starts a comment in MySQL
SHELL_META = set("|&;<>$`*?(){}[]~!#\\'\"\n")

# Keywords that cannot change which program runs or how its arguments are interpreted.
SAFE_SUBPROCESS_KEYWORDS = {
    "check", "capture_output", "text", "timeout", "stdout", "stderr", "encoding", "errors",
    "universal_newlines",
}  # fmt: skip


def generate_fixes(findings: list[Finding], index: SourceIndex) -> list[Finding]:
    out = []
    plugins = builtin_plugins()
    for f in findings:
        if f.status is Status.SUPPRESSED:
            out.append(f)
            continue
        loaded = index.context(f.location.path)
        call = _call_at(loaded[0], f.location) if loaded is not None else None
        if call is not None and (
            any(
                _strictly_contains(f.location, other.location)
                for other in findings
                if other is not f
            )
            or _has_nested_builtin_sink(call, loaded[0], plugins)
        ):
            f = replace(f, fix=None)
        elif f.fix is None:
            fix = _fix_for(f, index)
            if fix is not None:
                f = replace(f, fix=fix)
        out.append(f)
    return out


def _strictly_contains(outer: Region, inner: Region) -> bool:
    return (
        outer.path == inner.path
        and outer.start_pos <= inner.start_pos
        and inner.end_pos <= outer.end_pos
        and (outer.start_pos < inner.start_pos or inner.end_pos < outer.end_pos)
    )


def _has_nested_builtin_sink(call: ast.Call, ctx: FileContext, plugins) -> bool:
    outer = _node_region(ctx, call)
    for node in ast.walk(call):
        if (
            node is call
            or not isinstance(node, ast.Call)
            or not _strictly_contains(outer, _node_region(ctx, node))
        ):
            continue
        for plugin in plugins:
            if type(node) in plugin.node_types and any(plugin.check(node, ctx)):
                return True
    return False


def _fix_for(f: Finding, index: SourceIndex) -> Fix | None:
    builder = BUILDERS.get(f.vuln_class)
    loaded = index.context(f.location.path)
    if builder is None or loaded is None:
        return None
    ctx, _ = loaded
    call = _call_at(ctx, f.location)
    if call is None or ctx.has_secret_literal(call):
        return None  # a fix carries the call's real code, secrets included
    try:
        proposal = builder(call, ctx)
    except (ValueError, SyntaxError):
        return None
    if proposal is None:
        return None
    description, replacement, imports = proposal
    edits = [FixEdit(_node_region(ctx, call), replacement)]
    for module in imports:
        insertion = _import_edit(ctx, module)
        if insertion is not None:
            edits.insert(0, insertion)
    fix = Fix(description, tuple(edits), PRODUCER)
    return fix if _valid(ctx, fix) else None


# -- SQL injection ---------------------------------------------------------------------------


def _sqli(call: ast.Call, ctx: FileContext):
    if len(call.args) != 1 or call.keywords or not isinstance(call.func, ast.Attribute):
        return None
    if call.func.attr != "execute":
        return None
    placeholder = _placeholder(ctx)
    if placeholder is None:
        return None
    parts = _sql_parts(call.args[0])
    if parts is None or not any(isinstance(p, ast.AST) for p in parts):
        return None
    sql, params = _parameterize(parts, placeholder)
    if sql is None:
        return None
    receiver = ctx.segment(call.func)
    values = [ctx.segment(p) for p in params]
    args = f"({values[0]},)" if len(values) == 1 else f"({', '.join(values)})"
    replacement = f"{receiver}({sql!r}, {args})"
    return (
        f"Pass values as query parameters ({placeholder!r} placeholders) instead of "
        "formatting them into the SQL string. Review: bound values keep their Python "
        "type (a str stays text where the database saw a number).",
        replacement,
        (),
    )


def _placeholder(ctx: FileContext) -> str | None:
    modules = set()
    for node in ast.walk(ctx.tree):
        if isinstance(node, ast.Import):
            modules |= {a.name for a in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module:
            modules.add(node.module)

    def uses(prefixes: tuple[str, ...]) -> bool:
        return any(m == p or m.startswith(p + ".") for m in modules for p in prefixes)

    qmark, fmt = uses(QMARK_MODULES), uses(FORMAT_MODULES)
    if qmark == fmt:  # none or both: ambiguous
        return None
    return "?" if qmark else "%s"


def _sql_parts(expr: ast.AST) -> list[str | ast.AST] | None:
    """Literal text and value expressions, in order, for f-strings, `+` and `%`."""
    if isinstance(expr, ast.JoinedStr):
        parts: list[str | ast.AST] = []
        for v in expr.values:
            if (
                isinstance(v, ast.Constant)
                and isinstance(v.value, str)
                or isinstance(v, ast.FormattedValue)
                and v.conversion == -1
                and v.format_spec is None
            ):
                parts.append(v.value)
            else:
                return None
        return parts
    if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Add):
        left, right = _operand(expr.left), _operand(expr.right)
        if left is None or right is None:
            return None
        return [*left, *right]
    if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Mod):
        if not (isinstance(expr.left, ast.Constant) and isinstance(expr.left.value, str)):
            return None
        values = expr.right.elts if isinstance(expr.right, ast.Tuple) else [expr.right]
        pieces = re.split(r"(%s)", expr.left.value)
        if "%" in "".join(pieces[::2]).replace("%%", ""):
            return None  # conversions other than %s cannot keep their value unchanged
        if len(pieces[1::2]) != len(values):
            return None
        out: list[str | ast.AST] = []
        for i, piece in enumerate(pieces):
            if i % 2 == 0:
                out.append(piece.replace("%%", "%"))
            else:
                out.append(values[i // 2])
        return out
    if isinstance(expr, ast.Constant) and isinstance(expr.value, str):
        return [expr.value]
    return None


def _operand(expr: ast.AST) -> list[str | ast.AST] | None:
    """An operand of `+`: string-building expressions decompose, anything else is a value."""
    if isinstance(expr, (ast.JoinedStr, ast.BinOp)) or (
        isinstance(expr, ast.Constant) and isinstance(expr.value, str)
    ):
        return _sql_parts(expr)
    if isinstance(expr, ast.Constant):
        return None  # e.g. "id = " + 5: not a str concatenation
    return [expr]


def _parameterize(parts: list[str | ast.AST], placeholder: str):
    if any(isinstance(p, str) and any(c in p for c in SQL_COMMENTS) for p in parts):
        return None, []  # comments can hide what a position means (`typeof(/* VALUES ( */?)`)
    if any(isinstance(p, str) and ("\\" in p or "$" in p) for p in parts):
        return None, []  # escapes and PostgreSQL dollar quotes can change boundaries
    joined_parts: list[str | ast.AST] = []
    for part in parts:
        if isinstance(part, str) and joined_parts and isinstance(joined_parts[-1], str):
            joined_parts[-1] += part
        else:
            joined_parts.append(part)
    sql = ""
    params: list[ast.AST] = []
    placeholder_positions: list[int] = []
    pending_quote = None
    for part in joined_parts:
        if isinstance(part, str):
            if pending_quote is not None:
                # Without the value, these quotes must close an empty literal, not
                # become the first half of a doubled-quote escape.
                if (
                    not part.startswith("'")
                    or _sql_quote_start(pending_quote + part[:2]) is not None
                ):
                    return None, []  # value was only part of a quoted string
                part = part[1:]
                pending_quote = None
            sql += part
            continue
        quote_start = _sql_quote_start(sql)
        if quote_start is not None:
            if sql[quote_start] != "'" or quote_start != len(sql) - 1:
                return None, []  # identifiers and partial strings cannot be bound
            quote = "'"
        else:
            quote = None
        if quote:
            if sql[-2:-1] == "%":
                return None, []  # LIKE '%...' wildcard concatenation
            quote_prefix = sql
            sql = sql[:-1]
        if quote is None and _sql_has_unclosed_parenthesis(sql):
            return None, []  # a value may supply multiple elements or SQL syntax
        if not _VALUE_POSITION_RE.search(sql.rstrip()):
            return None, []  # identifier or keyword position: placeholders not allowed
        placeholder_positions.append(len(sql))
        sql += placeholder
        params.append(part)
        pending_quote = quote_prefix if quote else None
    if pending_quote is not None:
        return None, []
    if placeholder == "%s":
        # Format-style drivers parse every percent sign once parameters are supplied.
        # Escape literal SQL spans, leaving the placeholders themselves untouched.
        spans = []
        start = 0
        for position in placeholder_positions:
            spans.extend((sql[start:position].replace("%", "%%"), placeholder))
            start = position + len(placeholder)
        spans.append(sql[start:].replace("%", "%%"))
        sql = "".join(spans)
    return sql, params


def _sql_quote_start(sql: str) -> int | None:
    """Index of an open SQL quote, accounting for doubled quote escapes."""
    quote = None
    start = None
    i = 0
    while i < len(sql):
        char = sql[i]
        if quote is None:
            if char in ("'", '"'):
                quote, start = char, i
        elif char == quote:
            if i + 1 < len(sql) and sql[i + 1] == quote:
                i += 1
            else:
                quote, start = None, None
        i += 1
    return start


def _sql_has_unclosed_parenthesis(sql: str) -> bool:
    """Whether SQL text ends inside parentheses, ignoring quoted literal content."""
    depth = 0
    quote = None
    i = 0
    while i < len(sql):
        char = sql[i]
        if quote is None:
            if char in ("'", '"'):
                quote = char
            elif char == "(":
                depth += 1
            elif char == ")":
                depth = max(0, depth - 1)
        elif char == quote:
            if i + 1 < len(sql) and sql[i + 1] == quote:
                i += 1
            else:
                quote = None
        i += 1
    return depth > 0


# -- command injection -------------------------------------------------------------------


def _cmdi(call: ast.Call, ctx: FileContext):
    names = ctx.call_names(call)
    command = first_arg(call, "args") or first_arg(call, "cmd")
    if command is None:
        return None
    argv = _argv(command, ctx)
    if argv is None:
        return None
    argv_src = "[" + ", ".join(argv) + "]"
    if "os.system" in names and len(call.args) == 1 and not call.keywords:
        # subprocess.call returns the exit status, like os.system.
        return (
            "Run the program with an argument list (no shell), so input cannot add commands. "
            "Review: a value starting with '-' can still be read as an option.",
            f"subprocess.call({argv_src})",
            ("subprocess",),
        )
    target = sorted(n for n in names if n.startswith("subprocess."))
    shell = keyword(call, "shell")
    if target and isinstance(shell, ast.Constant) and shell.value is True and len(call.args) == 1:
        if any(
            k.arg not in SAFE_SUBPROCESS_KEYWORDS or not _safe_keyword_value(k.value)
            for k in call.keywords
            if k.arg != "shell"
        ):
            return None
        kwargs = [ctx.segment(k) for k in call.keywords if k.arg != "shell"]
        args = ", ".join([argv_src, *kwargs])
        return (
            "Pass an argument list and drop shell=True, so input cannot add commands. "
            "Review: a value starting with '-' can still be read as an option.",
            f"{ctx.segment(call.func)}({args})",
            (),
        )
    return None


def _safe_keyword_value(value: ast.AST) -> bool:
    if isinstance(value, (ast.Constant, ast.Name)):
        return True
    if isinstance(value, ast.Attribute):
        while isinstance(value, ast.Attribute):
            value = value.value
        return isinstance(value, ast.Name)
    return False


def _argv(expr: ast.AST, ctx: FileContext) -> list[str] | None:
    """argv element sources, if the literal text has no shell syntax and every dynamic
    part is a whole argument (separated from neighbours by whitespace)."""
    parts = _sql_parts(expr)  # same literal/value decomposition (f-string, +, %)
    if parts is None or not any(isinstance(p, ast.AST) for p in parts):
        return None
    # f-strings and %-formatting call str() on values; argv elements must be strings.
    stringify = any(
        isinstance(n, ast.JoinedStr) or (isinstance(n, ast.BinOp) and isinstance(n.op, ast.Mod))
        for n in ast.walk(expr)
    )
    argv: list[str] = []
    literal: list[str | None] = []  # the word, or None for a dynamic value
    for i, part in enumerate(parts):
        if isinstance(part, str):
            if SHELL_META & set(part):
                return None  # quoting, pipes, globbing...: shell semantics we cannot keep
            argv.extend(repr(token) for token in part.split())
            literal.extend(part.split())
            continue
        prev = parts[i - 1] if i > 0 else None
        nxt = parts[i + 1] if i + 1 < len(parts) else None
        if isinstance(prev, ast.AST) or (isinstance(prev, str) and prev and not prev[-1].isspace()):
            return None  # glued to the preceding text/value
        if isinstance(nxt, str) and nxt and not nxt[0].isspace():
            return None  # glued to the following text
        text = ctx.segment(part)
        argv.append(f"str({text})" if stringify else text)
        literal.append(None)
    if not argv or not _argv_is_inert(literal):
        return None
    return argv


# Programs whose arguments are data: no option or operand runs a command, loads code or
# writes an arbitrary file. An argument list only makes a dynamic value safe for these;
# countless others execute operands or options (`sh -c`, `npx PKG`, `git -c alias=!cmd`,
# `tar --to-command`, `sort --compress-program`, `find -exec`, `rg --pre`), so an
# allowlist, not a denylist.
INERT_PROGRAMS = {
    "printf", "cat", "tac", "nl", "ls", "head", "tail", "wc", "cut",
    "grep", "egrep", "fgrep", "file", "stat", "du", "df", "basename", "dirname",
    "realpath", "readlink", "which", "whoami", "id", "ping", "host", "dig", "nslookup",
}  # fmt: skip


def program_name(literal: str) -> str:
    """`/bin/grep` or `C:\\Tools\\grep.exe` -> `grep`. Only `.exe` is dropped: `.bat` and
    `.cmd` files run through cmd.exe, which re-parses the arguments."""
    name = literal.replace("\\", "/").rsplit("/", 1)[-1].lower()
    return name[: -len(".exe")] if name.endswith(".exe") else name


def _argv_is_inert(words: list[str | None]) -> bool:
    """The program is a fixed, allow-listed inert program, and no dynamic value is an
    option's argument (`grep -f VALUE` reads any file). Whether a flag takes an argument
    is program-specific, so a value right after any flag is refused; after `--` (end of
    options) it is a plain operand."""
    program = words[0]
    if program is None or program_name(program) not in INERT_PROGRAMS:
        return False
    return not any(
        value is None and prev is not None and prev.startswith("-") and prev != "--"
        for prev, value in zip(words, words[1:], strict=False)
    )


# -- code injection / weak hashing ----------------------------------------------------------


def _codei(call: ast.Call, ctx: FileContext):
    names = ctx.call_names(call)
    if not names & {"eval", "builtins.eval"} or len(call.args) != 1 or call.keywords:
        return None
    return (
        "If only Python literals are expected, parse them with ast.literal_eval, which "
        "never executes code (it raises ValueError for anything else).",
        f"ast.literal_eval({ctx.segment(call.args[0])})",
        ("ast",),
    )


def _weak_crypto(call: ast.Call, ctx: FileContext):
    func = call.func
    if isinstance(func, ast.Attribute) and func.attr in {"md5", "sha1"}:
        if "hashlib." + func.attr not in ctx.call_names(call):
            return None
        new_func = ctx.segment(func.value) + ".sha256"
        args = ", ".join(ctx.segment(a) for a in [*call.args, *call.keywords])
        return (
            "Use SHA-256. If the hash is not security-relevant (e.g. a cache key), keep the "
            "algorithm and pass usedforsecurity=False instead.",
            f"{new_func}({args})",
            (),
        )
    return None


BUILDERS: dict[str, Callable] = {SQLI: _sqli, CMDI: _cmdi, CODEI: _codei, WEAK_CRYPTO: _weak_crypto}


# -- edits: location, application, validation -------------------------------------------


def _call_at(ctx: FileContext, region: Region) -> ast.Call | None:
    """The call exactly spanning `region` (`a(x).b()` and `a(x)` share a start)."""
    for node in ast.walk(ctx.tree):
        if isinstance(node, ast.Call) and _node_region(ctx, node) == region:
            return node
    return None


def _node_region(ctx: FileContext, node: ast.AST) -> Region:
    return Region(
        path=ctx.path,
        start_line=node.lineno,
        start_column=ctx.char_column(node.lineno, node.col_offset),
        end_line=node.end_lineno,
        end_column=ctx.char_column(node.end_lineno, node.end_col_offset),
    )


def _import_edit(ctx: FileContext, module: str) -> FixEdit | None:
    for node in ctx.tree.body:
        if isinstance(node, ast.Import) and any(
            a.name == module and a.asname is None for a in node.names
        ):
            return None  # already imported at module level
    body = ctx.tree.body
    line, i = 1, 0
    if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant):
        line, i = body[0].end_lineno + 1, 1  # after the module docstring
    while i < len(body) and isinstance(body[i], (ast.Import, ast.ImportFrom)):
        line, i = body[i].end_lineno + 1, i + 1  # after the leading import block
    header = 0
    for n, text in enumerate(ctx.lines[:2], start=1):
        if (n == 1 and text.startswith("#!")) or re.match(r"^[ \t\f]*#.*?coding[:=]", text):
            header = n  # shebang / PEP 263 cookie must stay on lines 1-2
    line = max(line, header + 1)
    return FixEdit(Region(ctx.path, line, 1, line, 1), f"import {module}\n")


def apply_edits(source: str, edits: tuple[FixEdit, ...]) -> str:
    """Apply non-overlapping edits (1-based char columns, exclusive ends)."""
    starts = [0] + [m.end() for m in re.finditer(r"\r\n|\r|\n", source)]

    def offset(line: int, col: int | None, end: bool) -> int:
        if line - 1 >= len(starts):
            return len(source)
        base = starts[line - 1]
        if col is None:
            nxt = starts[line] if line < len(starts) else len(source)
            return len(source[base:nxt].rstrip("\r\n")) + base if end else base
        return base + col - 1

    spans = sorted(
        (
            offset(e.region.start_line, e.region.start_column, False),
            offset(e.region.end_line, e.region.end_column, True),
            e.replacement,
        )
        for e in edits
    )
    for (_, end_a, _), (start_b, _, _) in zip(spans, spans[1:], strict=False):
        if start_b < end_a:
            raise ValueError("overlapping edits")
    for start, end, text in reversed(spans):
        source = source[:start] + text + source[end:]
    return source


def _valid(ctx: FileContext, fix: Fix) -> bool:
    try:
        new_source = apply_edits(ctx.source, fix.edits)
        ast.parse(new_source)
    except (SyntaxError, ValueError):
        return False
    return new_source != ctx.source


def fix_diff(source: str, fix: Fix, path: str) -> str:
    """Unified diff of applying `fix` (derived on demand, never stored)."""
    new = apply_edits(source, fix.edits)
    return "".join(
        difflib.unified_diff(
            source.splitlines(keepends=True),
            new.splitlines(keepends=True),
            fromfile=f"a/{path}",
            tofile=f"b/{path}",
        )
    )
