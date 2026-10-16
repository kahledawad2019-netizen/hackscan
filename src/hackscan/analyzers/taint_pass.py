"""Pass 2: intra-procedural taint analysis over candidate sinks.

For each function (and the module and class bodies) the statements are interpreted
abstractly in order. Every variable maps to a `Taint` value; branches are joined, loops
iterate to a fixpoint. Within a statement, sub-expressions are scanned in evaluation
order, so `:=` bindings and container mutations take effect exactly where Python
applies them. When a candidate sink is reached, its argument is evaluated in the current
environment (joined over every visit).

Outcome per candidate (only for classes the engine models, see `TAINT_CLASSES`):
- provably constant              -> suppressed `taint:constant_input`
- sanitized for the finding class -> suppressed `taint:sanitized`
- reaches an untrusted source     -> confirmed, with a source trace, when the flow is
                                     established (see `Source.assumed`)
- otherwise (parameters, unknown calls, closures, imports) -> stays a candidate

Soundness stance: suppression only when *every* path yields constant/sanitized values.
Mutable values are tracked conservatively: a mutable object that is aliased, mutated,
passed to an unmodeled call, stored elsewhere or captured by a nested scope may change
behind the analysis' back, so it is joined with `unknown` at that point.
"""

from __future__ import annotations

import ast
import re
import string
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, replace

from hackscan.analyzers.interproc import (
    ASSUMED,
    DROP,
    MODEL,
    CallSite,
    FileFacts,
    Flow,
    FunctionFacts,
    SymbolPair,
    _import_base,
    digits,
    finding_key,
    join_marks,
    linkable_functions,
    models_of,
    module_name,
    module_symbols,
    outer_parts,
    parameters,
    quoted,
    sanitized_for,
)
from hackscan.core.models import ASSUMED_VERDICT, CONFIRMED_VERDICT, Evidence, Finding, Status
from hackscan.core.taxonomy import CMDI, TAINT_CLASSES
from hackscan.plugins.base import FileContext, Match
from hackscan.plugins.scopes import COMPREHENSION_TYPES, FUNCTION_TYPES
from hackscan.taint import knowledge
from hackscan.taint.sanitizers import (
    INERT_PROGRAMS,
    NUMERIC_SANITIZERS,
    QUOTING_SANITIZERS,
    SANITIZERS,
    SQL_OBJECT_SANITIZERS,
)
from hackscan.taint.sources import flask_request_source, route_decorators_of

PRODUCER = "taint"
CONSTANT_INPUT = "taint:constant_input"
SANITIZED = "taint:sanitized"
CONFIRMED_CONFIDENCE_BOOST = 35
POSIX_QUOTED_CONFIDENCE = 20
MAX_LOOP_ITERATIONS = 5

# Calls that neither mutate nor retain their arguments.
NON_ESCAPING_CALLS = frozenset(
    {
        "str",
        "repr",
        "format",
        "ascii",
        "bytes",
        "len",
        "print",
        "isinstance",
        "id",
        "hash",
        "bool",
        "int",
        "float",
        "sorted",
        "any",
        "all",
        "min",
        "max",
        "sum",
        "tuple",
        "list",
        "set",
        "frozenset",
        "dict",
    }
)
# Builtins whose result is derived only from their arguments.
# Pure builtins returning a new string.
STR_BUILTINS = frozenset({"str", "repr", "format", "ascii"})
PURE_BUILTINS = frozenset(
    {"str", "repr", "format", "ascii", "bytes", "tuple", "sorted", "frozenset"}
)
# Builtins returning a fresh mutable container built from their arguments.
MUTABLE_BUILTINS = frozenset({"list", "dict", "set", "bytearray"})
# String methods: result is a new immutable string derived from receiver and args.
STRING_METHODS = frozenset(
    {
        "join",
        "format",
        "format_map",
        "strip",
        "lstrip",
        "rstrip",
        "lower",
        "upper",
        "title",
        "capitalize",
        "casefold",
        "replace",
        "encode",
        "decode",
        "removeprefix",
        "removesuffix",
        "zfill",
        "center",
        "ljust",
        "rjust",
        "expandtabs",
        "swapcase",
    }
)
# The arguments of a string method that become part of its result (others: none).
STRING_DATA_ARGS = {"replace": (1,), "center": (1,), "ljust": (1,), "rjust": (1,)}
# String-building methods whose receiver is a template (quote context applies).
TEMPLATE_METHODS = frozenset({"join", "format", "format_map"})
# String methods that only change letter case or remove characters: a sanitized value's
# characters stay in its safe set (the sanitizers are numeric conversions, quoting helpers
# whose credit `unquote` already drops, and psycopg objects). Others (`replace`,
# `translate`, `decode`, `split`, ...) may produce arbitrary characters.
CREDIT_KEEPING_METHODS = frozenset(
    {
        "lower",
        "upper",
        "casefold",
        "title",
        "capitalize",
        "swapcase",
        "strip",
        "lstrip",
        "rstrip",
        "zfill",
    }
)
# Numeric builtins that return whatever `__abs__` / `__round__` returns.
NUMERIC_PASSTHROUGH = frozenset({"abs", "round", "builtins.abs", "builtins.round"})
# Pure builtins returning a container of the argument's elements.
CONTAINER_BUILTINS = frozenset({"tuple", "sorted", "frozenset"})
# The arguments of a builtin conversion that are its result's data (others: options).
BUILTIN_DATA_ARGS = {
    n: (0,) for n in ("str", "bytes", "bytearray", "repr", "ascii", "tuple", "sorted", "frozenset")
}


# Keyword spellings of those data arguments (`str(object=x)`, `bytes(source=x)`).
BUILTIN_DATA_KEYWORDS = {"str": {"object"}, "bytes": {"source"}, "bytearray": {"source"}}


def _builtin_data_keywords(names: frozenset[str]) -> set[str]:
    """Data keywords common to every builtin `names` may be."""
    names = frozenset(n[len("builtins.") :] if n.startswith("builtins.") else n for n in names)
    found = [BUILTIN_DATA_KEYWORDS.get(n, set()) for n in names if n in BUILTIN_DATA_ARGS]
    return set.intersection(*found) if found and len(found) == len(names) else set()


def _builtin_roles(names: frozenset[str]) -> frozenset[int] | None:
    """Data positions common to every builtin `names` may be (None: all are data)."""
    names = frozenset(n[len("builtins.") :] if n.startswith("builtins.") else n for n in names)
    roles = [BUILTIN_DATA_ARGS[n] for n in names if n in BUILTIN_DATA_ARGS]
    if not roles or len(roles) != len(names):
        return None
    return frozenset.intersection(*(frozenset(r) for r in roles))


# Builtins that make characters out of numbers: `format(65, "c")`, `bytes([65])`.
CHAR_BUILTINS = frozenset({"format", "bytes", "bytearray"})
# Element access and builtin conversions (`int.to_bytes`, `bytes.hex`): the result is (part
# of, or an encoding of) the receiver's data, whatever its type.
ACCESSOR_METHODS = frozenset(
    {
        "get",
        "getlist",
        "getall",
        "getone",
        "pop",
        "popitem",
        "copy",
        "values",
        "items",
        "keys",
        "to_dict",
        "dict",
        "lists",
    }
)
# Container methods that store their arguments in the receiver (established).
MUTATOR_METHODS = frozenset(
    {
        "append",
        "extend",
        "insert",
        "add",
        "update",
        "setdefault",
        "appendleft",
        "extendleft",
        "__setitem__",
        "__iadd__",
    }
)
# Library functions whose result carries their argument's data (decoding, parsing, path
# assembly): the flow stays established. They grant no sanitizer credit.
PRESERVING_FUNCTIONS: dict[str, tuple[tuple[int, ...] | None, tuple[str, ...]]] = {
    # name -> (data argument positions (None: every positional argument), data keywords)
    "json.loads": ((0,), ("s",)),
    "ast.literal_eval": ((0,), ("node_or_string",)),
    "compile": ((0,), ("source",)),
    "builtins.compile": ((0,), ("source",)),
    "base64.b64decode": ((0,), ("s",)),
    "base64.urlsafe_b64decode": ((0,), ("s",)),
    "base64.standard_b64decode": ((0,), ("s",)),
    "base64.b32decode": ((0,), ("s",)),
    "base64.b16decode": ((0,), ("s",)),
    "binascii.unhexlify": ((0,), ("hexstr",)),
    "binascii.a2b_base64": ((0,), ("data",)),
    "urllib.parse.unquote": ((0,), ("string",)),
    "urllib.parse.unquote_plus": ((0,), ("string",)),
    "urllib.parse.unquote_to_bytes": ((0,), ("string",)),
    "html.unescape": ((0,), ("s",)),
    "re.sub": ((1, 2), ("repl", "string")),
    "re.subn": ((1, 2), ("repl", "string")),
    "os.path.join": (None, ()),
    "os.path.abspath": ((0,), ("path",)),
    "os.path.normpath": ((0,), ("path",)),
    "os.path.expanduser": ((0,), ("path",)),
    "os.fspath": ((0,), ("path",)),
    "posixpath.join": (None, ()),
    "ntpath.join": (None, ()),
}


# One name per library model (the same function under another module name).
CANONICAL_MODELS = {"posixpath.join": "os.path.join", "ntpath.join": "os.path.join"}


def canonical_model(name: str) -> str:
    name = CANONICAL_MODELS.get(name, name)
    return name[len("builtins.") :] if name.startswith("builtins.") else name


# Builtins dispatched by name, also when qualified (`builtins.str`).
BUILTIN_CALLS = MUTABLE_BUILTINS | PURE_BUILTINS | frozenset({"abs", "round"})
# Calls modelled by their resolved name (their flow depends on that name, see `_call`).
_BARE_MODELLED = (
    PURE_BUILTINS | STR_BUILTINS | MUTABLE_BUILTINS | CHAR_BUILTINS | CONTAINER_BUILTINS
)
MODELLED_NAMES = (
    frozenset(SANITIZERS)
    | frozenset(PRESERVING_FUNCTIONS)
    | NUMERIC_PASSTHROUGH
    | _BARE_MODELLED
    | frozenset("builtins." + n for n in _BARE_MODELLED)
)
# Modelled functions that make other characters out of digits (binary decoders).
DIGIT_BREAKING = frozenset(
    n for n in PRESERVING_FUNCTIONS if n.startswith(("base64.", "binascii."))
)
# Builtin conversions of numbers and bytes: the result encodes the receiver's data.
CONVERSION_METHODS = frozenset({"to_bytes", "hex", "tobytes"})
# Accessors that return their second argument when the key is missing.
DEFAULT_ACCESSORS = frozenset({"get", "pop", "setdefault"})


# Methods that read an input stream's own data.
READ_METHODS = frozenset({"read", "readline", "readlines", "read1", "readall", "getvalue"})
# The arguments a mutator stores (others: all): `insert(index, x)`, `setdefault(key, x)`.
MUTATOR_DATA = {"insert": (1,), "__setitem__": (1,)}
# Methods on a mutable receiver known not to modify it.
READONLY_METHODS = frozenset(
    {"count", "index", "copy", "get", "keys", "values", "items", "__len__", "__contains__"}
)
# Text that changes how a quoted value is read: quotes and a backslash (a larger quoted
# word, an escaped quote) and shell syntax that starts another command or groups words
# (`;`, `|`, `&`, `$(...)`, redirections, braces, newlines). (A glob, `~` or `#` in an
# argument cannot make the quoted value code; a glob program word is no inert name.)
SHELL_META_CHARS = frozenset("'\"`\\;|&$()<>{}^\n\r")
# Programs a shell-quoted operand of which stays data (`echo` too: it only prints). Not
# `printf`: the shell builtin (bash) evaluates an array subscript in a `-v` variable name.
QUOTING_INERT_PROGRAMS = frozenset((INERT_PROGRAMS - {"printf"}) | {"echo"})
# printf-style conversions; only plain `%s` (and `%%`) insert a quoted value as is.
PRINTF_SPEC = re.compile(r"%(?:\([^)]*\))?[#0\- +]*(?:\*|\d+)?(?:\.(?:\*|\d+))?[hlL]?(.)", re.S)


@dataclass(frozen=True, order=True)
class Source:
    line: int
    description: str
    # Reaches the value only through a call nobody models (`via`): possible, not established.
    assumed: bool = False
    via: str = ""
    # The classes this source was sanitized for on its way (the value's `safe_for` is what
    # the whole value is sanitized for; a confirmation needs one unsanitized source).
    safe: frozenset[str] = frozenset()


@dataclass(frozen=True)
class Taint:
    sources: frozenset[Source] = frozenset()
    unknown: bool = False
    safe_for: frozenset[str] = TAINT_CLASSES
    # May refer to a mutable object (list/dict/set/...), which can change in place.
    mutable: bool = False
    # Text is known not to open a shell quote context: literals without quote characters,
    # numbers, or output of a quoting sanitizer (which is self-balanced).
    shell_plain: bool = True
    # Command-injection safety relies on a quoting sanitizer (context-sensitive).
    quote_sanitized: bool = False
    # Symbolic parts for inter-procedural linking (see `interproc`): parameters and call
    # results this value may come from, each with the classes it was sanitized for.
    # They never affect the verdict of this pass.
    symbols: frozenset[SymbolPair] = frozenset()

    # A SQL object (SQL_OBJECT_SANITIZERS): its credit holds only for the object itself.
    sql_object: bool = False
    # A list/tuple/set/dict: indexing selects one whole element (not characters of a text).
    container: bool = False
    # A number (numeric literal, numeric sanitizer, arithmetic of numbers): `%` is modulo.
    number: bool = False
    # The (command) text starts with a complete program word, written as a literal, that does
    # not run its operands or input as code (see `starts_with_program`). Shell-quoting credit
    # needs it: a quoted value in the program position is the program itself.
    program_start: bool = False

    @property
    def is_constant(self) -> bool:
        return not self.sources and not self.unknown


CONST = Taint()
UNKNOWN = Taint(unknown=True, safe_for=frozenset(), mutable=True, shell_plain=False)


def combine(values: Iterable[Taint]) -> Taint:
    """Value derived from all of `values` (also the join of alternative paths)."""
    sources: set[Source] = set()
    symbols: set[SymbolPair] = set()
    unknown = mutable = quote_sanitized = sql_object = False
    shell_plain = container = number = program_start = True
    count = 0
    safe = set(TAINT_CLASSES)
    for v in values:
        sources |= v.sources
        symbols |= v.symbols
        unknown = unknown or v.unknown
        safe &= v.safe_for
        mutable = mutable or v.mutable
        shell_plain = shell_plain and v.shell_plain
        quote_sanitized = quote_sanitized or v.quote_sanitized
        sql_object = sql_object or v.sql_object
        container = container and v.container
        number = number and v.number
        program_start = program_start and v.program_start
        count += 1
    return Taint(
        frozenset(sources),
        unknown,
        frozenset(safe),
        mutable,
        shell_plain,
        quote_sanitized,
        frozenset(symbols),
        sql_object=sql_object,
        container=container and count > 0,
        number=number and count > 0,
        program_start=program_start and count > 0,
    )


def _unsafe_symbols(value: Taint, classes: frozenset[str]) -> Taint:
    """Drop `classes` (credit marks) from what the symbolic parts and the sources count as
    sanitized for. A symbolic part also records the drop: credit its caller gave it before
    is invalidated too (see `interproc.then`)."""
    if not value.symbols and not any(s.safe & classes for s in value.sources):
        return value
    drops = frozenset(DROP + c for c in classes)
    return replace(
        value,
        symbols=frozenset((a, (s - classes) | drops) for a, s in value.symbols),
        sources=frozenset(replace(s, safe=s.safe - classes) for s in value.sources),
    )


# Credit that a number's text gives (see `interproc.DIGITS`).
DIGIT_MARKS = frozenset(digits(c) for c in TAINT_CLASSES)
# Every credit mark: plain credit per class, shell-quoting credit, a number's text.
CREDIT_MARKS = TAINT_CLASSES | {quoted(CMDI)} | DIGIT_MARKS


def assume(value: Taint, via: str) -> Taint:
    """`value` after a call nobody models: its untrusted parts may still flow on, but only as
    assumed (they never confirm), sources and symbolic parts alike."""
    if not value.sources and not value.symbols:
        return value
    return replace(
        value,
        sources=frozenset(
            s if s.assumed else replace(s, assumed=True, via=via) for s in value.sources
        ),
        symbols=frozenset(
            (a, join_marks(s, frozenset({f"{ASSUMED}:{via}"}))) for a, s in value.symbols
        ),
    )


def _with_symbol(value: Taint, atom: tuple) -> Taint:
    return replace(value, symbols=value.symbols | {(atom, frozenset())})


def concat(values: list[Taint]) -> Taint:
    """A string assembled from `values` (f-string, `+`, `%`, `.format`, `.join`).

    Shell quoting is context-sensitive: `'echo "' + shlex.quote(x) + '"'` puts the
    quoted value inside double quotes where `$(...)` still expands. If any part could
    open a quote context, quoting-based command-injection safety is dropped.
    """
    result = combine(values)
    if not result.shell_plain and any(v.quote_sanitized for v in values):
        result = replace(result, safe_for=result.safe_for - {CMDI})
        result = _unsafe_symbols(result, frozenset({quoted(CMDI)}))
    # (`+` of numbers is arithmetic: still a number)
    number = bool(values) and all(v.number for v in values)
    program_start = bool(values) and values[0].program_start  # the command's first word
    return replace(
        result, mutable=False, container=False, number=number, program_start=program_start
    )


def known(value: Taint) -> bool:
    """A constant with no symbolic parts: the same text on every run."""
    return value.is_constant and not value.symbols


# Characters of a literal program word: no whitespace, shell syntax, assignment (`FOO=x`),
# placeholder (`%s`, `{}`, a `.format` field's `\0`), quote or glob.
PROGRAM_CHARS = r"[^ \t\n\r;&|<>()$`'\"\\=%{}*?\[\]~!#^\0]+"
# The first word of a command when it is complete within the text: POSIX shells separate
# words by blanks (space, tab) only; other whitespace (`\v`, `\f`, NBSP) is part of a word.
PROGRAM_WORD = re.compile(rf"[ \t]*({PROGRAM_CHARS})[ \t]")
# Directories of the system programs the inert list names (elsewhere, `./ls` or `/opt/x/ls`
# may be any program).
SYSTEM_BIN_DIRS = frozenset(
    {"/bin", "/usr/bin", "/usr/local/bin", "/sbin", "/usr/sbin", "/usr/local/sbin"}
)


def inert_program(word: str) -> bool:
    """A literal program word naming a listed inert program exactly (POSIX names are case
    sensitive): a bare name, or one in a system bin directory."""
    if "\\" in word:
        return False
    directory, slash, name = word.rpartition("/")
    if slash and directory not in SYSTEM_BIN_DIRS:
        return False
    return name in QUOTING_INERT_PROGRAMS


def starts_with_program(text: str) -> bool:
    """Whether `text` starts with a complete program word naming a known inert program
    (`echo `, `/bin/ls -l `; not `sh -c `, `chrt `, `pyth` + `on3`, `%s `, `./ls `)."""
    m = PROGRAM_WORD.match(text)
    return m is not None and inert_program(m.group(1))


def item_of(value: Taint) -> Taint:
    """An item of an iterable (a character of a string, an element of a container): not the
    quoted whole, and not itself known to be a container. Only a container's elements
    (whole literals) keep the program flag; a character names no program."""
    return replace(
        unquote(value), container=False, program_start=value.program_start and value.container
    )


def unquote(value: Taint) -> Taint:
    """Any transformation of a shell-quoted value (strip, replace, slicing, repr...) may
    break the quoting, so quoting-based safety does not survive it. Symbolic parts lose
    it whether or not this value is quoted here: their quoting may come from a caller."""
    if not value.quote_sanitized:
        if not value.symbols:
            return value
        return _unsafe_symbols(value, frozenset({quoted(CMDI)}))
    value = _unsafe_symbols(value, frozenset({quoted(CMDI)}))
    # Its text holds quotes that may now be unbalanced (`shlex.quote("")[0]` is `'`).
    return replace(
        value, safe_for=value.safe_for - {CMDI}, quote_sanitized=False, shell_plain=False
    )


def literal(value: object) -> Taint:
    if isinstance(value, bytes):
        # Rendered into text (`str(b)`, f-strings, `%s`) bytes become `b'...'`.
        return Taint(shell_plain=False)
    if isinstance(value, str):
        return Taint(
            shell_plain=not (SHELL_META_CHARS & set(value)),
            program_start=starts_with_program(value),
        )
    if isinstance(value, (int, float, complex)):  # (bool is an int)
        return Taint(number=True)
    return CONST


def plain_template(node: ast.expr, *, printf: bool) -> bool:
    """A literal template whose placeholders insert values as is: `{}`/`{name}` fields
    without conversion or spec (`str.format`), or only `%s` (printf). `!r`, `%r`, padding
    and the like add or move characters around a quoted value."""
    if not (isinstance(node, ast.Constant) and isinstance(node.value, str)):
        return False
    text = node.value
    if printf:
        return all(m.group(0) in {"%s", "%%"} for m in PRINTF_SPEC.finditer(text))
    else:
        try:
            fields = list(string.Formatter().parse(text))
        except ValueError:
            return False
        if not all(conv is None and not spec for _, f, spec, conv in fields if f is not None):
            return False
        # `{0[0]}` / `{0.x}` insert a part of the value (`'` of a shell-quoted one)
        return not any(f is not None and ("." in f or "[" in f) for _, f, _, _ in fields)


def drop_credit(value: Taint, keep: frozenset[str] = frozenset()) -> Taint:
    """A transformation that can make arbitrary characters out of a sanitized value
    (`%c`, `int.to_bytes(...)`, `bytes([...])`, most methods): no sanitizer credit survives
    it, except the marks in `keep` per dependency. Transformations of constants stay
    constant."""
    if value.is_constant and not value.symbols:
        return value
    value = _unsafe_symbols(unquote(value), CREDIT_MARKS - keep)
    return replace(value, safe_for=frozenset())


def local_object(value: Taint) -> Taint:
    """A SQL object's credit stays within the function: a caller or callee may render it."""
    return drop_credit(value) if value.sql_object else value


def char_conversion(template: ast.expr | None, *, printf: bool) -> bool:
    """Whether a template may rewrite the inserted values: turn numbers into characters
    (`%c`, `{:c}`), select parts of them (`{0.wrapped}`, `{0[0]}`), or is unknown."""
    if not (isinstance(template, ast.Constant) and isinstance(template.value, str)):
        return True
    if printf:
        return any(m.group(1) == "c" for m in PRINTF_SPEC.finditer(template.value))
    try:
        fields = list(string.Formatter().parse(template.value))
    except ValueError:
        return True
    return any(
        f is not None and (spec_converts(spec) or "." in f or "[" in f) for _, f, spec, _ in fields
    )


# Format specs that only align with spaces/zeros, sign, pad, group and pick a numeric (or
# `s`) type. A fill character (`{:->9}`, repeated a number of times that depends on the
# value), type `c` or a nested `{...}` spec may produce other characters.
SAFE_SPEC = re.compile(r"(?:[ 0]?[<>=^])?[+\- ]?z?#?0?\d*[,_]?(?:\.\d+)?[bdeEfFgGnosxX%]?")


def spec_converts(spec: str | None) -> bool:
    """A format spec that may produce characters other than the value's own text."""
    return bool(spec) and SAFE_SPEC.fullmatch(spec) is None


def formatted(value: Taint) -> Taint:
    """Text from a template that converts or pads (`!r`, `%r`, `{:'>9}`): it may contain
    quotes that no literal shows (`("%r" % "x")[:1]` is `'`)."""
    return replace(value, shell_plain=False, program_start=False)


def source(description: str, node: ast.AST) -> Taint:
    return Taint(
        frozenset({Source(getattr(node, "lineno", 0), description)}),
        safe_for=frozenset(),
        shell_plain=False,
    )


def from_note(*keys: tuple[str, str]) -> bool:
    """Whether every knowledge entry behind a source is a project note (none is built in)."""
    provenance = knowledge.active().provenance
    return all(provenance.get(k) == knowledge.PROJECT_NOTE for k in keys)


def known_source(description: str, node: ast.AST, *keys: tuple[str, str]) -> Taint:
    """A source named by knowledge entries. Built-in sources are text values (as before); an input
    that only a project note names may be any object, so it is treated as possibly mutable, with
    its own methods: escaping and mutation stay conservative, and a note never suppresses."""
    value = source(description, node)
    return replace(value, mutable=True) if keys and from_note(*keys) else value


Env = dict[str, Taint]


def join_env(a: Env | None, b: Env | None) -> Env | None:
    if a is None:
        return None if b is None else dict(b)
    if b is None:
        return dict(a)
    out = dict(a)
    for k, v in b.items():
        out[k] = combine((out[k], v)) if k in out else v
    return out


# -- public API ---------------------------------------------------------------------------


def apply_taint(ctx: FileContext, candidates: list[tuple[Finding, Match]]) -> list[Finding]:
    """Return findings updated with taint results (same order; never drops any)."""
    return analyze_taint(ctx, candidates, link=False)[0]


def analyze_taint(
    ctx: FileContext, candidates: list[tuple[Finding, Match]], *, link: bool = True
) -> tuple[list[Finding], FileFacts | None]:
    """Like `apply_taint`; with `link`, also return this file's inter-procedural facts."""
    targets = {
        id(m.node): m
        for f, m in candidates
        if f.vuln_class in TAINT_CLASSES and m.arg is not None and f.status is Status.CANDIDATE
    }
    if not targets and not link:
        return [f for f, _ in candidates], None
    facts = FileFacts(ctx.path, module_name(ctx.path)) if link else None
    engine = _FileEngine(ctx, targets, facts)
    results = engine.run()
    findings = []
    for f, m in candidates:
        taint = results.get(id(m.node))
        if taint is not None:
            taint = _for_sink(f, taint)  # (so the exported flow is the one that was decided)
        decided = _decide(f, taint, defer=facts is not None)
        deferred = any(e.message == DEFERRED_VERDICT for e in decided.evidence)
        if (
            facts is not None
            and taint is not None
            and (taint.symbols or deferred)
            and decided.status is Status.CANDIDATE
        ):
            facts.sinks[finding_key(decided)] = _flow(ctx, taint)
        findings.append(decided)
    return findings, facts


def _flow(ctx: FileContext, value: Taint) -> Flow:
    return Flow(
        frozenset(
            ((ctx.path, s.line, s.description), s.safe) for s in value.sources if not s.assumed
        ),
        value.safe_for,
        value.symbols,
        frozenset(
            (
                (ctx.path, s.line, s.description),
                join_marks(s.safe, frozenset({f"{ASSUMED}:{s.via}"})),
            )
            for s in value.sources
            if s.assumed
        ),
    )


DEFERRED_VERDICT = (
    "Untrusted data reaches the sink only through library models; whether scanned code may "
    "replace them is decided with the whole scan."
)


def _for_sink(finding: Finding, taint: Taint) -> Taint:
    """`taint` as this sink sees it. For a command, a quoted value may be the program itself
    (`os.system(quote(x))`), or the program is not known to leave its operands alone
    (`sh -c`): quoting proves nothing there."""
    if finding.vuln_class == CMDI and taint.quote_sanitized and not taint.program_start:
        return unquote(taint)
    return taint


def _decide(finding: Finding, taint: Taint | None, *, defer: bool = False) -> Finding:
    if taint is None or finding.vuln_class not in TAINT_CLASSES:
        return finding
    if taint.is_constant:
        return replace(
            finding,
            status=Status.SUPPRESSED,
            suppression=CONSTANT_INPUT,
            confidence=0,
            evidence=(
                *finding.evidence,
                Evidence(PRODUCER, "taint_verdict", "Every path supplies a constant value."),
            ),
        )
    taint = _for_sink(finding, taint)
    if finding.vuln_class == CMDI and CMDI in taint.safe_for and taint.quote_sanitized:
        # shlex.quote protects POSIX shells only; under Windows cmd.exe `&`, `|` still
        # chain commands. The target platform is unknown, so keep it visible.
        return replace(
            finding,
            confidence=min(finding.confidence, POSIX_QUOTED_CONFIDENCE),
            evidence=(
                *finding.evidence,
                Evidence(
                    PRODUCER,
                    "taint_verdict",
                    "Shell-quoted with POSIX quoting (shlex.quote); safe on POSIX shells only.",
                ),
            ),
        )
    if finding.vuln_class in taint.safe_for:
        return replace(
            finding,
            status=Status.SUPPRESSED,
            suppression=SANITIZED,
            evidence=(
                *finding.evidence,
                Evidence(PRODUCER, "taint_verdict", "Every path is sanitized for this sink."),
            ),
        )
    unsanitized = [s for s in taint.sources if not sanitized_for(s.safe, finding.vuln_class)]
    established = sorted(s for s in unsanitized if not s.assumed)
    if established and defer and all(models_of(s.safe) for s in established):
        # Every established path goes through a library model that another scanned file
        # might replace (`json.loads = ...`): `interproc.confirm_findings` decides.
        return replace(
            finding,
            evidence=(*finding.evidence, Evidence(PRODUCER, "taint_verdict", DEFERRED_VERDICT)),
        )
    if established:
        # With whole-scan linking, a path through a library model is decided there (it may be
        # replaced): the confirmation and its steps stand on the paths without one.
        shown = [s for s in established if not (defer and models_of(s.safe))]
        steps = tuple(
            Evidence(
                PRODUCER,
                "taint_step",
                f"Modelled flow: untrusted {s.description} at line {s.line}.",
            )
            for s in shown
        )
        return replace(
            finding,
            status=Status.CONFIRMED,
            confidence=min(100, finding.confidence + CONFIRMED_CONFIDENCE_BOOST),
            evidence=(
                *finding.evidence,
                *steps,
                Evidence(PRODUCER, "taint_verdict", CONFIRMED_VERDICT),
            ),
        )
    assumed = sorted({(s.line, s.description, s.via) for s in unsanitized if s.assumed})
    if assumed:
        finding = replace(
            finding,
            evidence=(
                *finding.evidence,
                *(
                    Evidence(
                        PRODUCER,
                        "taint_step",
                        f"Untrusted {description} at line {line} may reach the sink, but only "
                        f"through {via}, which is not modelled.",
                    )
                    for line, description, via in assumed
                ),
                Evidence(PRODUCER, "taint_verdict", ASSUMED_VERDICT),
            ),
        )
        return finding
    return replace(
        finding,
        evidence=(
            *finding.evidence,
            Evidence(
                PRODUCER,
                "taint_verdict",
                "Value origin not established within the function (parameter, call or "
                "non-local name); left for review.",
            ),
        ),
    )


# -- engine -------------------------------------------------------------------------------


class _FileEngine:
    def __init__(
        self, ctx: FileContext, targets: dict[int, Match], facts: FileFacts | None = None
    ) -> None:
        self.ctx = ctx
        self.targets = targets
        self.results: dict[int, Taint] = {}
        self.module_constants: frozenset[str] = frozenset()
        # Their module-level values: constant, but the shell quote characters still
        # matter where they are concatenated around a quoted value (`Q + quote(x) + Q`).
        self.module_constant_values: dict[str, Taint] = {}
        self.facts = facts
        # `globals()`, `exec`, `__dict__`...: module names may change behind our back.
        self.namespace = _Namespace(ctx.tree)
        self.namespace_exposed = self.namespace.module
        # For certainty (which flows are established): what this file may replace by name
        # (`_replaced_names`; code the program evaluates, `eval`/`exec`, is outside the model).
        # Its own namespace written (`globals()[...] = ...`): any of its names may change.
        self.replaced = _replaced_names(ctx.tree, module_symbols(ctx.tree, ctx.path), ctx.path)
        entries = {entry for entry, _ in self.replaced}
        self.replaced_names = {e for e in entries if not e.startswith("module:")}
        self.replaced_modules = {e[len("module:") :] for e in entries if e.startswith("module:")}
        self.namespace_written = bool(self.replaced_modules & {module_name(ctx.path), "*"})
        self.linked: dict[int, str] = {}  # id(def) -> name, for linkable functions
        self._call_targets: dict[int, str | None] = {}
        self._binding_counts: dict[int, dict[str, int]] = {}
        self._stored_attrs: frozenset[str] | None = None
        self._sites: dict[tuple[int, int], tuple[str, int, list[Taint], dict[str, Taint], str]] = {}
        if facts is not None:
            facts.symbols = module_symbols(ctx.tree, ctx.path)
            facts.replaced = self.replaced
            # (a module whose namespace may be written: `interproc` does not link into it)
            for func in linkable_functions(ctx.tree, facts.symbols):
                self.linked[id(func)] = func.name  # type: ignore[attr-defined]

    def run(self) -> dict[int, Taint]:
        module = _FunctionEngine(self, self.ctx.tree, request_params=frozenset())
        module_env = module.run({})
        if not module.has_walrus:  # see `_FunctionEngine.has_walrus`
            self.module_constants = self._constant_globals(module_env or {})
            self.module_constant_values = {n: module_env[n] for n in self.module_constants}
        for func in self._functions():
            if isinstance(func, ast.ClassDef):  # class body runs once, top to bottom
                _FunctionEngine(self, func, frozenset()).run({})
                continue
            params, request_params = self._initial_env(func)
            engine = _FunctionEngine(self, func, request_params)
            if isinstance(func, ast.Lambda):
                engine.visit_expression(func.body, params)
            else:
                engine.run(params)
            if self.facts is not None and id(func) in self.linked:
                positional, keyword = parameters(func)  # type: ignore[arg-type]
                returns = engine.returns
                self.facts.functions[self.linked[id(func)]] = FunctionFacts(
                    positional,
                    keyword,
                    _flow(self.ctx, returns) if returns is not None else None,
                )
        if self.facts is not None:
            for key, (target, line, positional, keywords, root) in sorted(self._sites.items()):
                self.facts.sites[key] = CallSite(
                    target,
                    line,
                    tuple(_flow(self.ctx, v) for v in positional),
                    tuple(sorted((k, _flow(self.ctx, v)) for k, v in keywords.items())),
                    root,
                )
        return self.results

    def record(self, call: ast.AST, value: Taint) -> None:
        prev = self.results.get(id(call))
        self.results[id(call)] = value if prev is None else combine((prev, value))

    def call_target(self, call: ast.Call) -> str | None:
        """Absolute dotted name of a module-level callee, when it can be named statically."""
        if self.facts is None:
            return None
        if id(call) not in self._call_targets:
            self._call_targets[id(call)] = self._resolve_target(call)
        return self._call_targets[id(call)]

    def _resolve_target(self, call: ast.Call) -> str | None:
        assert self.facts is not None
        if not self.stable_callee(call):
            return None  # the name may refer to a replacement (`f = other`)
        # (a file whose own namespace is written is a replaced module: `interproc` does not
        # link its calls, see `_solve`)
        parts: list[str] = []
        func = call.func
        while isinstance(func, ast.Attribute):
            parts.append(func.attr)
            func = func.value
        if not isinstance(func, ast.Name) or not self.module_owned(func.id, call):
            return None
        entry = self.facts.symbols.get(func.id)
        if entry is None:
            return None
        kind, target = entry
        base = f"{self.facts.module}.{target}" if kind == "def" else target
        return ".".join([base, *reversed(parts)])

    def stable_callee(self, call: ast.Call) -> bool:
        """Whether the callee of `call` (a name or `module.attr` chain) cannot have been
        replaced in this file: a stable root name, and no attribute of that name is
        assigned or deleted anywhere (`shlex.quote = ...`, `setattr`, `delattr`)."""
        attrs: list[str] = []
        root = call.func
        while isinstance(root, ast.Attribute):
            attrs.append(root.attr)
            root = root.value
        if not isinstance(root, ast.Name) or not self.stable_name(root.id, call):
            return False
        if not attrs:
            return True
        self.stable_callee_attrs()
        assert self._stored_attrs is not None
        return "*" not in self._stored_attrs and not (self._stored_attrs & set(attrs))

    def replaces_model(self, names: frozenset[str]) -> bool:
        """Whether this file may replace any of the library functions `names`: its own
        namespace (`namespace_written`), the function or a submodule on the way by name
        (`json.loads = ...`), or the owning module (`json.__dict__`, `vars(json)`)."""
        if self.namespace_written:
            return True
        for name in names:
            parts = canonical_model(name).split(".")
            owner = ".".join(parts[:-1]) or "builtins"
            if any(part in self.replaced_names for part in parts[1:] or parts):
                return True
            if any(owner == m or owner.startswith(m + ".") for m in self.replaced_modules):
                return True
        return False

    def stable_callee_attrs(self) -> None:
        if self._stored_attrs is None:
            stored: set[str] = set()
            for x in ast.walk(self.ctx.tree):
                if isinstance(x, ast.Attribute) and isinstance(x.ctx, (ast.Store, ast.Del)):
                    stored.add(x.attr)
                elif isinstance(x, ast.Name) and x.id in {"setattr", "delattr"}:
                    stored.add("*")  # any attribute, by a computed name
            self._stored_attrs = frozenset(stored)

    def stable_name(self, name: str, node: ast.AST) -> bool:
        """Whether `name` at `node` has exactly one binding (one import, one def) or none
        (a builtin), so that a resolved callee cannot be a later reassignment instead."""
        scope = self.ctx.scopes.scope_of(node)
        first = True
        while scope is not None:
            if isinstance(scope.node, ast.ClassDef) and not first:
                scope = scope.parent
                continue
            first = False
            if scope.star_imports:
                return False
            # Follow declarations like `ScopeIndex.resolve_name`; their assignments are
            # recorded as bindings of the owner scope.
            if name in scope.globals_ and scope is not self.ctx.scopes.module:
                scope = self.ctx.scopes.module
                continue
            if name in scope.nonlocals:
                scope = scope.parent
                while scope is not None and not scope.is_function:
                    scope = scope.parent
                continue
            if name in scope.bindings:
                if len(scope.bindings[name]) != 1:
                    return False
                if not isinstance(scope.node, (ast.Module, ast.ClassDef, *FUNCTION_TYPES)):
                    return False  # comprehension variable
                key = id(scope.node)
                if key not in self._binding_counts:
                    self._binding_counts[key] = _module_binding_counts(scope.node)
                return self._binding_counts[key].get(name) == 1
            scope = scope.parent
        return True

    def module_owned(self, name: str, node: ast.AST) -> bool:
        """Whether `name` at `node` refers to the module-level binding."""
        scope = self.ctx.scopes.scope_of(node)
        first = True
        while scope is not None:
            if isinstance(scope.node, ast.ClassDef) and not first:
                scope = scope.parent
                continue
            first = False
            if name in scope.globals_:
                return True
            if name in scope.nonlocals or name in scope.bindings:
                return scope is self.ctx.scopes.module
            scope = scope.parent
        return False

    def record_site(self, call: ast.Call, positional: list[Taint], keywords: dict[str, Taint]):
        target = self.call_target(call)
        if target is None:
            return
        key = (call.lineno, call.col_offset)
        prev = self._sites.get(key)
        if prev is not None:
            n = min(len(prev[2]), len(positional))
            positional = [combine((a, b)) for a, b in zip(prev[2][:n], positional[:n], strict=True)]
            keywords = {
                k: combine((v, prev[3][k])) if k in prev[3] else v for k, v in keywords.items()
            } | {k: v for k, v in prev[3].items() if k not in keywords}
        root = call.func
        while isinstance(root, ast.Attribute):
            root = root.value
        name = root.id if isinstance(root, ast.Name) else ""
        self._sites[key] = (target, call.lineno, positional, keywords, name)

    def _functions(self) -> Iterator[ast.AST]:
        for node in ast.walk(self.ctx.tree):
            if isinstance(node, (*FUNCTION_TYPES, ast.ClassDef)):
                yield node

    def _constant_globals(self, module_env: Env) -> frozenset[str]:
        """Module names bound exactly once, to an immutable constant, never rebound via
        `global` and with no way to write the module namespace dynamically. (A function
        may run before a later rebinding, so the final value alone proves nothing.)"""
        if self.namespace_exposed:
            return frozenset()
        rebound = {
            name
            for node in ast.walk(self.ctx.tree)
            if isinstance(node, ast.Global)
            for name in node.names
        }
        counts = _module_binding_counts(self.ctx.tree)
        module_scope = self.ctx.scopes.module
        constants = set()
        for name, value in module_env.items():
            kinds = module_scope.bindings.get(name, set())
            if (
                value.is_constant
                and not value.mutable
                and name not in rebound
                and counts.get(name) == 1
                and all(k == "local" for k, _ in kinds)
            ):
                constants.add(name)
        return frozenset(constants)

    def _initial_env(self, func: ast.AST) -> tuple[Env, frozenset[str]]:
        args = func.args  # type: ignore[attr-defined]
        names = [a.arg for a in (*args.posonlyargs, *args.args, *args.kwonlyargs)]
        names += [a.arg for a in (args.vararg, args.kwarg) if a is not None]
        decorators = route_decorators_of(func)
        route = bool(decorators)
        note_route = route and from_note(*(("route_decorator", d) for d in decorators))
        fname = getattr(func, "name", "<lambda>")
        linked = self.linked.get(id(func))
        env: Env = {}
        for name in names:
            # Only built-in request-object names stop a route parameter from being a source: a
            # project note may add request objects but never removes an untrusted input.
            if (
                route
                and name not in {"self", "cls"}
                and name not in knowledge.BUILTIN.request_param_names
            ):
                env[name] = source(f"route parameter `{name}` of handler `{fname}`", func)
                if note_route:
                    env[name] = replace(env[name], mutable=True)
            elif linked is not None:
                env[name] = _with_symbol(UNKNOWN, ("param", self.ctx.path, linked, name))
            else:
                env[name] = UNKNOWN
        request_params = frozenset(n for n in names if n in knowledge.active().request_param_names)
        return env, request_params


class _FunctionEngine:
    def __init__(self, file: _FileEngine, scope: ast.AST, request_params: frozenset[str]) -> None:
        self.file = file
        self.ctx = file.ctx
        self.scope = scope
        self.request_params = request_params
        self.is_module = isinstance(scope, ast.Module)
        # Flow-insensitive alias groups among names that may share a mutable object.
        self.groups: dict[str, set[str]] = {}
        self.closure_loads, self.closure_stores = _closure_names(scope)
        # States at which an exception may be raised / control may leave a `try` early;
        # one collector per active `try` statement.
        self.try_states: list[list[Env]] = []
        # States at `break` / `continue`, one collector per active loop.
        self.break_states: list[list[Env]] = []
        self.continue_states: list[list[Env]] = []
        # Join of every returned value (linkable functions only).
        self.track_returns = id(scope) in file.linked
        self.returns: Taint | None = None
        # `:=` can rebind a name mid-expression, conditionally (short-circuits, chained
        # comparisons, `assert` messages, comprehension filters) or after an operand was
        # already evaluated. Statements are interpreted as a whole, so in a scope with its
        # own `:=` no sink is ever suppressed (confirmation still works).
        self.has_walrus = _has_own_walrus(scope) or (
            (self.is_module and file.namespace_exposed)
            # `locals()` in a class body writes the real class namespace.
            or (isinstance(scope, ast.ClassDef) and file.namespace.class_body(scope))
        )
        self.class_body = isinstance(scope, ast.ClassDef)
        self.shared = _declared_shared(scope)
        # >0 while scanning code that runs later (a generator expression's body).
        self.deferred = 0

    # -- statements ------------------------------------------------------------------------

    def run(self, env: Env) -> Env | None:
        return self.exec_block(self.scope.body, dict(env))  # type: ignore[attr-defined]

    def visit_expression(self, expr: ast.AST, env: Env) -> None:
        self._scan(expr, env)

    def exec_block(self, stmts: list[ast.stmt], env: Env | None) -> Env | None:
        for stmt in stmts:
            if env is None:
                return None
            env = self.exec_stmt(stmt, env)
        return env

    def exec_stmt(self, stmt: ast.stmt, env: Env) -> Env | None:
        if self.try_states:  # any statement may raise (or return) from here
            self.try_states[-1].append(dict(env))
        for node in _header_nodes(stmt):
            self._scan(node, env)
        if self.try_states and isinstance(stmt, (ast.Return, ast.Raise)):
            self.try_states[-1].append(dict(env))  # after evaluating e.g. `return x := ...`

        if isinstance(stmt, ast.Assign):
            value = self.eval(stmt.value, env)
            for target in stmt.targets:
                self._assign(target, value, env, stmt.value)
        elif isinstance(stmt, ast.AnnAssign):
            if stmt.value is not None:
                self._assign(stmt.target, self.eval(stmt.value, env), env, stmt.value)
        elif isinstance(stmt, ast.AugAssign):
            current = self.eval(stmt.target, env)
            value = self.eval(stmt.value, env)
            if current.mutable:
                value = combine((current, value))
            elif isinstance(stmt.op, ast.Add):
                value = concat([current, value])  # `cmd += ...` builds text like `+`
            elif isinstance(stmt.op, ast.Mod):  # like `%` with a template that is not a literal
                value = formatted(concat([unquote(current), drop_credit(value)]))
            else:  # arithmetic, like the BinOp case
                value = unquote(combine((current, value)))
            if current.mutable and isinstance(stmt.target, ast.Name):
                self._weak_update(stmt.target.id, value, env)  # in-place `+=` on lists
            else:
                self._assign(stmt.target, value, env, None)
        elif isinstance(stmt, (ast.Return, ast.Raise)):
            if self.track_returns and isinstance(stmt, ast.Return) and stmt.value is not None:
                value = local_object(self.eval(stmt.value, env))
                self.returns = value if self.returns is None else combine((self.returns, value))
            return None
        elif isinstance(stmt, ast.Break):
            if self.break_states:
                self.break_states[-1].append(dict(env))
            return None  # statements after `break` do not run on this path
        elif isinstance(stmt, ast.Continue):
            if self.continue_states:
                self.continue_states[-1].append(dict(env))
            return None
        elif isinstance(stmt, ast.If):
            then = self.exec_block(stmt.body, dict(env))
            other = self.exec_block(stmt.orelse, dict(env))
            return join_env(then, other)
        elif isinstance(stmt, (ast.For, ast.AsyncFor)):
            return self._loop(stmt, env, target=stmt.target, iter_=stmt.iter)
        elif isinstance(stmt, ast.While):
            return self._loop(stmt, env, target=None, iter_=None)
        elif isinstance(stmt, (ast.With, ast.AsyncWith)):
            for item in stmt.items:
                if item.optional_vars is not None:
                    value = self.eval(item.context_expr, env)
                    self._assign(item.optional_vars, value, env, item.context_expr)
            return self.exec_block(stmt.body, env)
        elif isinstance(stmt, ast.Try) or type(stmt).__name__ == "TryStar":
            return self._try(stmt, env)
        elif isinstance(stmt, ast.Match):
            subject = self.eval(stmt.subject, env)
            # A failed pattern or a false guard may leave captures bound, so later cases
            # and the no-match path see them too.
            fall: Env = dict(env)
            out: Env | None = None
            for case in stmt.cases:
                case_env = dict(fall)
                for node in ast.walk(case.pattern):
                    name = getattr(
                        node, "rest" if isinstance(node, ast.MatchMapping) else "name", None
                    )
                    if isinstance(name, str):
                        # The capture may be (part of) the subject object: alias them.
                        target = ast.Name(id=name, ctx=ast.Store())
                        self._assign(target, subject, case_env, stmt.subject)
                if case.guard is not None:
                    self._scan(case.guard, case_env)
                fall = join_env(fall, case_env) or fall
                out = join_env(out, self.exec_block(case.body, dict(case_env)))
            return join_env(out, fall)
        elif isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            env[stmt.name] = UNKNOWN
        elif isinstance(stmt, (ast.Import, ast.ImportFrom)):
            for alias in stmt.names:
                if alias.name != "*":
                    env[(alias.asname or alias.name).split(".")[0]] = UNKNOWN
        elif isinstance(stmt, ast.Delete):
            for target in stmt.targets:
                if isinstance(target, ast.Name):
                    env.pop(target.id, None)
        return env

    def _loop(self, stmt: ast.stmt, env: Env, target: ast.AST | None, iter_: ast.AST | None):
        entry = dict(env)
        current: Env = dict(env)
        breaks: list[Env] = []
        for _ in range(MAX_LOOP_ITERATIONS):
            body_env = dict(current)
            if target is not None and iter_ is not None:
                # an item of the iterable (a character of a string), never the whole
                self._assign(target, item_of(self.eval(iter_, body_env)), body_env, iter_)
            self.break_states.append([])
            self.continue_states.append([])
            try:
                out = self.exec_block(stmt.body, body_env)  # type: ignore[attr-defined]
            finally:
                breaks.extend(self.break_states.pop())
                continues = self.continue_states.pop()
            for state in continues:  # `continue` jumps back to the loop head
                out = join_env(out, state)
            if isinstance(stmt, ast.While) and out is not None:
                self._scan(stmt.test, out)  # condition re-evaluated each iteration
            merged = join_env(current, out)
            if merged == current:
                break
            current = merged or current
        else:  # no fixpoint within the budget: give up precision, stay sound
            current = {k: combine((v, UNKNOWN)) for k, v in current.items()}
        # Normal exit (condition false / iterator exhausted) runs `else`; `break` skips it.
        normal_exit = join_env(entry, current)
        out_env = self.exec_block(stmt.orelse, normal_exit)  # type: ignore[attr-defined]
        for state in breaks:
            out_env = join_env(out_env, state)
        return out_env

    def _try(self, stmt: ast.stmt, env: Env) -> Env | None:
        # Handlers can be entered from any point in the body, so they see the join of
        # every state the body passed through (including just before a raise/return).
        self.try_states.append([dict(env)])
        body_out = self.exec_block(stmt.body, dict(env))  # type: ignore[attr-defined]
        raise_points = list(self.try_states[-1])
        outs: Env | None = self.exec_block(stmt.orelse, body_out)  # type: ignore[attr-defined]
        handler_entry: Env | None = None
        for state in [*raise_points, body_out]:
            handler_entry = join_env(handler_entry, state)
        for handler in stmt.handlers:  # type: ignore[attr-defined]
            h_env = dict(handler_entry or env)
            if handler.name:
                h_env[handler.name] = UNKNOWN
            outs = join_env(outs, self.exec_block(handler.body, h_env))
        leave_points = self.try_states.pop()  # body + orelse + handlers
        if self.try_states:  # an enclosing try sees these states too
            self.try_states[-1].extend(leave_points)
        # `finally` runs on normal exit and on every early exit (raise/return/break).
        final_in: Env | None = outs
        for state in leave_points:
            final_in = join_env(final_in, state)
        final = self.exec_block(stmt.finalbody, final_in or dict(env))  # type: ignore[attr-defined]
        if self.try_states and final is not None:
            # An exception propagating out of this try carries the post-`finally` state
            # to the enclosing handler.
            self.try_states[-1].append(dict(final))
        return final if outs is not None else None

    def _assign(self, target: ast.AST, value: Taint, env: Env, value_expr: ast.AST | None):
        if isinstance(target, ast.Name):
            env[target.id] = value
            if value_expr is not None:
                for name in self._mutable_names_in(value_expr, env):
                    self._union(target.id, name)  # alias = parts / x = [parts] / row = rows[0]
        elif isinstance(target, (ast.Tuple, ast.List)):
            for elt in target.elts:  # parts of the value (characters of a string)
                self._assign(elt, item_of(value), env, value_expr)
        elif isinstance(target, ast.Starred):
            self._assign(target.value, value, env, value_expr)  # inside a Tuple/List
        elif isinstance(target, (ast.Attribute, ast.Subscript)):
            base = _root_name(target)
            if base is not None:  # obj.x = v / d[k] = v: weak update of the container
                if isinstance(target, ast.Attribute) or not self.eval(target.value, env).container:
                    # Objects are tracked as a whole (not field by field): that a later read
                    # or method of `obj` returns this value is assumed, not established. A
                    # container's own item store (`d[k] = v`) is modelled.
                    line = getattr(target, "lineno", 0)
                    value = assume(value, f"a store into `{base}` ({self.ctx.path}:{line})")
                self._weak_update(base, value, env)
            if value_expr is not None:  # storing a mutable elsewhere lets it escape
                for name in self._mutable_names_in(value_expr, env):
                    self._weak_update(name, UNKNOWN, env)

    # -- in-order scan: sinks, walrus, mutation and escape -------------------------------

    def _scan(self, node: ast.AST, env: Env) -> None:
        if isinstance(node, (*FUNCTION_TYPES, ast.ClassDef)):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                for part in _header_nodes(node):
                    self._scan(part, env)
            return
        if isinstance(node, COMPREHENSION_TYPES):
            # Only the first iterable runs exactly once, now; the rest runs per item.
            generators = node.generators  # type: ignore[attr-defined]
            for gen in generators:  # `cmd.append(x) for cmd in commands` mutates commands
                for target in ast.walk(gen.target):
                    if isinstance(target, ast.Name):
                        for name in self._mutable_names_in(gen.iter, env):
                            self._union(target.id, name)
            self._scan(generators[0].iter, env)
            if self._mutates_targets(node):
                # An item is mutated in place: the containers it came from change too.
                for gen in generators:
                    for name in self._mutable_names_in(gen.iter, env):
                        self._weak_update(name, UNKNOWN, env)
            for gen in generators:  # `for d[k] in items` stores into d
                for target in ast.walk(gen.target):
                    if isinstance(target, (ast.Subscript, ast.Attribute)):
                        base = _root_name(target)
                        if base is not None:
                            self._weak_update(
                                base, combine((self.eval(gen.iter, env), UNKNOWN)), env
                            )
            rest = [generators[0].target, *generators[0].ifs]
            for gen in generators[1:]:
                rest += [gen.iter, gen.target, *gen.ifs]
            if isinstance(node, ast.DictComp):
                rest += [node.key, node.value]
            else:
                rest.append(node.elt)  # type: ignore[attr-defined]
            if isinstance(node, ast.GeneratorExp):
                # Runs when consumed, possibly after its free names were rebound, so
                # sinks there are never suppressed.
                self.deferred += 1
                try:
                    for part in rest:
                        self._scan(part, env)
                finally:
                    self.deferred -= 1
                return
            # Eager: filters run before the element, and each item sees the mutations of
            # the previous ones; scan to a fixpoint (sink values join over all visits).
            for _ in range(MAX_LOOP_ITERATIONS):
                before = dict(env)
                for part in rest:
                    self._scan(part, env)
                if env == before:
                    break
            else:  # no fixpoint within the budget: stay sound
                for key in list(env):
                    env[key] = combine((env[key], UNKNOWN))
                for part in rest:
                    self._scan(part, env)
            return
        callee = node.func if isinstance(node, ast.Call) else None
        for child in ast.iter_child_nodes(node):
            if child is callee and isinstance(child, ast.Attribute):
                self._scan(child.value, env)  # a method called right away, not extracted
            else:
                self._scan(child, env)
        if isinstance(node, ast.NamedExpr):
            self._assign(node.target, self.eval(node.value, env), env, node.value)
        elif isinstance(node, ast.Call):
            match = self.file.targets.get(id(node))
            if match is not None and match.arg is not None:
                value = self.eval(match.arg, env)
                if _may_choose_shell(node):
                    value = unquote(value)  # fish, csh...: POSIX quoting proves nothing there
                if self.has_walrus or self.deferred:
                    value = combine((value, UNKNOWN))  # never suppressed (see __init__)
                self.file.record(node, value)
            if self.file.call_target(node) is not None:
                self._record_site(node, env)
            self._call_effects(node, env)
        elif (
            isinstance(node, ast.Attribute)
            and isinstance(node.ctx, ast.Load)
            and node.attr not in READONLY_METHODS | STRING_METHODS
        ):
            # `append = parts.append`: a bound method taken off a mutable object can
            # change it later from anywhere.
            for name in self._mutable_names_in(node.value, env):
                self._weak_update(name, UNKNOWN, env)

    def _mutates_targets(self, comp: ast.AST) -> bool:
        """Whether a comprehension may change one of its items in place: a target used
        as a non-read-only method receiver, stored into, or passed to a call that may
        keep or change it (sinks, sanitizers, pure builtins and string methods do not)."""
        targets = {
            t.id
            for gen in comp.generators  # type: ignore[attr-defined]
            for t in ast.walk(gen.target)
            if isinstance(t, ast.Name)
        }
        for node in ast.walk(comp):
            if isinstance(node, ast.Call):
                func = node.func
                if (
                    isinstance(func, ast.Attribute)
                    and func.attr not in READONLY_METHODS | STRING_METHODS
                    and any(  # `[cmd][0].append(x)`, `(cmd if c else d).append(x)`
                        isinstance(n, ast.Name) and n.id in targets for n in ast.walk(func.value)
                    )
                ):
                    return True
                if any(
                    isinstance(n, ast.Name) and n.id in targets
                    for a in _call_args(node)
                    for n in ast.walk(a)  # also `change([cmd])`
                ) and not (
                    id(node) in self.file.targets
                    or self.ctx.call_names(node) & (NON_ESCAPING_CALLS | SANITIZERS.keys())
                    or (isinstance(func, ast.Attribute) and func.attr in STRING_METHODS)
                ):
                    return True
            if (
                isinstance(node, (ast.Subscript, ast.Attribute))
                and isinstance(node.ctx, ast.Store)
                and _root_name(node) in targets
            ):
                return True
        return False

    def _record_site(self, call: ast.Call, env: Env) -> None:
        positional = []
        for arg in call.args:
            if isinstance(arg, ast.Starred):
                break  # later positions are unknown
            positional.append(local_object(self.eval(arg, env)))
        keywords = {
            k.arg: local_object(self.eval(k.value, env)) for k in call.keywords if k.arg is not None
        }
        self.file.record_site(call, positional, keywords)

    def _call_effects(self, call: ast.Call, env: Env) -> None:
        args = _call_args(call)
        func = call.func
        # Mutating method on a mutable receiver: `parts.append(x)`, `d.setdefault(k, x)`.
        if isinstance(func, ast.Attribute) and func.attr not in READONLY_METHODS:
            # The receiver may be any object named in it: `d.get(k).append(x)` mutates d,
            # `(a if c else b).append(x)` mutates a or b.
            receivers = set(self._mutable_names_in(func.value, env))
            base = _root_name(func.value)
            if base is not None and self._lookup(base, func.value, env).mutable:
                receivers.add(base)
            if receivers:
                via = f"the method `{func.attr}` ({self.ctx.path}:{call.lineno})"
                stored = MUTATOR_DATA.get(func.attr)
                if stored is not None and (
                    call.keywords or any(isinstance(a, ast.Starred) for a in call.args)
                ):
                    stored = ()
                value = combine(
                    self.eval(a, env)
                    if stored is None or i in stored
                    else assume(self.eval(a, env), via)
                    for i, a in enumerate(args)
                )
                if (
                    func.attr not in MUTATOR_METHODS
                    or not self.eval(func.value, env).container  # `boxes[0].update(x)`
                    or not all(env[n].container for n in receivers if n in env)
                ):
                    # Only a container's own mutators (`parts.append(x)`) are modelled; any
                    # other method may or may not store its arguments: assumed.
                    value = assume(value, via)
                for name in sorted(receivers):
                    self._weak_update(name, value, env)
        # Mutable arguments escaping into code we do not model may be changed by it.
        names = self.ctx.call_names(call)
        is_string_method = (
            isinstance(func, ast.Attribute)
            and func.attr in STRING_METHODS
            and not self.eval(func.value, env).mutable
        )
        if names & (NON_ESCAPING_CALLS | SANITIZERS.keys()) or is_string_method:
            return
        for arg in args:
            for name in self._mutable_names_in(arg, env):
                self._weak_update(name, UNKNOWN, env)

    # -- aliasing ------------------------------------------------------------------------

    def _group(self, name: str) -> set[str]:
        return self.groups.get(name, {name})

    def _union(self, a: str, b: str) -> None:
        merged = self._group(a) | self._group(b)
        for n in merged:
            self.groups[n] = merged

    def _weak_update(self, name: str, value: Taint, env: Env) -> None:
        # Groups are may-aliases (flow-insensitive): that another name sees the change is
        # assumed, not established.
        alias = assume(value, f"a possible alias of `{name}` ({self.ctx.path})")
        for n in self._group(name):
            if n in env:  # the same object, changed in place: still a container (or not)
                part = value if n == name else alias
                env[n] = replace(combine((env[n], part)), container=env[n].container)

    def _mutable_names_in(self, expr: ast.AST, env: Env) -> list[str]:
        """Local names anywhere in `expr` that may hold a mutable object. Calls are included:
        `dict(cmd=parts)` or `wrap(parts)` may keep a reference to `parts`."""
        out = []
        stack = [expr]
        while stack:
            node = stack.pop()
            if isinstance(node, ast.Name) and node.id in env and env[node.id].mutable:
                out.append(node.id)
            elif not isinstance(node, FUNCTION_TYPES):
                stack.extend(ast.iter_child_nodes(node))
        return out

    # -- expressions -----------------------------------------------------------------------

    def eval(self, node: ast.AST | None, env: Env) -> Taint:
        value = self._eval(node, env)
        if (value.quote_sanitized or value.symbols) and not self._keeps_quoting(node):
            value = self._outside_own_result(node, value, unquote)
        if value.sql_object and not self._keeps_object(node):
            # rendered as Python text, or taken apart
            value = self._outside_own_result(node, value, drop_credit)
        return value

    def _outside_own_result(self, node: ast.AST | None, value: Taint, transform) -> Taint:
        """`transform` for what `node` does to its operands, except to a linked call's own
        result: what the callee does to its arguments is in its summary (`interproc`)."""
        if not isinstance(node, ast.Call):
            return transform(value)
        atom = ("ret", self.ctx.path, node.lineno, node.col_offset)
        own = frozenset(pair for pair in value.symbols if pair[0] == atom)
        if not own:
            return transform(value)
        rest = transform(replace(value, symbols=value.symbols - own))
        return replace(rest, symbols=rest.symbols | own)

    def _keeps_object(self, node: ast.AST | None) -> bool:
        """A SQL object keeps its credit only while it is passed on as is."""
        if isinstance(node, (ast.Name, ast.NamedExpr, ast.IfExp, ast.BoolOp)):
            return True
        return isinstance(node, ast.Call) and bool(
            self._sanitizer_names(node) & SQL_OBJECT_SANITIZERS
        )

    def _join(self, node: ast.Call, sep: Taint, args: list[Taint], env: Env) -> Taint:
        """`sep.join(items)`. Items of a list/tuple display or comprehension are whole
        strings; anything else may be a string, whose items are single characters."""
        arg = node.args[0] if len(node.args) == 1 and not node.keywords else None
        if isinstance(arg, (ast.List, ast.Tuple)) and not any(
            isinstance(e, ast.Starred) for e in arg.elts
        ):
            result = concat([sep, *(self.eval(e, env) for e in arg.elts)])
            first, joiner = (arg.elts[0] if arg.elts else None), node.func.value  # type: ignore[attr-defined]
            if not (isinstance(joiner, ast.Constant) and isinstance(joiner.value, str)):
                return replace(result, program_start=False)  # `sep.join(...)`: unknown text
            # The separator follows the first item only if there is a second one.
            after = joiner.value if len(arg.elts) > 1 else ""
            program = (
                isinstance(first, ast.Constant)
                and isinstance(first.value, str)
                and starts_with_program(first.value + after)
            )
            return replace(result, program_start=program)
        if isinstance(arg, (ast.ListComp, ast.GeneratorExp)):
            # Consumed right here; loop variables are items (see `_comprehension_binding`).
            item = self.eval(arg.elt, env)
            count = combine(self.eval(g.iter, env) for g in arg.generators)
            if known(item) and (any(g.ifs for g in arg.generators) or not known(count)):
                # a constant repeated a number of times chosen at runtime is no constant
                item = combine((item, UNKNOWN))
            # (the text starts with an item, not with the separator)
            return replace(concat([sep, item]), program_start=False)
        result = concat([sep, *(unquote(a) for a in args)])  # characters / unknown items
        return replace(result, program_start=False)

    def _keeps_quoting(self, node: ast.AST | None) -> bool:
        """Quoting credit is context-sensitive, so it survives only expressions that pass a
        quoted string on whole or embed it as is in larger text (whose context `concat`
        checks). Containers, iteration, indexing, other calls... lose it: `str((q,))`
        quotes again, `"".join(q)` or `[c for c in q]` work on single characters."""
        if isinstance(node, (ast.Name, ast.NamedExpr, ast.IfExp, ast.BoolOp, ast.JoinedStr)):
            return True
        if isinstance(node, ast.FormattedValue):
            return True  # conversions and specs are handled in `_eval`
        if isinstance(node, ast.BinOp):
            return isinstance(node.op, (ast.Add, ast.Mod))
        if not isinstance(node, ast.Call):
            return False
        if self._sanitizer_names(node) & QUOTING_SANITIZERS:
            return True
        func = node.func
        # no `*args` / `**kwargs` (their items are unknown); named arguments are fine
        plain_args = not any(isinstance(a, ast.Starred) for a in node.args) and all(
            k.arg is not None for k in node.keywords
        )
        if isinstance(func, ast.Attribute):
            if func.attr == "join":
                return True  # items are checked in `_join`
            return func.attr == "format" and plain_args and plain_template(func.value, printf=False)
        return (
            isinstance(func, ast.Name)
            and not node.keywords
            and plain_args
            and len(node.args) == 1
            and self._sanitizer_names(node) == {"str"}
        )

    def _eval(self, node: ast.AST | None, env: Env) -> Taint:
        if node is None:
            return CONST
        if isinstance(node, ast.Constant):
            return literal(node.value)
        if isinstance(node, ast.Name):
            return self._lookup(node.id, node, env)
        if isinstance(node, ast.Attribute):
            # Any object's attribute, rendered as anything (`str("x".__class__)`); of a
            # sanitized value, maybe its raw data (`uuid.UUID(x).bytes`, `.wrapped`).
            value = drop_credit(self._attribute(node, env))
            return replace(value, shell_plain=False, program_start=False)
        if isinstance(node, ast.Subscript):
            value = self.eval(node.value, env)
            index = self.eval(node.slice, env)
            if (
                value.is_constant
                and not value.symbols
                and not value.container
                and not (index.is_constant and not index.symbols)
            ):
                # Characters of a constant text, chosen at runtime (`"abc"[i]`): no longer a
                # constant. (A container's element is one whole constant value.)
                return combine((unquote(value), UNKNOWN))
            if value.container and not isinstance(node.slice, ast.Slice):
                # One element: maybe a text, whose characters a later index selects.
                return replace(unquote(value), container=False)
            if value.container:
                return unquote(value)  # a slice of the container
            # slicing can strip the quotes; a slice of a text names no known program
            return replace(unquote(value), program_start=False)
        if isinstance(node, ast.Call):
            return self._call(node, env)
        if isinstance(node, ast.Compare) or (
            isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not)
        ):
            return CONST  # booleans cannot carry injection payloads
        if isinstance(node, ast.IfExp):
            return combine((self.eval(node.body, env), self.eval(node.orelse, env)))
        if isinstance(node, ast.NamedExpr):
            return self.eval(node.value, env)
        if isinstance(node, ast.JoinedStr):
            return concat([self.eval(v, env) for v in node.values])
        if isinstance(node, ast.FormattedValue):
            value = self.eval(node.value, env)
            if node.conversion != -1 or node.format_spec is not None:
                # `!r` adds quotes, a spec pads with arbitrary fill characters.
                spec = self.eval(node.format_spec, env) if node.format_spec else CONST
                if node.format_spec is not None and (
                    any(not isinstance(v, ast.Constant) for v in node.format_spec.values)
                    or spec_converts("".join(v.value for v in node.format_spec.values))
                ):
                    value = drop_credit(value)  # `{n:c}`, or a spec only known at runtime
                return formatted(concat([unquote(value), spec]))
            return value
        if isinstance(node, ast.BinOp):
            if (
                isinstance(node.op, ast.Mod)
                and isinstance(node.right, ast.Tuple)
                and not any(isinstance(e, ast.Starred) for e in node.right.elts)
                and plain_template(node.left, printf=True)
            ):
                # `"... %s" % (a, b)`: each item fills one `%s` (an item that is itself a
                # container loses quoting credit in `eval`).
                left = self.eval(node.left, env)
                return concat([left, *(self.eval(e, env) for e in node.right.elts)])
            left, right = self.eval(node.left, env), self.eval(node.right, env)
            if isinstance(node.op, ast.Mod) and (used := _printf_keys(node.left)) is not None:
                right = self._printf_used(node, used, right, env)
            if isinstance(node.op, ast.Mod) and not left.mutable and not left.number:
                # printf formatting: a list/dict operand or a `%r`-like spec changes the text.
                if right.mutable or not plain_template(node.left, printf=True):
                    left, right = unquote(left), unquote(right)  # a quoted value as template
                    if char_conversion(node.left, printf=True):
                        right = drop_credit(right)  # `%c`, or a template only known at runtime
                    return formatted(concat([left, right]))
                return concat([left, right])
            if isinstance(node.op, ast.Add) and not (left.mutable or right.mutable):
                return concat([left, right])  # string building (or arithmetic: harmless)
            return combine((left, right))
        if isinstance(node, COMPREHENSION_TYPES):
            parts = [node.key, node.value] if isinstance(node, ast.DictComp) else [node.elt]
            value = combine(self.eval(p, env) for p in parts)
            if isinstance(node, ast.GeneratorExp):
                # Produced when consumed, possibly after its free names were rebound.
                return combine((value, UNKNOWN))
            return replace(value, mutable=True, shell_plain=False, container=True)  # ['x']
        if isinstance(node, (ast.List, ast.Set, ast.Dict)):
            children = [c for c in ast.iter_child_nodes(node) if isinstance(c, ast.expr)]
            value = combine(self.eval(c, env) for c in children)
            return replace(value, mutable=True, shell_plain=False, container=True)  # ['x']
        if isinstance(node, (ast.Lambda, ast.Yield, ast.YieldFrom)):
            return UNKNOWN
        if isinstance(
            node, (ast.BoolOp, ast.UnaryOp, ast.Tuple, ast.Starred, ast.Await, ast.Slice)
        ):
            children = [c for c in ast.iter_child_nodes(node) if isinstance(c, ast.expr)]
            value = combine(self.eval(c, env) for c in children) if children else CONST
            if isinstance(node, ast.Tuple):  # renders as `('x',)`
                return replace(value, shell_plain=False, container=True)
            return value
        return UNKNOWN

    def _lookup(self, name: str, node: ast.AST, env: Env) -> Taint:
        # A comprehension target shadows any outer binding of the same name.
        comp = self._comprehension_binding(name, node, env)
        if comp is not None:
            return comp
        # Class-body names are invisible inside comprehensions in that body.
        hidden = self.class_body and self.ctx.scopes.scope_of(node).node is not self.scope
        if name in env and not hidden:
            value = env[name]
            if (
                name in self.closure_stores
                or name in self.shared  # `global`/`nonlocal`: any call may rebind it
                or (name in self.closure_loads and value.mutable)
            ):
                return combine((value, UNKNOWN))  # another scope may change it
            return value
        for qualified in self.ctx.scopes.resolve_name(name, node):
            if qualified in knowledge.active().source_names:
                return known_source(
                    knowledge.active().source_names[qualified], node, ("source_name", qualified)
                )
        if (
            not self.is_module
            and name in self.file.module_constants
            and self.file.module_owned(name, node)  # not an enclosing function's local
        ):
            value = self.file.module_constant_values.get(name, CONST)
            # a constant, with its text flag and shape (`FORMULAS[name]` picks a whole value)
            return Taint(
                shell_plain=value.shell_plain,
                container=value.container,
                number=value.number,
                program_start=value.program_start,
            )
        return UNKNOWN

    def _comprehension_binding(self, name: str, node: ast.AST, env: Env) -> Taint | None:
        scope = self.ctx.scopes.scope_of(node)
        while scope is not None and scope.is_comprehension:
            if name in scope.bindings:
                binders = [
                    gen
                    for gen in scope.node.generators  # type: ignore[attr-defined]
                    if any(isinstance(t, ast.Name) and t.id == name for t in ast.walk(gen.target))
                ]
                if len(binders) == 1 and not self._mutates_targets(scope.node):
                    # an item of the iterable (a character of a string), never the whole
                    return item_of(self.eval(binders[0].iter, env))
                return UNKNOWN  # rebound by a later `for`: which one applies depends on order
            scope = scope.parent
        return None

    def _attribute(self, node: ast.Attribute, env: Env) -> Taint:
        for qualified in self.ctx.resolve_all(node):
            flask = flask_request_source(qualified)
            if flask:
                attr = qualified[len("flask.request.") :].split(".", 1)[0]
                return known_source(flask, node, ("flask_request_attr", attr))
            description = knowledge.active().source_names.get(qualified)
            if description:
                return known_source(description, node, ("source_name", qualified))
        base = node.value
        if node.attr in knowledge.active().request_param_attrs and self._is_request_object(base):
            value = source(f"request data (`{self.ctx.segment(node)}`)", node)
            holder = base.id if isinstance(base, ast.Name) else getattr(base, "attr", "")
            if from_note(("request_param_attr", node.attr)) or from_note(
                ("request_param_name", holder)
            ):
                value = replace(value, mutable=True)
            return value
        return self.eval(base, env)

    def _request_data_expr(self, expr: ast.AST) -> bool:
        """Whether `expr`, a method, is the request's own data method (`request.get_json`,
        a named source): an attribute of the request itself, not a method of its data
        (`request.args.render`, an unknown method)."""
        if not isinstance(expr, ast.Attribute):
            return False
        for qualified in self.ctx.resolve_all(expr):
            direct = flask_request_source(qualified) and qualified.count(".") == 2
            if direct or qualified in knowledge.active().source_names:
                return True
        return expr.attr in knowledge.active().request_param_attrs and self._is_request_object(
            expr.value
        )

    def _is_request_object(self, expr: ast.AST) -> bool:
        """`request` parameter, or `self.request` (Django/DRF class-based views)."""
        if isinstance(expr, ast.Name):
            return expr.id in self.request_params
        return (
            isinstance(expr, ast.Attribute)
            and expr.attr in knowledge.active().request_param_names
            and isinstance(expr.value, ast.Name)
            and expr.value.id in {"self", "cls"}
        )

    def _call(self, node: ast.Call, env: Env) -> Taint:
        value = self._call_value(node, env)
        # What a call modelled by its name does (a sanitizer, a builtin, a library model)
        # holds only while scanned code does not replace that name: the flow depends on it.
        modelled = self.ctx.call_names(node) & MODELLED_NAMES
        if modelled:
            # (also where it is called and the name reaching it: `json` of `json.loads(...)`)
            root = node.func
            while isinstance(root, ast.Attribute):
                root = root.value
            site = f"@{self.ctx.path}@{root.id if isinstance(root, ast.Name) else ''}"
            value = _depends(value, frozenset(MODEL + canonical_model(n) + site for n in modelled))
        if self.file.call_target(node) is None:
            return value
        if self._sanitizer_names(node) & (
            knowledge.active().source_names.keys() | SANITIZERS.keys()
        ):
            return value
        # A linkable callee may return untrusted data of its own (resolved by `interproc`).
        return _with_symbol(value, ("ret", self.ctx.path, node.lineno, node.col_offset))

    def _format_arguments(
        self, node: ast.Call, template: ast.AST, args: list[Taint]
    ) -> list[Taint]:
        """`args` of `template.format(...)` with every argument the template does not use
        assumed (all of them when the template is not a literal or `*args`/`**kw` are used)."""
        used = None
        if isinstance(template, ast.Constant) and isinstance(template.value, str):
            used = _format_fields(template.value)
        if used is None:
            return args  # not a literal template
        via = f"the method `format` ({self.ctx.path}:{node.lineno}), unused"
        keys = [k.arg for k in node.keywords]
        if any(isinstance(x, ast.Starred) for x in node.args) or None in keys:
            return [assume(a, via) for a in args]  # which argument is which is unknown
        n_pos = len(node.args)
        return [
            a if (i in used if i < n_pos else keys[i - n_pos] in used) else assume(a, via)
            for i, a in enumerate(args)
        ]

    def _printf_used(self, node: ast.BinOp, used: set[str], right: Taint, env: Env) -> Taint:
        """The right operand of `template % mapping` with the values the template does not use
        assumed (all of it when the template has no conversions: it is returned as is)."""
        via = f"the `%` operator ({self.ctx.path}:{node.lineno}), unused"
        if not used:
            return assume(right, via)
        return self._used_mapping(node.right, used, right, via, env)

    def _used_mapping(self, mapping: ast.AST, used: set, value: Taint, via: str, env: Env) -> Taint:
        """A dict literal argument with the entries a template does not use assumed: unused
        keys, and earlier values of a repeated key (the last one is kept)."""
        if not (
            isinstance(mapping, ast.Dict)
            and all(isinstance(k, ast.Constant) for k in mapping.keys)  # (no `**` entries)
        ):
            return value
        last = {k.value: i for i, k in enumerate(mapping.keys)}  # type: ignore[union-attr]
        parts = [
            self.eval(v, env)
            if k.value in used and last[k.value] == i  # type: ignore[union-attr]
            else assume(self.eval(v, env), via)
            for i, (k, v) in enumerate(zip(mapping.keys, mapping.values, strict=True))
        ]
        return replace(combine(parts), mutable=True, shell_plain=False, container=True)

    def _sanitizer_names(self, node: ast.Call) -> frozenset[str]:
        """Resolved names of a callee that cannot be a reassignment instead (see
        `_FileEngine.stable_callee`): `int = lambda s: s` after the import gets no credit."""
        if not self.file.stable_callee(node):
            return frozenset()
        names = self.ctx.call_names(node)
        if self.file.namespace_exposed:
            # `exec`/`globals()` may rebind any module name; keep only plain sanitizers
            # (as before), not the context-sensitive quoting helpers.
            names = names - QUOTING_SANITIZERS
        return names

    def _call_value(self, node: ast.Call, env: Env) -> Taint:
        names = self.ctx.call_names(node)
        # `builtins.str(x)` is `str(x)` (a builtin model, not a method of a module)
        names = names | {n[len("builtins.") :] for n in names if n.startswith("builtins.")}
        args = [self.eval(a, env) for a in _call_args(node)]
        for qualified in names:
            if qualified in knowledge.active().source_names:
                return known_source(
                    knowledge.active().source_names[qualified], node, ("source_name", qualified)
                )
        safe: set[str] = set()
        quoting = obj = numeric = False
        only_numeric = True
        for qualified in self._sanitizer_names(node):
            safe |= SANITIZERS.get(qualified, frozenset())
            quoting = quoting or qualified in QUOTING_SANITIZERS
            obj = obj or qualified in SQL_OBJECT_SANITIZERS
            numeric = numeric or qualified in NUMERIC_SANITIZERS
            if qualified in SANITIZERS and qualified not in NUMERIC_SANITIZERS:
                only_numeric = False
        if safe:
            value = combine(args) if args else CONST
            # Per dependency: shell-quoting credit is its own mark (see `concat`, `unquote`).
            credit = frozenset(
                digits(c) if only_numeric else quoted(c) if quoting and c == CMDI else c
                for c in safe
            )
            return Taint(
                frozenset(replace(s, safe=s.safe | credit) for s in value.sources),
                value.unknown,
                frozenset(value.safe_for | safe),
                mutable=False,
                shell_plain=True if quoting else value.shell_plain,
                quote_sanitized=quoting or value.quote_sanitized,
                symbols=frozenset((a, s | credit) for a, s in value.symbols),
                sql_object=obj,
                number=numeric and not quoting and not obj,
                program_start=quoting and _joined_program(node),
            )
        modelled = [PRESERVING_FUNCTIONS[n] for n in sorted(names) if n in PRESERVING_FUNCTIONS]
        if (
            modelled
            and self.file.stable_callee(node)
            and not self.file.replaces_model(names)
            and not _replaces_result(node, names)
        ):
            # Modelled library calls (not replaced in this file, by name or through a
            # namespace: `json.__dict__`, `globals()`): the result carries the data
            # arguments' data (established); any other argument (an option, a callback) may
            # still flow on, assumed. No sanitizer credit.
            via = f"`{min(names)}` ({self.ctx.path}:{node.lineno}) beyond its data arguments"
            # (the flow depends on the models: `MODEL` marks, added in `_call`)
            value = combine((UNKNOWN, *_data_arguments(node, args, modelled, via)))
            # A number's text stays digits through them (not through a binary decoder).
            keep = frozenset() if names & DIGIT_BREAKING else DIGIT_MARKS
            return drop_credit(value, keep)
        func = node.func
        if isinstance(func, ast.Attribute) and not names & BUILTIN_CALLS:
            # Methods derive their result from the receiver and arguments
            # (`request.args.get("q")`, `" ".join(parts)`, `template.format(x)`).
            receiver = self._attribute(func, env)
            if receiver.mutable and func.attr in TEMPLATE_METHODS | STRING_METHODS:
                # Not known to be text (`Box().replace(...)`, a parameter): any method. What
                # it is called with is assumed; the receiver keeps its own certainty (an
                # object never carries established data, see `_assign`).
                via = f"the method `{func.attr}` ({self.ctx.path}:{node.lineno})"
                value = drop_credit(combine((receiver, *[assume(a, via) for a in args])))
                return replace(value, shell_plain=False, number=False, program_start=False)
            if func.attr in TEMPLATE_METHODS:
                if func.attr == "format":
                    # Only the fields a literal template names reach the result, whatever their
                    # conversions: `'{0!r}'.format(a, b)` drops b.
                    args = self._format_arguments(node, func.value, args)
                elif (
                    func.attr == "format_map"
                    and isinstance(func.value, ast.Constant)
                    and isinstance(func.value.value, str)
                    and (used := _format_fields(func.value.value)) is not None
                    and len(node.args) == 1
                    and not node.keywords
                ):
                    # only the entries the template names reach the result
                    via = f"the method `format_map` ({self.ctx.path}:{node.lineno}), unused"
                    if not used:
                        args = [assume(a, via) for a in args]
                    else:
                        args = [self._used_mapping(node.args[0], used, args[0], via, env)]
                if func.attr != "join" and not plain_template(func.value, printf=False):
                    # `{!r}`, `{:>9}`, or an unknown template (maybe a quoted value itself)
                    receiver, args = unquote(receiver), [unquote(a) for a in args]
                    if char_conversion(func.value, printf=False):
                        args = [drop_credit(a) for a in args]  # `{:c}`, or an unknown template
                    return formatted(concat([receiver, *args]))
                if func.attr == "join":
                    return self._join(node, receiver, args, env)
                # The template's text without its fields (a field breaks a word: `ec{}ho`).
                pieces = list(string.Formatter().parse(func.value.value))  # type: ignore[attr-defined]
                text = literal("\0".join(lit for lit, *_ in pieces))
                flags = {"shell_plain": text.shell_plain, "program_start": text.program_start}
                return concat([replace(receiver, **flags), *args])
            if func.attr in STRING_METHODS:
                # Only some arguments become part of the result (`replace(old, new)`: `new`;
                # `strip(chars)`: none): the others select or measure, so their flow is assumed.
                via = f"the method `{func.attr}` ({self.ctx.path}:{node.lineno})"
                stored = STRING_DATA_ARGS.get(func.attr, ())
                parts = [
                    a if _plain_position(node, i) and i in stored else assume(a, via)
                    for i, a in enumerate(args)
                ]
                value = replace(combine((receiver, *parts)), mutable=False)
                if func.attr == "encode":  # bytes render as b'...' (credit: see `eval`)
                    value = replace(value, shell_plain=False)
                    # a codec may rewrite characters (`encode("unicode_escape")`)
                    return value if not node.args and not node.keywords else drop_credit(value)
                # (decode: every bytes value is already not shell_plain, see `literal`)
                value = replace(unquote(value), number=False, program_start=False)
                return value if func.attr in CREDIT_KEEPING_METHODS else drop_credit(value)
            # Any other method: any value (a list renders with quotes), any characters. Only
            # element access (`.get`, `.getlist`, ...) and the request's own data methods
            # (`request.get_json()`) are modelled; through any other method the flow is assumed.
            via = f"the method `{func.attr}` ({self.ctx.path}:{node.lineno})"
            if self._request_data_expr(func) and not receiver.mutable:
                # `request.get_json()`: the request object's own data method (built in: an
                # attribute that only a project note names may be any object, see `known_source`)
                value = combine((receiver, *[assume(a, via) for a in args]))
            elif func.attr in ACCESSOR_METHODS | CONVERSION_METHODS | DEFAULT_ACCESSORS:
                # Element access and builtin conversions return (an encoding of) the receiver's
                # data, with the receiver's own certainty: an object never carries established
                # data (stores into it are assumed, see `_assign`); a default
                # (`.get(key, default)`) is returned as is.
                modelled_receiver = receiver.container or (
                    bool(receiver.sources) and not receiver.mutable
                )  # a container, or untrusted data itself (not an arbitrary object's `get`)
                defaults = {1} if func.attr in DEFAULT_ACCESSORS and modelled_receiver else set()
                value = combine(
                    (
                        receiver,
                        *[
                            a if i in defaults and _plain_position(node, i) else assume(a, via)
                            for i, a in enumerate(args)
                        ],
                    )
                )
            elif func.attr in READ_METHODS and receiver.sources and not receiver.mutable:
                # `sys.stdin.read()`, `request.stream.read()`, `request.files[k].read()`: the
                # input itself (not a file a tainted name opens: that receiver is an object)
                value = combine((receiver, *[assume(a, via) for a in args]))
            elif func.attr == "__iadd__" and receiver.container:
                value = combine((receiver, *args))  # the container itself, extended
            else:
                value = combine((assume(receiver, via), *[assume(a, via) for a in args]))
            value = drop_credit(unquote(value))
            return replace(value, shell_plain=False, number=False, program_start=False)
        if self._sanitizer_names(node) & NUMERIC_PASSTHROUGH:
            # The argument's own credit, if any (`abs(int(x))`), not a new one.
            value = combine(args) if args else CONST
            return replace(value, mutable=False, number=bool(args) and args[0].number)
        if names & (MUTABLE_BUILTINS | PURE_BUILTINS) and not (
            self.file.stable_callee(node) and not self.file.replaces_model(names)
        ):
            names = names - MUTABLE_BUILTINS - PURE_BUILTINS  # rebound here: any function
        roles = _builtin_roles(names)
        if roles is not None and names & (MUTABLE_BUILTINS | PURE_BUILTINS):
            # `str(b, codec)`, `sorted(xs, key=f)`: only the data argument is the result's data.
            via = f"`{min(names)}` ({self.ctx.path}:{node.lineno}) beyond its data argument"
            keys = _builtin_data_keywords(names)
            n_pos = len(node.args)
            args = [
                a
                if (_plain_position(node, i) and i in roles)
                or (i >= n_pos and node.keywords[i - n_pos].arg in keys)
                else assume(a, via)
                for i, a in enumerate(args)
            ]
        if names & MUTABLE_BUILTINS:
            value = combine(args) if args else CONST
            if names & CHAR_BUILTINS:
                value = drop_credit(value)  # bytearray: bytes, not a container of elements
                return replace(value, mutable=True, shell_plain=False)
            return replace(value, mutable=True, shell_plain=False, container=True)
        if names & PURE_BUILTINS:
            value = combine(args) if args else CONST
            if names & CHAR_BUILTINS:
                value = drop_credit(value)
            if names & STR_BUILTINS:  # a new string: not the (maybe mutable) argument
                value = replace(value, mutable=False)
            if names == {"str"}:
                # A string as is. Values that render with quotes (bytes, containers) are
                # already not shell_plain; str(b, encoding) decodes bytes, likewise.
                return replace(value, container=False)  # text, even of a container
            # repr()/ascii() add quotes, format() pads, tuple()/sorted() add brackets.
            value = replace(unquote(value), shell_plain=False, number=False, program_start=False)
            return replace(value, container=bool(names & CONTAINER_BUILTINS))
        # Unknown function: taint may flow through (assumed), and the result is not provably
        # constant (modelled library calls are handled above).
        callee = min(names) if names else ast.unparse(node.func)[:60]
        via = f"`{callee}` ({self.ctx.path}:{node.lineno})"
        return combine((UNKNOWN, *[assume(a, via) for a in args]))


# -- helpers ------------------------------------------------------------------------------


def _may_choose_shell(call: ast.Call) -> bool:
    """Whether a sink call may name the shell that runs its command instead of `/bin/sh`:
    `executable=`, `Popen`'s third positional parameter, or arguments passed in bulk."""
    return (
        len(call.args) > 2
        or any(isinstance(a, ast.Starred) for a in call.args)
        or any(k.arg is None or k.arg == "executable" for k in call.keywords)
    )


def _joined_program(node: ast.Call) -> bool:
    """`shlex.join([...])` whose program (first item) is a literal on the inert list and
    followed by another item, so the separating space completes it (`shlex.join(["ls"])`
    ends right after the name, as may `["ls", *rest]`: text appended next extends it);
    `shlex.quote(x)` itself is a single word: in the program position it is the program."""
    if not (isinstance(node.func, (ast.Name, ast.Attribute)) and len(node.args) == 1):
        return False
    name = node.func.attr if isinstance(node.func, ast.Attribute) else node.func.id
    arg = node.args[0]
    if name != "join" or not isinstance(arg, (ast.List, ast.Tuple)) or len(arg.elts) < 2:
        return False
    if any(isinstance(e, ast.Starred) for e in arg.elts):
        return False
    first = arg.elts[0]
    return (  # the whole item: `shlex.join` keeps `"ls x"` one (unlisted) program name
        isinstance(first, ast.Constant)
        and isinstance(first.value, str)
        and inert_program(first.value)
    )


# Options of a modelled function that can replace what it returns (a custom decoder, a hook).
RESULT_OPTIONS = {
    "json.loads": frozenset(
        {"cls", "object_hook", "object_pairs_hook", "parse_float", "parse_int", "parse_constant"}
    ),
}


def _replaces_result(node: ast.Call, names: frozenset[str]) -> bool:
    """Whether the call may run code of the caller's choosing that produces its result: a
    result option (`json.loads(s, cls=...)`), `**kw`, or a replacement for `re.sub` that is not
    a literal string (a function computes the replacement)."""
    keys = {k.arg for k in node.keywords}
    if None in keys and names & (RESULT_OPTIONS.keys() | {"re.sub", "re.subn"}):
        return True
    if any(keys & RESULT_OPTIONS[n] or len(node.args) > 1 for n in names if n in RESULT_OPTIONS):
        return True
    if names & {"re.sub", "re.subn"}:
        repl = (
            node.args[1]
            if len(node.args) > 1
            else next((k.value for k in node.keywords if k.arg == "repl"), None)
        )
        return not (isinstance(repl, ast.Constant) and isinstance(repl.value, (str, bytes)))
    return False


def _data_arguments(
    node: ast.Call, args: list[Taint], models: list[tuple], via: str
) -> list[Taint]:
    """`args` (positional, then keyword values) with every non-data argument assumed. A
    position at or after a `*args` is uncertain, so it is not a data argument either."""
    positions: set[int] | None = set()
    keywords: set[str] = set()
    for model_positions, model_keywords in models:
        positions = (
            None
            if positions is None or model_positions is None
            else positions | set(model_positions)
        )
        keywords |= set(model_keywords)
    out = []
    starred = False
    for index, value in enumerate(args):
        if index < len(node.args):
            starred = starred or isinstance(node.args[index], ast.Starred)
            # (after a `*args` the position is unknown: data only if every position is)
            data = positions is None or (not starred and index in positions)
        else:
            data = node.keywords[index - len(node.args)].arg in keywords
        out.append(value if data else assume(value, via))
    return out


def _depends(value: Taint, tokens: frozenset[str]) -> Taint:
    """`value` with its flow depending on the library models `tokens` (`MODEL` marks)."""
    if not tokens or (not value.sources and not value.symbols):
        return value
    return replace(
        value,
        sources=frozenset(replace(s, safe=s.safe | tokens) for s in value.sources),
        symbols=frozenset((a, join_marks(s, tokens)) for a, s in value.symbols),
    )


# Functions that write an object's attribute by name, or read a namespace mapping.
WRITE_HELPERS = frozenset({"setattr", "delattr"})
NAMESPACE_GETTERS = frozenset({"globals", "vars", "locals"})
IMPORT_HELPERS = frozenset({"importlib.import_module", "__import__"})
# Attributes of a module that only read it.
READ_DUNDERS = frozenset(
    {
        "__name__",
        "__file__",
        "__doc__",
        "__version__",
        "__path__",
        "__spec__",
        "__package__",
        "__all__",
    }
)
# Attributes that only describe an object (setting them does not change what it does).
DOC_DUNDERS = frozenset(
    {"__doc__", "__annotations__", "__name__", "__qualname__", "__module__", "__wrapped__"}
)
# Methods of `sys.modules` that hand out a module.
MODULE_LOOKUPS = frozenset({"get", "__getitem__", "pop", "setdefault"})
# Methods of a mapping that only look a name up or test for it (`.copy()`, `.items()`,
# `.values()` hand out what it holds).
MAPPING_READERS = frozenset({"get", "__getitem__", "keys", "__contains__"})
# Attributes of a function or object that change what it does when called.
BEHAVIOUR_DUNDERS = frozenset(
    {"__code__", "__defaults__", "__kwdefaults__", "__dict__", "__class__", "__call__"}
)


def _replaced_names(
    tree: ast.Module, symbols: dict[str, tuple[str, str]], rel_path: str
) -> frozenset[tuple[str, int]]:
    """What this file may replace in other modules (or its own), each with the line of its
    first write. A name: an attribute assigned or deleted on any object but a method's own
    instance (`helpers.ident = ...`), or set by name (`setattr(x, "ident", f)`). A module
    (`module:<dotted>`, or `module:*` for any): one whose object escapes, i.e. is used other
    than by reading or calling one of its attributes (`m = json`, `vars(json)`,
    `json.__dict__`, `f(json)`, `sys.modules[...] = ...`), and this file's own module when its
    namespace mapping (`globals()`, `vars()`) is used other than for reading."""
    own_module = module_name(rel_path)
    lines: dict[str, int] = {}

    def add(entry: str, at: ast.AST) -> None:
        lines.setdefault(entry, getattr(at, "lineno", 0))

    parents: dict[int, ast.AST] = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parents[id(child)] = node
    bound: dict[str, set[str]] = {"__builtins__": {"builtins"}}  # names bound to imports
    for name, (kind, target) in symbols.items():
        if kind == "import":
            bound.setdefault(name, set()).add(target)
    for node in ast.walk(tree):  # at any depth (`def f(): from . import helpers`)
        if isinstance(node, ast.Import):
            for a in node.names:
                top = a.name.split(".")[0]
                bound.setdefault(a.asname or top, set()).add(a.name if a.asname else top)
        elif isinstance(node, ast.ImportFrom):
            base = _import_base(node, rel_path, own_module)
            for a in node.names:
                if base and a.name != "*":
                    bound.setdefault(a.asname or a.name, set()).add(f"{base}.{a.name}")

    aliases: dict[str, set[str]] = {}  # `g = globals`: g -> {globals}

    def callee(expr: ast.AST) -> set[str]:
        """The builtin or library function names `expr` may denote (`builtins.` dropped)."""
        if isinstance(expr, ast.Name):
            names = (bound.get(expr.id) or {expr.id}) | aliases.get(expr.id, set())
        elif isinstance(expr, ast.Attribute):
            names = {f"{m}.{expr.attr}" for m in modules(expr.value)}
        else:
            return set()
        return {n[len("builtins.") :] if n.startswith("builtins.") else n for n in names}

    memo: dict[int, set[str]] = {}

    def modules(expr: ast.AST) -> set[str]:
        """The modules (or module attributes) `expr` may be."""
        if id(expr) in memo:
            return memo[id(expr)]
        out: set[str] = set()
        if isinstance(expr, ast.Name):
            out = set(bound.get(expr.id, ()))
        elif isinstance(expr, ast.Attribute) and not expr.attr.startswith("__"):
            out = {"*" if m == "*" else f"{m}.{expr.attr}" for m in modules(expr.value)}
        elif isinstance(expr, ast.Subscript) and "sys.modules" in modules(expr.value):
            key = expr.slice
            literal_key = isinstance(key, ast.Constant) and isinstance(key.value, str)
            out = {key.value} if literal_key else {"*"}  # type: ignore[union-attr]
        elif (key := _namespace_lookup(expr, callee)) is not None:
            # `globals()['json']`, `vars().get('json')`: what this module binds to that name
            out = set(bound.get(key, ())) if key else {"*"}
        elif (
            isinstance(expr, ast.Call)
            and isinstance(expr.func, ast.Attribute)
            and expr.func.attr in MODULE_LOOKUPS
            and "sys.modules" in modules(expr.func.value)
        ):
            key = expr.args[0] if expr.args else None  # `sys.modules.get("json")`
            literal_key = isinstance(key, ast.Constant) and isinstance(key.value, str)
            out = {key.value} if literal_key else {"*"}  # type: ignore[union-attr]
        elif isinstance(expr, ast.Call) and callee(expr.func) & IMPORT_HELPERS:
            out = _imported_names(expr, callee(expr.func)) or {"*"}
        memo[id(expr)] = out
        return out

    helpers = NAMESPACE_GETTERS | WRITE_HELPERS | IMPORT_HELPERS
    assigned = [
        (node.value, node.targets if isinstance(node, ast.Assign) else [node.target])
        for node in ast.walk(tree)
        if isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr)) and node.value is not None
    ]
    changed = True
    while changed:  # names bound to a helper function, through other such names too
        changed = False
        for value, targets in assigned:
            found = (
                callee(value) & helpers if isinstance(value, (ast.Name, ast.Attribute)) else set()
            )
            for target in targets:
                if found and isinstance(target, ast.Name):
                    before = aliases.get(target.id, set())
                    if not found <= before:
                        aliases[target.id] = before | found
                        changed = True
    memo.clear()
    instance = _instance_stores(tree)
    # names this module binds itself (not imports): its own functions, classes and values
    local = {n for stmt in tree.body for n in _bound_names(stmt)} | {
        n for stmt in tree.body for t in getattr(stmt, "targets", []) for n in _target_names(t)
    }
    local -= set(bound)
    for node in ast.walk(tree):
        parent = parents.get(id(node))
        if (
            isinstance(node, ast.Attribute)
            and isinstance(node.ctx, (ast.Store, ast.Del))
            and id(node) not in instance  # `self.path = ...` sets the instance's own attribute
        ):
            add(node.attr, node)
            for module in sorted(modules(node.value)):  # `app.json = ...`
                add(f"attr:{module}.{node.attr}", node)
            if node.attr in BEHAVIOUR_DUNDERS:  # `ident.__code__ = ...`: `ident` itself changes
                for entry in _changed_callable(node.value, modules, local):
                    add(entry, node)
        if isinstance(node, ast.Call):
            helpers = callee(node.func)
            if helpers & WRITE_HELPERS and len(node.args) >= 2:
                name = node.args[1]
                if isinstance(name, ast.Constant) and isinstance(name.value, str):
                    add(name.value, node)  # (a computed name: its object escapes, below)
                    if name.value in BEHAVIOUR_DUNDERS:  # `setattr(f, "__code__", g)`
                        for entry in _changed_callable(node.args[0], modules, local):
                            add(entry, node)
        # A helper used as a value other than by a name bound to it (`ops = [setattr]`,
        # `f(globals)`): where it is called is unknown. A write or import helper may write any
        # module; a namespace getter may write this module's names, or any module it imports.
        if isinstance(node, (ast.Name, ast.Attribute)) and isinstance(node.ctx, ast.Load):
            helpers = callee(node)
            called = isinstance(parent, ast.Call) and parent.func is node
            aliased = isinstance(parent, (ast.Assign, ast.AnnAssign, ast.NamedExpr)) and all(
                isinstance(target, ast.Name)
                for target in (
                    parent.targets if isinstance(parent, ast.Assign) else [parent.target]
                )
            )  # `g = globals`: followed (`aliases`)
            if not (called or aliased):
                if helpers & (WRITE_HELPERS | IMPORT_HELPERS):
                    add("module:*", node)
                if helpers & NAMESPACE_GETTERS:
                    add(f"module:{own_module}", node)
                    for module in sorted(set().union(*bound.values()) - {"builtins"}):
                        add(f"module:{module}", node)
        # This module's namespace used other than for reading (`globals()[k] = v`, `|=`).
        if (
            isinstance(node, ast.Call)
            and callee(node.func) & NAMESPACE_GETTERS
            and not (node.args or node.keywords)
            and not _only_read(node, parents)
        ):
            add(f"module:{own_module}", node)  # (also `globals().copy()`: what it holds)
            for module in sorted(set().union(*bound.values()) - {"builtins"}):
                add(f"module:{module}", node)
        # A function's globals of unknown origin (`fn.__globals__`): any module's namespace.
        if (
            isinstance(node, ast.Attribute)
            and node.attr == "__globals__"
            and not modules(node.value)
            and not _only_read(node, parents)
        ):
            add("module:*", node)
        # A module object that escapes.
        found = modules(node) if isinstance(node, ast.expr) else set()
        if not found:
            continue
        if "sys.modules" in found:
            looked_up = isinstance(parent, ast.Subscript) and parent.value is node
            if _changes_mapping(node, parents):  # `sys.modules[name] = m`, `.update(...)`
                key = parent.slice if looked_up else None  # type: ignore[union-attr]
                literal = isinstance(key, ast.Constant) and isinstance(key.value, str)
                add(f"module:{key.value}" if literal else "module:*", node)  # type: ignore[union-attr]
            elif not (
                looked_up  # a lookup is a module expression of its own (`modules`)
                or isinstance(parent, ast.Compare)
                or (
                    isinstance(parent, ast.Attribute)
                    and parent.value is node
                    and parent.attr in MODULE_LOOKUPS | {"keys", "__contains__"}
                )
            ):
                add("module:*", node)  # `mods = sys.modules`, `.copy()`: may reach any module
            continue
        if "*" in found:
            # A module whose name is computed (`import_module(name)`, a plugin): written here
            # (`.__dict__`, `vars(...)`, `setattr(..., name, ...)`), it may be any module.
            # (Handing it to other code is not followed: see `module:` entries below.)
            writes = (
                isinstance(parent, ast.Attribute)
                and parent.value is node
                and parent.attr.startswith("__")
                and parent.attr not in READ_DUNDERS
            ) or (
                isinstance(parent, ast.Call)
                and node in parent.args
                and bool(callee(parent.func) & (WRITE_HELPERS | {"vars"}))
            )
            if writes:
                add("module:*", node)
            found = found - {"*"}
            if not found:
                continue
        if _module_use_reads(node, parent, modules):
            continue
        if isinstance(parent, ast.Attribute) and parent.attr == "__globals__":
            if _only_read(parent, parents):
                continue  # `fn.__globals__.keys()`, `fn.__globals__[k]`: read
            # `json.loads.__globals__`: the namespace of the module that defines the function
            # (found through re-exports by `interproc`)
            for function in sorted(found):
                add(f"globals:{function}", node)
            continue
        for module in sorted(found):
            add(f"module:{module}", node)
    return frozenset(lines.items())


def _namespace_lookup(expr: ast.AST, callee) -> str | None:
    """For a lookup in this module's namespace (`globals()[k]`, `vars().get(k)`): the literal
    key, or "" when it is computed; None for anything else."""
    if isinstance(expr, ast.Subscript) and isinstance(expr.ctx, ast.Load):
        mapping, key = expr.value, expr.slice
    elif (
        isinstance(expr, ast.Call)
        and isinstance(expr.func, ast.Attribute)
        and expr.func.attr in MODULE_LOOKUPS
    ):
        mapping, key = expr.func.value, (expr.args[0] if expr.args else None)
    else:
        return None
    if not (
        isinstance(mapping, ast.Call)
        and callee(mapping.func) & NAMESPACE_GETTERS
        and not (mapping.args or mapping.keywords)
    ):
        return None
    return key.value if isinstance(key, ast.Constant) and isinstance(key.value, str) else ""


def _imported_names(call: ast.Call, helpers: set[str]) -> set[str]:
    """The modules a literal `import_module(name, package)` / `__import__(name, ...)` call
    returns (relative names resolved against a literal package; `__import__('a.b')` returns
    `a` unless its `fromlist` is non-empty), or none when that is not known."""
    name = _imported_name(call, helpers)
    if name is None or "__import__" not in helpers or "." not in name:
        return {name} if name else set()
    fromlist = call.args[3] if len(call.args) > 3 else None
    fromlist = next((k.value for k in call.keywords if k.arg == "fromlist"), fromlist)
    top = name.split(".")[0]
    if fromlist is None or (isinstance(fromlist, (ast.List, ast.Tuple)) and not fromlist.elts):
        return {top}
    if isinstance(fromlist, (ast.List, ast.Tuple)):
        return {name}
    return {top, name}  # a fromlist of unknown value


def _imported_name(call: ast.Call, helpers: set[str]) -> str | None:
    """The module name a literal import call asks for (relative names resolved against a
    literal package), or None when it is not literal."""

    def literal(node: ast.AST | None) -> str | None:
        return (
            node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None
        )

    name = literal(call.args[0] if call.args else None)
    if name is None:
        return None
    if "__import__" in helpers:
        level = call.args[4] if len(call.args) > 4 else None
        level = next((k.value for k in call.keywords if k.arg == "level"), level)
        if level is not None and not (isinstance(level, ast.Constant) and level.value == 0):
            return None  # a relative `__import__`
        return name
    if not name.startswith("."):
        return name
    package = literal(call.args[1] if len(call.args) > 1 else None)
    package = package or literal(next((k.value for k in call.keywords if k.arg == "package"), None))
    if not package:
        return None
    dots = len(name) - len(name.lstrip("."))
    base = package.split(".")
    if dots - 1 > len(base) - 1:
        return None
    base = base[: len(base) - (dots - 1)]
    rest = name[dots:]
    return ".".join([*base, rest] if rest else base)


def _changed_callable(target: ast.AST, modules, local: set[str]) -> list[str]:
    """Replacement entries for an object whose behaviour is changed in place (`__code__`):
    a module's function by its name (`helpers.ident`, `from helpers import ident`); an object
    this module defines (`Schema.__new__`) by its names; anything else (a parameter) may be any
    function (`module:*`)."""
    found = modules(target)
    if found and "*" not in found:
        return sorted({m.rsplit(".", 1)[-1] for m in found} | {f"module:{m}" for m in found})
    names = []
    root = target
    while isinstance(root, ast.Attribute):
        names.append(root.attr)
        root = root.value
    if isinstance(root, ast.Name) and root.id in local:
        return sorted({root.id, *names})
    return ["module:*"]


def _module_use_reads(node: ast.AST, parent: ast.AST | None, modules) -> bool:
    """Whether a module expression only reads or calls one of its attributes here."""
    if isinstance(parent, ast.Attribute) and parent.value is node:
        return (
            not parent.attr.startswith("__")
            or parent.attr in DOC_DUNDERS  # `json.__doc__ = ...`: metadata only
            or (parent.attr in READ_DUNDERS and isinstance(parent.ctx, ast.Load))
        )
    if isinstance(parent, ast.Call) and parent.func is node:
        return True
    if isinstance(parent, ast.Subscript) and parent.value is node:
        return "sys.modules" in modules(node) and isinstance(parent.ctx, ast.Load)
    return False


def _only_read(node: ast.AST, parents: dict[int, ast.AST]) -> bool:
    """Whether a namespace mapping (`globals()`) is only read where it is used."""
    parent = parents.get(id(node))
    if isinstance(parent, ast.Subscript) and parent.value is node:
        return isinstance(parent.ctx, ast.Load)  # (`globals()[k] += v` stores)
    if isinstance(parent, ast.Attribute) and parent.value is node:
        return parent.attr in MAPPING_READERS
    return isinstance(parent, ast.Compare)  # `name in globals()`


def _changes_mapping(node: ast.AST, parents: dict[int, ast.AST]) -> bool:
    """`node` (a mapping) stored into, deleted from or changed by a method here."""
    parent = parents.get(id(node))
    if isinstance(parent, ast.Subscript) and parent.value is node:
        return isinstance(parent.ctx, (ast.Store, ast.Del))  # (also `m[k] += v`)
    if isinstance(parent, ast.Attribute) and parent.value is node:
        return parent.attr in MAPPING_WRITERS
    return isinstance(parent, ast.AugAssign) and parent.target is node


def _instance_stores(tree: ast.Module) -> set[int]:
    """Attribute stores on a method's own instance or class (`self.x = ...`): the first
    parameter of a function defined directly in a class body, not a static method, and never
    bound again anywhere inside it (nested functions, defaults and `nonlocal` included)."""
    out: set[int] = set()
    for cls in ast.walk(tree):
        if not isinstance(cls, ast.ClassDef):
            continue
        for method in cls.body:
            if not isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            params = [*method.args.posonlyargs, *method.args.args]
            static = any(
                (isinstance(d, ast.Name) and d.id == "staticmethod")
                or (isinstance(d, ast.Attribute) and d.attr == "staticmethod")
                for d in method.decorator_list
            )
            if not params or static:
                continue
            first = params[0].arg
            inner = [n for n in ast.walk(method) if n is not method]
            rebound = any(
                first in _bound_names(n)
                or (isinstance(n, ast.arg) and n is not params[0] and n.arg == first)
                for n in inner
            )
            if rebound:
                continue  # `self = json`, or a nested scope's own `self`
            for node in inner:
                if (
                    isinstance(node, ast.Attribute)
                    and isinstance(node.ctx, (ast.Store, ast.Del))
                    and isinstance(node.value, ast.Name)
                    and node.value.id == first
                ):
                    out.add(id(node))
    return out


def _target_names(target: ast.AST) -> set[str]:
    """The names an assignment target binds (`a, (b, *c) = ...`)."""
    return {n.id for n in ast.walk(target) if isinstance(n, ast.Name)}


def _bound_names(node: ast.AST) -> set[str]:
    """Names `node` binds (or declares global/nonlocal): stores, imports, definitions,
    `except ... as`, match captures."""
    if isinstance(node, ast.Name) and not isinstance(node.ctx, ast.Load):
        return {node.id}
    if isinstance(node, (ast.Global, ast.Nonlocal)):
        return set(node.names)
    if isinstance(node, ast.alias):
        return {node.asname or node.name.split(".")[0]}
    if isinstance(node, (*FUNCTION_TYPES, ast.ClassDef)) and hasattr(node, "name"):
        return {node.name}  # type: ignore[attr-defined]
    if isinstance(node, ast.ExceptHandler) and node.name:
        return {node.name}
    name = getattr(node, "name", None) if type(node).__name__ in {"MatchAs", "MatchStar"} else None
    rest = getattr(node, "rest", None) if type(node).__name__ == "MatchMapping" else None
    return {n for n in (name, rest) if n}


def _own_scope_nodes(func: ast.AST):
    """The nodes of `func`'s body that run in its own scope (not nested functions/classes)."""
    stack = list(getattr(func, "body", []))
    while stack:
        node = stack.pop()
        yield node
        if isinstance(node, (*FUNCTION_TYPES, ast.ClassDef)):
            continue
        stack.extend(ast.iter_child_nodes(node))


def _printf_keys(template: ast.AST) -> set[str] | None:
    """The mapping keys a literal printf template uses (`%(name)s`; a key may hold balanced
    parentheses, as Python parses it), or None when it has a positional conversion (`%s`:
    every operand is used), does not parse, or is not a literal."""
    if not (isinstance(template, ast.Constant) and isinstance(template.value, (str, bytes))):
        return None
    raw = template.value
    text = raw.decode("latin-1") if isinstance(raw, bytes) else raw  # bytes keys are bytes
    keys: set = set()
    i = 0
    while i < len(text):
        if text[i] != "%":
            i += 1
            continue
        i += 1
        if i < len(text) and text[i] == "%":
            i += 1
            continue
        if i >= len(text) or text[i] != "(":
            return None  # a positional conversion (or a truncated one)
        depth, start = 1, i + 1
        i += 1
        while i < len(text) and depth:
            depth += {"(": 1, ")": -1}.get(text[i], 0)
            i += 1
        if depth:
            return None
        key = text[start : i - 1]
        keys.add(key.encode("latin-1") if isinstance(raw, bytes) else key)
        while i < len(text) and text[i] in "#0- +*.0123456789hlL":
            i += 1
        i += 1  # the conversion character
    return keys


def _format_fields(template: str) -> set | None:
    """Argument positions and names a `str.format` template uses (`{}`, `{1!r}`, `{x[0]}`,
    fields nested in a spec), or None when it does not parse."""
    used: set = set()
    auto = [0]

    def walk(text: str, depth: int) -> None:
        for _, field, spec, _ in string.Formatter().parse(text):
            if field is None:
                continue
            base = re.split(r"[.\[]", field, maxsplit=1)[0]
            if base == "":
                used.add(auto[0])
                auto[0] += 1
            elif base.isdecimal():  # (as Python: `{²}` names a key, not a position)
                used.add(int(base))
            else:
                used.add(base)
            if spec and depth < 2:
                walk(spec, depth + 1)

    try:
        walk(template, 0)
    except ValueError:
        return None
    return used


def _plain_position(node: ast.Call, index: int) -> bool:
    """Whether argument `index` (positional, then keyword values) is the positional argument
    at that position: no `*args` up to it (its position is unknown), and not a keyword."""
    return index < len(node.args) and not any(
        isinstance(a, ast.Starred) for a in node.args[: index + 1]
    )


def _call_args(node: ast.Call) -> list[ast.expr]:
    return [*node.args, *(k.value for k in node.keywords)]


def _root_name(node: ast.AST) -> str | None:
    """Name a target or receiver is rooted at, also through method calls: `d.get(k)` or
    `d.setdefault(k, [])` may return an object stored in `d`, so changing it changes `d`."""
    while True:
        if isinstance(node, (ast.Attribute, ast.Subscript, ast.Starred)):
            node = node.value
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            node = node.func.value
        else:
            return node.id if isinstance(node, ast.Name) else None


def _closure_names(scope: ast.AST) -> tuple[frozenset[str], frozenset[str]]:
    """Names nested scopes inside `scope` read, and names they rebind (nonlocal/global)."""
    loads: set[str] = set()
    stores: set[str] = set()
    # Each outermost nested scope is walked once; its walk covers deeper nesting too.
    outermost: list[ast.AST] = []
    stack = list(ast.iter_child_nodes(scope))
    while stack:
        node = stack.pop()
        if isinstance(node, (*FUNCTION_TYPES, ast.ClassDef)):
            outermost.append(node)
        else:
            stack.extend(ast.iter_child_nodes(node))
    for node in outermost:
        for inner in ast.walk(node):
            if isinstance(inner, ast.Name):
                loads.add(inner.id)
            elif isinstance(inner, ast.Nonlocal) or (
                isinstance(inner, ast.Global) and isinstance(scope, ast.Module)
            ):
                stores.update(inner.names)
    return frozenset(loads), frozenset(stores)


def _own_nodes(scope: ast.AST) -> Iterator[ast.AST]:
    """Nodes of code that runs in `scope`. Nested function and class bodies are other
    scopes; their name, decorators, defaults and bases (and comprehensions, whose `:=`
    binds here) belong to this one."""
    if isinstance(scope, ast.Lambda):
        stack: list[ast.AST] = [scope.body]
    else:
        stack = list(scope.body)  # type: ignore[attr-defined]
    while stack:
        node = stack.pop()
        yield node
        if isinstance(node, (*FUNCTION_TYPES, ast.ClassDef)):
            stack.extend(outer_parts(node))
            continue
        stack.extend(ast.iter_child_nodes(node))


def _has_own_walrus(scope: ast.AST) -> bool:
    return any(isinstance(node, ast.NamedExpr) for node in _own_nodes(scope))


def _declared_shared(scope: ast.AST) -> frozenset[str]:
    """Names `scope` declares `global`/`nonlocal` (other code may rebind them)."""
    if isinstance(scope, ast.Module):
        return frozenset()
    return frozenset(
        name
        for node in _own_nodes(scope)
        if isinstance(node, (ast.Global, ast.Nonlocal))
        for name in node.names
    )


def _module_binding_counts(tree: ast.AST) -> dict[str, int]:
    """How many binding sites each name of a scope (module, class or function body; not
    parameters) has (over-counting is safe)."""
    counts: dict[str, int] = {}
    for node in _own_nodes(tree):
        names: list[str] = []
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            names = [node.id]
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names = [node.name]
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            names = [(a.asname or a.name).split(".")[0] for a in node.names]
        elif isinstance(node, (ast.ExceptHandler, ast.MatchAs, ast.MatchStar)) and node.name:
            names = [node.name]
        elif isinstance(node, ast.MatchMapping) and node.rest:
            names = [node.rest]
        for name in names:
            counts[name] = counts.get(name, 0) + 1
    return counts


# Ways code can write module globals by name at runtime.
NAMESPACE_FUNCTIONS = frozenset({"globals", "vars", "locals", "exec", "eval", "__import__"})
# Methods that change a mapping (a namespace's `__dict__`, `globals()`).
MAPPING_WRITERS = frozenset(
    {"update", "setdefault", "pop", "popitem", "clear", "__setitem__", "__delitem__"}
)


NAMESPACE_ATTRIBUTES = frozenset({"__dict__", "__globals__", "modules", "__builtins__"})


class _Namespace:
    """Whether a namespace may be written by name at runtime: the module's (anywhere in
    the file) or a class body's (only code in that body can). Any spelling counts:
    `exec`, `builtins.exec`, `from builtins import exec as run`, `run = exec` (assigned
    aliases are followed file-wide). Computed once per file."""

    def __init__(self, tree: ast.Module, functions: frozenset[str] = NAMESPACE_FUNCTIONS) -> None:
        self.functions = functions
        self.imported = any(  # writers imported under another name
            (
                isinstance(node, ast.ImportFrom)
                and any(
                    a.name == "*"  # a star import may also rebind our names
                    or a.name in functions
                    or a.name in NAMESPACE_ATTRIBUTES
                    or a.name == "__builtins__"
                    for a in node.names
                )
            )
            or (
                isinstance(node, ast.Import)
                and any(a.name.split(".")[0] == "builtins" for a in node.names)
            )
            for node in ast.walk(tree)
        )
        self.writers = set(functions) | {"__builtins__"}
        self.module = self.imported or any(
            _mentions_writer(node, self.writers, functions) for node in ast.walk(tree)
        )
        if not self.module:
            return  # no writer anywhere: no aliases either
        # Names bound (anywhere) from an expression that mentions a writer are writers too.
        assignments = [
            (node.value, node.targets if isinstance(node, ast.Assign) else [node.target])
            for node in ast.walk(tree)
            if isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr))
            and node.value is not None
        ]
        changed = True
        while changed:
            changed = False
            for value, targets in assignments:
                if not any(
                    _mentions_writer(part, self.writers, functions) for part in ast.walk(value)
                ):
                    continue
                for target in targets:
                    for name in ast.walk(target):
                        if isinstance(name, ast.Name) and name.id not in self.writers:
                            self.writers.add(name.id)
                            changed = True

    def class_body(self, scope: ast.ClassDef) -> bool:
        if not self.module:
            return False
        return self.imported or any(
            _mentions_writer(node, self.writers, self.functions) for node in _own_nodes(scope)
        )


def _mentions_writer(
    node: ast.AST, writers: set[str], functions: frozenset[str] = NAMESPACE_FUNCTIONS
) -> bool:
    if isinstance(node, ast.Name):
        return node.id in writers
    if isinstance(node, ast.Attribute):
        return node.attr in NAMESPACE_ATTRIBUTES or node.attr in functions
    return False


def _header_nodes(stmt: ast.stmt) -> list[ast.AST]:
    """Parts of `stmt` evaluated before any nested block runs."""
    if isinstance(stmt, (ast.If, ast.While)):
        return [stmt.test]
    if isinstance(stmt, (ast.For, ast.AsyncFor)):
        return [stmt.iter]
    if isinstance(stmt, (ast.With, ast.AsyncWith)):
        return [i.context_expr for i in stmt.items]
    if isinstance(stmt, ast.Match):
        return [stmt.subject]
    if isinstance(stmt, ast.Try) or type(stmt).__name__ == "TryStar":
        return []
    if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
        args = stmt.args
        return [*stmt.decorator_list, *args.defaults, *(d for d in args.kw_defaults if d)]
    if isinstance(stmt, ast.ClassDef):
        return [*stmt.decorator_list, *stmt.bases, *(k.value for k in stmt.keywords)]
    return [stmt]
