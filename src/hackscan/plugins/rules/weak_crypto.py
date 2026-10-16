"""Weak cryptography: MD5/SHA-1 hashing, unless explicitly marked non-security.

A weak hash whose hashed data visibly names a password (in the constructor, or in `update()`
calls on the same hash object) is reported at HIGH severity: unsalted fast hashes of passwords
are CWE-916. The libpq password-verifier helpers (psycopg `PGconn.encrypt_password`,
`psycopg2.extensions.encrypt_password`) produce an MD5 verifier unless a strong algorithm is
given literally, since without one the server's `password_encryption` setting decides.
"""

from __future__ import annotations

import ast
from collections.abc import Iterable

from hackscan.core.models import Severity
from hackscan.plugins.base import FileContext, Match, RulePlugin, first_arg, keyword, same_binding

WEAK_ALGORITHMS = frozenset({"md5", "sha1", "md4", "md2"})
WEAK_CONSTRUCTORS = {f"hashlib.{alg}": alg for alg in WEAK_ALGORITHMS}
# Words that name a password inside an identifier, matched case-insensitively as substrings
# (`newpassword`, `passwd_hash`, `userPwd`).
PASSWORD_WORDS = ("password", "passwd", "passphrase", "pwd")
# Verifier helpers: dotted name or `<x>.pgconn.encrypt_password`, and the position of `algorithm`.
PSYCOPG2_ENCRYPT = "psycopg2.extensions.encrypt_password"
PSYCOPG2_POSITION = 3  # (psycopg 3's `PGconn.encrypt_password` has it second, at 2)
# Messages avoid "password <word>", which the secret redactor would treat as a value.
VERIFIER_MD5 = "A PostgreSQL authentication verifier is built with MD5."
VERIFIER_SERVER = (
    "A PostgreSQL authentication verifier may be built with MD5: no algorithm is given, so "
    "the server's encryption setting decides."
)
VERIFIER_UNKNOWN = (
    "A PostgreSQL authentication verifier may be built with MD5: the algorithm is not "
    "statically established."
)
# Remediation appended to a verifier message, per helper API (PostgreSQL 10+ for SCRAM); the
# credentials must then be set again so stored MD5 verifiers are replaced.
PSYCOPG2_GUIDANCE = (
    " Pass algorithm='scram-sha-256' together with a connection or cursor as scope (psycopg2"
    " needs it for SCRAM), then set the credentials again so stored MD5 verifiers are replaced."
)
PSYCOPG3_GUIDANCE = (
    " Pass algorithm=b'scram-sha-256' (a bytes value), then set the credentials again so stored"
    " MD5 verifiers are replaced."
)


class WeakHash(RulePlugin):
    rule_id = "HS-CRYPTO-001"
    name = "weak-hash"
    description = "A cryptographically broken hash (MD5/SHA-1) is used."
    severity = Severity.LOW
    cwe = ("CWE-328",)
    default_confidence = 80

    def check(self, node: ast.AST, ctx: FileContext) -> Iterable[Match]:
        assert isinstance(node, ast.Call)
        names = ctx.call_names(node)
        if (position := _verifier_helper(node, names)) is not None:
            yield from _verifier_match(node, position)
            return
        confidence = None
        if constructors := sorted(names & WEAK_CONSTRUCTORS.keys()):
            algorithm = WEAK_CONSTRUCTORS[constructors[0]]
        elif "hashlib.new" in names:
            arg = first_arg(node, "name")
            literals = [arg]
            if isinstance(arg, ast.Name):
                # Find a literal algorithm name bound locally (never used to dismiss).
                literals = ctx.assignments_before(arg.id, node)
                confidence = 60
            weak = sorted({_normalize(v.value) for v in literals if _is_str(v)} & WEAK_ALGORITHMS)
            if not weak:
                return
            algorithm = weak[0]
        else:
            return
        flag = keyword(node, "usedforsecurity")
        if isinstance(flag, ast.Constant) and flag.value is False:
            return
        if any(_names_password(expr) for expr in _hashed_data(node, ctx)):
            yield Match(
                node,
                f"Weak hash algorithm {algorithm.upper()} is used on credential data (CWE-916): "
                "use a slow, salted scheme made for credentials (Argon2, scrypt, bcrypt or "
                "PBKDF2) and migrate the stored hashes (rehash at the next login).",
                confidence,
                severity=Severity.HIGH,
            )
        else:
            yield Match(node, f"Weak hash algorithm {algorithm.upper()} is used.", confidence)


def _hashed_data(call: ast.Call, ctx: FileContext) -> list[ast.expr]:
    """The data hashed by `call`: its data argument, and the arguments of `update()` calls on
    a variable the hash object is assigned to (`h = md5()` or `h: T = md5()`), wherever that
    same variable is bound. Flow-insensitive and alias-blind (documented in the tests)."""
    data = [k.value for k in call.keywords if k.arg in ("data", "string")]
    # Data position per possible constructor: first for md5()/sha1(), second for new(name, data);
    # a call that may be either (conditional imports) collects both.
    names = ctx.call_names(call)
    positional = (call.args[:1] if names & WEAK_CONSTRUCTORS.keys() else []) + (
        call.args[1:2] if "hashlib.new" in names else []
    )
    data.extend(a for a in positional if not isinstance(a, ast.Starred))
    holders: list[ast.Name] = []
    nodes = list(ast.walk(ctx.tree))
    for node in nodes:
        if isinstance(node, ast.Assign) and node.value is call:
            holders.extend(t for t in node.targets if isinstance(t, ast.Name))
        elif (
            isinstance(node, ast.AnnAssign)
            and node.value is call
            and isinstance(node.target, ast.Name)
        ):
            holders.append(node.target)
    for node in nodes:
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "update"
            and isinstance(node.func.value, ast.Name)
            and any(
                node.func.value.id == h.id and same_binding(ctx, node.func.value, h)
                for h in holders
            )
        ):
            data.extend(node.args)
    return data


def credential_hash(call: ast.Call, ctx: FileContext) -> bool:
    """Whether `call` hashes credential data: a libpq verifier helper, or a hash whose data
    names a password (the rule's CWE-916 evidence). Such a hash needs a slow, salted scheme and a
    migration, so no fix may swap in another fast digest (template or LLM)."""
    if _verifier_helper(call, ctx.call_names(call)) is not None:
        return True
    return any(_names_password(expr) for expr in _hashed_data(call, ctx))


def _names_password(expr: ast.AST) -> bool:
    """Whether a name, attribute or identifier-like string key in `expr` names a password
    (`password`, `user.passwd`, `form["password"]`, `userPwd`)."""
    for node in ast.walk(expr):
        if isinstance(node, ast.Name):
            name = node.id
        elif isinstance(node, ast.Attribute):
            name = node.attr
        elif (
            isinstance(node, ast.Constant)
            and isinstance(node.value, str)
            and node.value.isidentifier()
        ):
            name = node.value
        else:
            continue
        if any(word in name.lower() for word in PASSWORD_WORDS):
            return True
    return False


def _verifier_helper(call: ast.Call, names: frozenset[str]) -> int | None:
    """Position of the `algorithm` argument when `call` is a libpq password-verifier helper."""
    if PSYCOPG2_ENCRYPT in names:
        return PSYCOPG2_POSITION  # encrypt_password(password, user, scope=None, algorithm=None)
    func = call.func
    if (
        isinstance(func, ast.Attribute)
        and func.attr == "encrypt_password"
        and isinstance(func.value, ast.Attribute)
        and func.value.attr == "pgconn"
    ):
        return 2  # PGconn.encrypt_password(passwd, user, algorithm=None)
    return None


def _verifier_match(call: ast.Call, position: int) -> Iterable[Match]:
    """MD5 when the algorithm is the literal md5; unknown (reported) when it is not a literal,
    when an earlier `*args` makes its position uncertain, or when it is missing or None (then
    the server's setting decides); nothing for another literal algorithm."""
    guidance = PSYCOPG2_GUIDANCE if position == PSYCOPG2_POSITION else PSYCOPG3_GUIDANCE
    algorithm = keyword(call, "algorithm")
    if algorithm is None:
        if any(isinstance(a, ast.Starred) for a in call.args[: position + 1]):
            yield Match(call, VERIFIER_UNKNOWN + guidance, 60, severity=Severity.HIGH)
            return
        if len(call.args) > position:
            algorithm = call.args[position]
    if algorithm is None or isinstance(algorithm, ast.Constant) and algorithm.value is None:
        yield Match(call, VERIFIER_SERVER + guidance, 60, severity=Severity.HIGH)
        return
    if isinstance(algorithm, ast.Constant) and isinstance(algorithm.value, (str, bytes)):
        value = algorithm.value
        if isinstance(value, bytes):
            value = value.decode("utf-8", errors="replace")
        if _normalize(value) != "md5":
            return
        yield Match(call, VERIFIER_MD5 + guidance, severity=Severity.HIGH)
        return
    yield Match(call, VERIFIER_UNKNOWN + guidance, 60, severity=Severity.HIGH)


def _is_str(node: ast.AST | None) -> bool:
    return isinstance(node, ast.Constant) and isinstance(node.value, str)


def _normalize(name: str) -> str:
    return name.lower().replace("-", "").replace("_", "")
