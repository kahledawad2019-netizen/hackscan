"""Rules added for recall in 0.4: a shell enabled through `**` unpacking, weak hashes of
credential data (HIGH severity), and the libpq password-verifier helpers."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from hackscan.analyzers.ast_pass import analyze_file
from hackscan.core.models import Severity
from hackscan.plugins.loader import builtin_plugins

CMDI, CRYPTO = "HS-CMDI-001", "HS-CRYPTO-001"


def scan(tmp_path: Path, code: str) -> list:
    path = tmp_path / "app.py"
    path.write_text(textwrap.dedent(code), encoding="utf-8")
    return analyze_file(path, tmp_path, builtin_plugins(), taint=False).findings


def only(findings: list, rule: str) -> list:
    return [f for f in findings if f.rule_id == rule]


SHELL_UNPACKED = {
    "conditional subscript": """
        import subprocess, sys
        def run(command):
            kwargs = dict()
            kwargs['shell'] = True if sys.platform == 'win32' else False
            subprocess.Popen(command, **kwargs)
        """,
    "dict literal": """
        import subprocess
        def run(command):
            options = {'shell': True, 'cwd': '/tmp'}
            subprocess.run(command, **options)
        """,
    "dict() call with a flag": """
        import subprocess
        def run(command, flag):
            options = dict(shell=flag)
            subprocess.check_call(command, **options)
        """,
    "update keyword": """
        import subprocess
        def run(command):
            options = {}
            options.update(shell=True)
            subprocess.call(command, **options)
        """,
    "update with a dict": """
        import subprocess
        def run(command):
            options = {}
            options.update({'shell': True})
            subprocess.call(command, **options)
        """,
    "setdefault": """
        import subprocess
        def run(command):
            options = {}
            options.setdefault('shell', True)
            subprocess.check_output(command, **options)
        """,
    "a duplicate literal key ends true": """
        import subprocess
        def run(command):
            subprocess.run(command, **{'shell': False, 'shell': True})
        """,
    "dict() of a literal": """
        import subprocess
        def run(command):
            subprocess.run(command, **dict({'shell': True}))
        """,
    "dict() that may be the builtin (star import)": """
        import subprocess
        from os.path import *
        def run(command):
            subprocess.run(command, **dict(shell=True))
        """,
    "builtins.dict()": """
        import builtins, subprocess
        def run(command):
            subprocess.run(command, **builtins.dict(shell=True))
        """,
    "unpacked literal": """
        import subprocess
        def run(command):
            subprocess.run(command, **{'shell': True})
        """,
    "module level": """
        import subprocess, sys
        options = {'shell': sys.platform == 'win32'}
        subprocess.Popen(sys.argv[1:], **options)
        """,
}

SHELL_NOT_ENABLED = {
    "shell false": """
        import subprocess
        def run(command):
            options = {'shell': False}
            subprocess.Popen(command, **options)
        """,
    "no shell key": """
        import subprocess
        def run(command, where):
            options = {'cwd': where}
            subprocess.Popen(command, **options)
        """,
    "unknown dict (a parameter)": """
        import subprocess
        def run(command, **options):
            subprocess.Popen(command, **options)
        """,
    "shell set in another function": """
        import subprocess
        def configure():
            options = {}
            options['shell'] = True
            return options
        def run(command):
            options = {}
            subprocess.Popen(command, **options)
        """,
    "another dict gets the shell": """
        import subprocess
        def run(command):
            options, other = {}, {}
            other['shell'] = True
            subprocess.Popen(command, **options)
        """,
    "another dict literal has the shell": """
        import subprocess
        def run(command):
            options = {}
            other = {'shell': True}
            subprocess.Popen(command, **options)
        """,
    "a shadowed dict function": """
        import subprocess
        def dict(**kw):
            return {}
        def run(command):
            subprocess.run(command, **dict(shell=True))
        """,
    "a duplicate literal key ends false": """
        import subprocess
        def run(command):
            subprocess.run(command, **{'shell': True, 'shell': False})
        """,
    "dict() keyword overrides its argument": """
        import subprocess
        def run(command):
            subprocess.run(command, **dict({'shell': True}, shell=False))
        """,
    "constant command": """
        import subprocess
        def run():
            subprocess.Popen('ls -l', **{'shell': True})
        """,
}


@pytest.mark.parametrize("code", SHELL_UNPACKED.values(), ids=SHELL_UNPACKED.keys())
def test_shell_enabled_through_unpacking_is_a_sink(tmp_path, code):
    found = only(scan(tmp_path, code), CMDI)
    assert len(found) == 1
    assert "shell enabled through ** unpacking" in found[0].message


@pytest.mark.parametrize("code", SHELL_NOT_ENABLED.values(), ids=SHELL_NOT_ENABLED.keys())
def test_no_shell_through_unpacking(tmp_path, code):
    assert only(scan(tmp_path, code), CMDI) == []


def test_explicit_shell_keyword_message_unchanged(tmp_path):
    code = """
        import subprocess
        def run(command):
            subprocess.run(command, shell=True)
        """
    [found] = only(scan(tmp_path, code), CMDI)
    assert "subprocess.run(shell=True)" in found.message


CREDENTIAL_HASHES = {
    "constructor argument": """
        import hashlib
        def check(user, password):
            return user.hash == hashlib.md5(password.encode()).hexdigest()
        """,
    "update on the same object": """
        import hashlib
        def verifier(password, user):
            m = hashlib.md5()
            m.update(password.encode())
            m.update(user.encode())
            return m.hexdigest()
        """,
    "attribute": """
        import hashlib
        def store(account):
            return hashlib.sha1(account.passwd).hexdigest()
        """,
    "string key": """
        import hashlib
        from flask import request
        def signup():
            return hashlib.md5(request.form['password'].encode()).hexdigest()
        """,
    "compound name": """
        import hashlib
        def change(newpassword):
            return hashlib.md5(newpassword.encode()).hexdigest()
        """,
    "camelCase pwd": """
        import hashlib
        def change(userPwd):
            return hashlib.md5(userPwd.encode()).hexdigest()
        """,
    "hashlib.new with data": """
        import hashlib
        def change(passphrase):
            return hashlib.new('md5', passphrase.encode()).hexdigest()
        """,
    "constructor that may be md5 or new": """
        import hashlib
        if hashlib.algorithms_available:
            from hashlib import md5 as digest
        else:
            from hashlib import new as digest
        def store(password):
            return digest(password.encode()).hexdigest()
        """,
}

OTHER_HASHES = {
    "file content": """
        import hashlib
        def digest(path):
            with open(path, 'rb') as fh:
                return hashlib.md5(fh.read()).hexdigest()
        """,
    "pass prefix is not a password": """
        import hashlib
        def digest(passport_number, compass):
            return hashlib.md5((passport_number + compass).encode()).hexdigest()
        """,
    "cwd is not pwd": """
        import hashlib, os
        def digest():
            return hashlib.md5(os.getcwd().encode()).hexdigest()
        """,
    "another object is updated": """
        import hashlib
        def digest(data, password):
            m = hashlib.md5()
            other = hashlib.sha256()
            m.update(data)
            other.update(password.encode())
            return m.hexdigest(), other.hexdigest()
        """,
    "password in another function": """
        import hashlib
        def digest(data):
            m = hashlib.md5()
            m.update(data)
            return m
        def later(m, password):
            m.update(password.encode())
        """,
    "hashlib.new algorithm argument only": """
        import hashlib
        def digest(data):
            password_algorithm = 'md5'
            return hashlib.new(password_algorithm, data).hexdigest()
        """,
}


@pytest.mark.parametrize("code", CREDENTIAL_HASHES.values(), ids=CREDENTIAL_HASHES.keys())
def test_weak_hash_of_credential_data_is_high(tmp_path, code):
    [found] = only(scan(tmp_path, code), CRYPTO)
    assert found.severity is Severity.HIGH
    assert "credential data (CWE-916)" in found.message


@pytest.mark.parametrize("code", OTHER_HASHES.values(), ids=OTHER_HASHES.keys())
def test_other_weak_hashes_stay_low(tmp_path, code):
    [found] = only(scan(tmp_path, code), CRYPTO)
    assert found.severity is Severity.LOW


def test_not_for_security_flag_still_wins(tmp_path):
    code = """
        import hashlib
        def digest(password):
            return hashlib.md5(password.encode(), usedforsecurity=False).hexdigest()
        """
    assert only(scan(tmp_path, code), CRYPTO) == []


VERIFIERS = {
    "algorithm chosen by the caller": (
        """
        def change(conn, password, user, algorithm):
            return conn.pgconn.encrypt_password(password.encode(), user.encode(), algorithm)
        """,
        60,
        "not statically established",
    ),
    "no algorithm": (
        """
        def change(conn, password, user):
            return conn.pgconn.encrypt_password(password.encode(), user.encode())
        """,
        60,
        "server's encryption setting decides",
    ),
    "algorithm None": (
        """
        def change(conn, password, user):
            return conn.pgconn.encrypt_password(password, user, None)
        """,
        60,
        "server's encryption setting decides",
    ),
    "literal md5": (
        """
        def change(conn, password, user):
            return conn.pgconn.encrypt_password(password, user, algorithm=b"md5")
        """,
        80,
        "is built with MD5",
    ),
    "psycopg2 helper without algorithm": (
        """
        from psycopg2.extensions import encrypt_password
        def change(conn, password, user):
            return encrypt_password(password, user, conn)
        """,
        60,
        "server's encryption setting decides",
    ),
    "starred arguments shift the position (psycopg 3)": (
        """
        def change(conn):
            return conn.pgconn.encrypt_password(*(), b"secret", b"user", b"md5")
        """,
        60,
        "not statically established",
    ),
    "starred arguments shift the position (psycopg2)": (
        """
        import psycopg2.extensions
        def change(conn, rest):
            return psycopg2.extensions.encrypt_password(*rest, conn, "scram-sha-256")
        """,
        60,
        "not statically established",
    ),
}

STRONG_VERIFIERS = {
    "literal scram (bytes)": """
        def change(conn, password, user):
            return conn.pgconn.encrypt_password(password, user, b"scram-sha-256")
        """,
    "literal scram keyword after starred arguments": """
        def change(conn, args):
            return conn.pgconn.encrypt_password(*args, algorithm=b"scram-sha-256")
        """,
    "psycopg2 literal scram": """
        import psycopg2.extensions
        def change(conn, password, user):
            return psycopg2.extensions.encrypt_password(password, user, conn, "scram-sha-256")
        """,
    "an unrelated encrypt_password method": """
        def change(vault, password):
            return vault.encrypt_password(password)
        """,
    "an unrelated encrypt_password attribute chain": """
        class Store:
            def change(self, password, user, algorithm):
                return self.vault.encrypt_password(password, user, algorithm)
        """,
}


@pytest.mark.parametrize(("code", "confidence", "cause"), VERIFIERS.values(), ids=VERIFIERS.keys())
def test_libpq_verifier_helpers(tmp_path, code, confidence, cause):
    [found] = only(scan(tmp_path, code), CRYPTO)
    assert found.severity is Severity.HIGH
    assert found.confidence == confidence
    assert "PostgreSQL authentication verifier" in found.message
    assert cause in found.message


@pytest.mark.parametrize("code", STRONG_VERIFIERS.values(), ids=STRONG_VERIFIERS.keys())
def test_strong_or_unrelated_verifiers(tmp_path, code):
    assert only(scan(tmp_path, code), CRYPTO) == []


# -- lexical binding: evidence counts only for the same variable ---------------------------

SHELL_SAME_VARIABLE = {
    "class body": """
        import subprocess, sys
        class Tool:
            options = {'shell': True}
            subprocess.run(sys.argv[1], **options)
        """,
    "closure sets the outer dict": """
        import subprocess
        def run(command):
            options = {}
            def configure():
                options['shell'] = True
            configure()
            subprocess.run(command, **options)
        """,
    "global dict set in a function": """
        import subprocess
        OPTIONS = {}
        def configure():
            OPTIONS['shell'] = True
        def run(command):
            subprocess.run(command, **OPTIONS)
        """,
}

SHELL_OTHER_VARIABLE = {
    "comprehension target of the same name": """
        import subprocess
        def run(command, configs):
            options = {}
            [options.update(shell=True) for options in configs]
            subprocess.run(command, **options)
        """,
    "nested function rebinds its own local": """
        import subprocess
        def run(command):
            options = {}
            def configure():
                options = {'shell': True}
                return options
            subprocess.run(command, **options)
        """,
    "method uses a module name, not the class attribute": """
        import subprocess
        options = {}
        class Tool:
            options = {'shell': True}
            def run(self, command):
                subprocess.run(command, **options)
        """,
}


@pytest.mark.parametrize("code", SHELL_SAME_VARIABLE.values(), ids=SHELL_SAME_VARIABLE.keys())
def test_shell_evidence_follows_the_same_variable(tmp_path, code):
    assert len(only(scan(tmp_path, code), CMDI)) == 1


@pytest.mark.parametrize("code", SHELL_OTHER_VARIABLE.values(), ids=SHELL_OTHER_VARIABLE.keys())
def test_shell_evidence_ignores_other_variables(tmp_path, code):
    assert only(scan(tmp_path, code), CMDI) == []


HASH_SAME_VARIABLE = {
    "annotated assignment": """
        import hashlib
        def verifier(password):
            h: object = hashlib.md5()
            h.update(password.encode())
            return h.hexdigest()
        """,
    "class body": """
        import hashlib
        class Seed:
            digest = hashlib.md5()
            digest.update(b"admin")
            digest.update(DEFAULT_PASSWORD)
        """,
}

HASH_OTHER_VARIABLE = {
    "comprehension target of the same name": """
        import hashlib
        def digest(data, hashes, password):
            h = hashlib.md5(data)
            [h.update(password.encode()) for h in hashes]
            return h.hexdigest()
        """,
}


@pytest.mark.parametrize("code", HASH_SAME_VARIABLE.values(), ids=HASH_SAME_VARIABLE.keys())
def test_hash_evidence_follows_the_same_variable(tmp_path, code):
    [found] = only(scan(tmp_path, code), CRYPTO)
    assert found.severity is Severity.HIGH


@pytest.mark.parametrize("code", HASH_OTHER_VARIABLE.values(), ids=HASH_OTHER_VARIABLE.keys())
def test_hash_evidence_ignores_other_variables(tmp_path, code):
    [found] = only(scan(tmp_path, code), CRYPTO)
    assert found.severity is Severity.LOW


# -- documented limitations (flow-insensitive, alias-blind, name heuristics) -----------------

LIMITATION = "documented limitation: evidence is flow-insensitive, alias-blind and name-based"


@pytest.mark.xfail(strict=True, reason=LIMITATION)
def test_limitation_reassigned_hash_object(tmp_path):
    code = """
        import hashlib
        def digest(password):
            h = hashlib.md5()
            h = hashlib.sha256()
            h.update(password.encode())
            return h.hexdigest()
        """
    [found] = only(scan(tmp_path, code), CRYPTO)
    assert found.severity is Severity.LOW  # the MD5 object never sees the password


@pytest.mark.xfail(strict=True, reason=LIMITATION)
def test_limitation_aliased_hash_object(tmp_path):
    code = """
        import hashlib
        def digest(password):
            h = hashlib.md5()
            alias = h
            alias.update(password.encode())
            return h.hexdigest()
        """
    [found] = only(scan(tmp_path, code), CRYPTO)
    assert found.severity is Severity.HIGH


@pytest.mark.xfail(strict=True, reason=LIMITATION)
def test_limitation_name_is_not_a_password(tmp_path):
    code = """
        import hashlib, os
        def digest():
            pwd = os.getcwd()
            return hashlib.md5(pwd.encode()).hexdigest()
        """
    [found] = only(scan(tmp_path, code), CRYPTO)
    assert found.severity is Severity.LOW  # `pwd` here is a directory, not a secret


@pytest.mark.xfail(strict=True, reason=LIMITATION)
def test_limitation_shell_set_after_the_call(tmp_path):
    code = """
        import subprocess
        def run(command):
            options = {}
            subprocess.run(command, **options)
            options['shell'] = True
        """
    assert only(scan(tmp_path, code), CMDI) == []


@pytest.mark.xfail(strict=True, reason=LIMITATION)
def test_limitation_aliased_options_dict(tmp_path):
    code = """
        import subprocess
        def run(command):
            options = {}
            alias = options
            alias['shell'] = True
            subprocess.run(command, **options)
        """
    assert len(only(scan(tmp_path, code), CMDI)) == 1
