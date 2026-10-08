"""Differential soundness fuzzing for the taint pass.

Random small programs (branches, loops with break/continue, try/except/finally, raises,
list mutation through aliases) are *executed* with an instrumented `os.system` and an
`input()` that returns a marker. If any execution delivers the marker to a sink that the
scanner reported as suppressed, the suppression is unsound and the test fails with the
offending program.
"""

from __future__ import annotations

import contextlib
import random

from vulnhawk.analyzers.ast_pass import analyze_source
from vulnhawk.core.models import Status
from vulnhawk.plugins.loader import builtin_plugins

MARK = "ATTACKER_MARK"
N_PROGRAMS = 250
N_FLAG_VECTORS = 12
N_FLAGS = 6


class _Gen:
    def __init__(self, rng: random.Random) -> None:
        self.rng = rng
        self.lines: list[str] = []
        self.sinks = 0
        # Closures make values non-suppressible, so only some programs get them;
        # otherwise the fuzzer would never exercise suppressions.
        self.closures = [c for c in ("add_input()", "set_cmd()") if rng.random() < 0.25]

    def emit(self, indent: int, text: str) -> None:
        self.lines.append("    " * indent + text)

    def flag(self) -> str:
        return f"flags[{self.rng.randrange(N_FLAGS)}]"

    def simple(self, indent: int, in_loop: bool, in_try: bool) -> None:
        r = self.rng
        choices = [
            'cmd = "echo safe"',
            "cmd = input()",
            'cmd = cmd + " x"',
            "parts.append(input())",
            'parts.append("y")',
            'parts = ["echo "]',
            "alias = parts",
            "alias.append(input())",
            'cmd = "".join(parts)',
            "cmd = helper(cmd)",
            "helper(parts)",
            'box = {"k": parts}',
            "box['k'].append(input())",
            "WALRUS",
            *self.closures,
        ]
        if r.random() < 0.35:
            self.emit(indent, "os.system(cmd)")
            self.sinks += 1
        else:
            choice = r.choice(choices)
            if choice == "WALRUS":
                self.emit(indent, f"if (cmd := input()) and {self.flag()}:")
                self.emit(indent + 1, "pass")
            else:
                self.emit(indent, choice)
        if in_loop and r.random() < 0.15:
            self.emit(indent, f"if {self.flag()}:")
            self.emit(indent + 1, r.choice(["break", "continue"]))
        if in_try and r.random() < 0.15:
            self.emit(indent, f"if {self.flag()}:")
            self.emit(indent + 1, "raise ValueError()")
        if r.random() < 0.05:
            self.emit(indent, f"if {self.flag()}:")
            self.emit(indent + 1, "return")

    def block(self, indent: int, depth: int, in_loop: bool, in_try: bool) -> None:
        for _ in range(self.rng.randint(1, 4)):
            kind = self.rng.random()
            if depth >= 3 or kind < 0.55:
                self.simple(indent, in_loop, in_try)
            elif kind < 0.7:
                self.emit(indent, f"if {self.flag()}:")
                self.block(indent + 1, depth + 1, in_loop, in_try)
                if self.rng.random() < 0.5:
                    self.emit(indent, "else:")
                    self.block(indent + 1, depth + 1, in_loop, in_try)
            elif kind < 0.78:
                counter = f"_n{len(self.lines)}"
                self.emit(indent, f"{counter} = 0")
                self.emit(indent, f"while {counter} < {self.rng.randint(0, 3)}:")
                self.emit(indent + 1, f"{counter} += 1")
                self.block(indent + 1, depth + 1, True, in_try)
            elif kind < 0.88:
                self.emit(indent, f"for _i in range({self.rng.randint(0, 3)}):")
                self.block(indent + 1, depth + 1, True, in_try)
                if self.rng.random() < 0.3:
                    self.emit(indent, "else:")
                    self.block(indent + 1, depth + 1, in_loop, in_try)
            else:
                self.emit(indent, "try:")
                self.block(indent + 1, depth + 1, in_loop, True)
                self.emit(indent, "except ValueError:")
                self.block(indent + 1, depth + 1, in_loop, in_try)
                if self.rng.random() < 0.5:
                    self.emit(indent, "finally:")
                    self.block(indent + 1, depth + 1, in_loop, in_try)

    def program(self) -> str:
        self.emit(0, "import os")
        self.emit(0, "")
        self.emit(0, "def f(flags):")
        self.emit(1, 'cmd = "echo safe"')
        self.emit(1, 'parts = ["echo "]')
        self.emit(1, "alias = []")
        self.emit(1, 'box = {"k": parts}')
        if "add_input()" in self.closures:
            self.emit(1, "def add_input():")
            self.emit(2, "parts.append(input())")
        if "set_cmd()" in self.closures:
            self.emit(1, "def set_cmd():")
            self.emit(2, "nonlocal cmd")
            self.emit(2, "if flags[1]:")
            self.emit(3, "cmd = input()")
        self.block(1, 0, in_loop=False, in_try=False)
        self.emit(1, "os.system(cmd)")
        return "\n".join(self.lines) + "\n"


def _execute(source: str, flags: list[bool]) -> set[int]:
    """Lines of sink calls that received the marker during one execution."""
    hits: set[int] = set()

    def fake_system(command: object) -> int:
        import sys

        frame = sys._getframe(1)
        if MARK in str(command):
            hits.add(frame.f_lineno)
        return 0

    class FakeOs:
        system = staticmethod(fake_system)

    runnable = source.replace("import os\n", "pass\n", 1)
    namespace: dict = {"os": FakeOs, "input": lambda *a: MARK, "helper": lambda v: v}
    exec(compile(runnable, "<fuzz>", "exec"), namespace)
    with contextlib.suppress(ValueError):
        namespace["f"](flags)
    return hits


def test_no_unsound_suppressions_in_random_programs():
    rng = random.Random(20261008)
    checked = 0
    suppressions_tested = 0
    for _ in range(N_PROGRAMS):
        gen = _Gen(rng)
        source = gen.program()
        result = analyze_source(source, "fuzz.py", builtin_plugins())
        assert not result.errors, (result.errors, source)
        suppressed = {
            f.location.start_line: f.suppression
            for f in result.findings
            if f.status is Status.SUPPRESSED
        }
        suppressions_tested += len(suppressed)
        for _ in range(N_FLAG_VECTORS):
            flags = [rng.random() < 0.5 for _ in range(N_FLAGS)]
            for line in _execute(source, flags):
                assert line not in suppressed, (
                    f"unsound {suppressed[line]} at line {line} with flags={flags}:\n{source}"
                )
                checked += 1
    # Guard against a vacuous fuzzer: it must hit tainted sinks and test suppressions.
    assert checked > 100
    assert suppressions_tested > 100
