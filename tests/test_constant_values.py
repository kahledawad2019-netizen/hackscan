"""Constant values through literal containers and pure library functions (0.4.1).

Precision: an element of a list, set, dict or tuple display written as literals is not a mutable
object, so passing it on cannot change the display; a pure text function (`os.path.join`,
`urllib.parse.unquote`, ...) of constants is a constant. Soundness: a display that holds, or may
come to hold, a mutable object keeps its elements mutable; objects stored in containers stay linked
to them; functions that read the environment, the working directory or the file system (pathlib
paths) never give a constant.
"""

from __future__ import annotations

import textwrap

import pytest

from hackscan.analyzers.ast_pass import analyze_source
from hackscan.analyzers.taint_pass import CONSTANT_INPUT
from hackscan.core.models import Status
from hackscan.plugins.loader import builtin_plugins

HEADER = (
    "import os\nimport re\nimport json\nimport html\nimport pathlib\nimport sqlite3\n"
    "import urllib.parse\n"
)


def statuses(code: str) -> list[tuple[Status, str | None]]:
    source = HEADER + textwrap.dedent(code)
    result = analyze_source(source, "t.py", builtin_plugins())
    assert not result.errors, result.errors
    return [
        (f.status, f.suppression)
        for f in sorted(result.findings, key=lambda f: f.location.start_line)
    ]


SUPPRESSED = (Status.SUPPRESSED, CONSTANT_INPUT)


@pytest.mark.parametrize(
    "code",
    [
        pytest.param(
            """
            def seed(c):
                users = [("admin", "x"), ("tim", "y")]
                for u, p in users:
                    c.execute("INSERT INTO users VALUES ('%s', '%s')" % (u, p))
            """,
            id="list of literal tuples, unpacked, unknown call in the loop",
        ),
        pytest.param(
            """
            def f():
                names = ["a", "b"]
                for n in names:
                    helper(n)
                    os.system("echo " + n)
            """,
            id="strings passed to an unknown function",
        ),
        pytest.param(
            """
            def f():
                options = {"a": "x", "b": "y"}
                for key in options:
                    helper(key)
                    os.system("echo " + key)
            """,
            id="dict display of strings",
        ),
        pytest.param(
            """
            def f():
                names = {"a", "b"}
                for n in names:
                    helper(n)
                    os.system("echo " + n)
            """,
            id="set display of strings",
        ),
        pytest.param(
            """
            def f():
                rows = [("a", 1), ("b", 2)]
                rows2 = rows if helper(0) else [("c", 3)]
                for name, count in rows2:
                    helper(name)
                    os.system("echo %s %d" % (name, count))
            """,
            id="join of two displays of immutable elements",
        ),
        pytest.param(
            """
            def f():
                os.system("ls " + os.path.join("/tmp", "x"))
            """,
            id="os.path.join of constants",
        ),
        pytest.param(
            """
            def logs(logtime):
                filename = "app.log"
                fullname = os.path.join(".", filename)
                os.system("journalctl -b > {}".format(fullname))
            """,
            id="a joined constant path in a command",
        ),
        pytest.param(
            """
            def f():
                os.system("ls " + os.path.normpath("a/../b"))
            """,
            id="normpath of a constant",
        ),
        pytest.param(
            """
            def f():
                rows = [(-1, "a" + "b"), (2 * 3, f"c{1}")]
                for n, s in rows:
                    helper(s)
                    os.system("echo %d %s" % (n, s))
            """,
            id="tuples of operators and f-strings of literals",
        ),
        pytest.param(
            """
            def f():
                commands = {"list": "ls -l", "disk": "df -h"}
                for name, cmd in commands.items():
                    helper(name)
                    os.system(cmd)
            """,
            id="a command table iterated by items()",
        ),
        pytest.param(
            """
            def f():
                commands = {"list": "ls -l", "disk": "df -h"}
                for cmd in commands.values():
                    os.system(cmd)
            """,
            id="a command table iterated by values()",
        ),
        pytest.param(
            """
            def f(i):
                rows = [("echo", "a")]
                out = [item[i] for *item, in rows]
                os.system(" ".join(out))
            """,
            id="an item of a starred comprehension target",
        ),
        pytest.param(
            """
            def f():
                os.system("ls " + urllib.parse.unquote("%2Ftmp"))
            """,
            id="unquote of a constant",
        ),
        pytest.param(
            """
            def f():
                os.system("echo " + html.unescape("&lt;b&gt;"))
            """,
            id="html.unescape of a constant",
        ),
        pytest.param(
            """
            def f():
                os.system(re.sub("a", "b", "echo a"))
            """,
            id="re.sub with constant pattern, replacement and string",
        ),
    ],
)
def test_constants_are_suppressed(code: str) -> None:
    assert statuses(code)[-1] == SUPPRESSED


@pytest.mark.parametrize(
    "code",
    [
        pytest.param(
            """
            def f():
                parts = ["echo "]
                rows = ["echo a"]
                rows.append(parts)
                for item in rows:
                    if isinstance(item, list):
                        item.append(input())
                os.system("".join(parts))
            """,
            id="a list appended, changed through the loop variable",
        ),
        pytest.param(
            """
            def f():
                parts = ["echo "]
                rows = ["echo a", parts]
                for item in rows:
                    if isinstance(item, list):
                        item.append(input())
                os.system("".join(parts))
            """,
            id="a display holding a list",
        ),
        pytest.param(
            """
            def f(flag):
                parts = ["echo "]
                rows = ["echo a"] if flag else [parts]
                for item in rows:
                    if isinstance(item, list):
                        item.append(input())
                os.system("".join(parts))
            """,
            id="one alternative holds a list",
        ),
        pytest.param(
            """
            def f():
                parts = ["echo "]
                rows = ["echo a"]
                rows += [parts]
                for item in rows:
                    if isinstance(item, list):
                        item.append(input())
                os.system("".join(parts))
            """,
            id="a list added by +=",
        ),
        pytest.param(
            """
            class Box:
                pass

            def f():
                parts = ["echo "]
                box = Box()
                box.items = []
                box.items += [parts]
                for item in box.items:
                    item.append(input())
                os.system("".join(parts))
            """,
            id="a list added by += to an attribute",
        ),
        pytest.param(
            """
            def f():
                rows = [["echo "]]
                for item in rows:
                    item.append(input())
                os.system("".join(rows[0]))
            """,
            id="a list element changed through the loop variable",
        ),
        pytest.param(
            """
            def f():
                names = ["a", "b"]
                helper(names)
                for n in names:
                    os.system("echo " + n)
            """,
            id="the display escapes to an unknown function",
        ),
        pytest.param(
            """
            def f():
                os.system("ls " + os.path.abspath("x"))
            """,
            id="abspath depends on the working directory",
        ),
        pytest.param(
            """
            def f():
                os.system("ls " + os.path.expanduser("~/x"))
            """,
            id="expanduser depends on the environment",
        ),
        pytest.param(
            """
            def f():
                os.system("ls " + json.loads('"x"'))
            """,
            id="json.loads is not a pure text model",
        ),
        pytest.param(
            """
            def f(pattern):
                os.system(re.sub(pattern, "b", "echo a"))
            """,
            id="a pure function with one non-constant argument",
        ),
        pytest.param(
            """
            def f(name):
                os.system("ls " + os.path.join("/tmp", name))
            """,
            id="os.path.join of a parameter",
        ),
        pytest.param(
            """
            def f():
                os.system(pathlib.Path("command.txt").read_text())
            """,
            id="a file read through a constant path",
        ),
        pytest.param(
            """
            def f():
                os.system(pathlib.Path("command.txt").read_bytes().decode())
            """,
            id="bytes read through a constant path",
        ),
        pytest.param(
            """
            def f():
                os.system(pathlib.Path("command.txt").open().read())
            """,
            id="a file opened through a constant path",
        ),
        pytest.param(
            """
            def f():
                os.system("ls " + str(pathlib.Path("data").resolve()))
            """,
            id="a resolved constant path",
        ),
        pytest.param(
            """
            def f():
                os.system("ls " + str(pathlib.Path("~/data").expanduser()))
            """,
            id="an expanded constant path",
        ),
        pytest.param(
            """
            def f():
                rows = (["echo "],)
                for item in rows:
                    item.append(input())
                os.system("".join(rows[0]))
            """,
            id="a tuple holding a list",
        ),
        pytest.param(
            """
            def f():
                rows = [["echo "] for _ in range(1)]
                for item in rows:
                    item.append(input())
                os.system("".join(rows[0]))
            """,
            id="a comprehension of lists",
        ),
        pytest.param(
            """
            def f(c):
                parts = [int(input())]
                rows = []
                rows.append(parts)
                parts.append(input())
                c.execute("SELECT " + str(rows[0][-1]))
            """,
            id="a sanitized list stored, then changed",
        ),
        pytest.param(
            """
            def f():
                parts = ["echo "]
                rows = []
                rows.append(dict(k=parts))
                parts.append(input())
                os.system("".join(rows[0]["k"]))
            """,
            id="a list stored through a keyword argument",
        ),
        pytest.param(
            """
            def f():
                parts = ["echo "]
                rows = []
                rows.append([item for item in [parts]])
                parts.append(input())
                os.system("".join(rows[0][0]))
            """,
            id="a list stored through a comprehension",
        ),
        pytest.param(
            """
            def f():
                rows = ["echo".split()]
                for item in rows:
                    item.append(input())
                os.system(" ".join(rows[0]))
            """,
            id="a display of a method's result (a list)",
        ),
        pytest.param(
            """
            def f():
                rows = [sorted(("echo",))]
                for item in rows:
                    item.append(input())
                os.system(" ".join(rows[0]))
            """,
            id="a display of sorted() (a list)",
        ),
        pytest.param(
            """
            def f():
                rows = [("echo",)]
                for *item, in rows:
                    item.append(input())
                    os.system(" ".join(item))
            """,
            id="a starred loop target is a new list",
        ),
        pytest.param(
            """
            def f():
                first, *rest = ("echo", "a")
                rest.append(input())
                os.system(" ".join(rest))
            """,
            id="a starred assignment target is a new list",
        ),
        pytest.param(
            """
            def f():
                rows = [("echo",)]
                out = [item for *item, in rows]
                for item in out:
                    item.append(input())
                os.system(" ".join(out[0]))
            """,
            id="a starred comprehension target is a new list",
        ),
        pytest.param(
            """
            def f():
                x = sorted(("echo",))
                y = x
                y.append(input())
                os.system(" ".join(x))
            """,
            id="sorted() aliased and changed",
        ),
        pytest.param(
            """
            def f():
                x = "echo a".split()
                y = x
                y.append(input())
                os.system(" ".join(x))
            """,
            id="a split result aliased and changed",
        ),
        pytest.param(
            """
            def f():
                x = "echo a".split()
                helper(x)
                os.system(" ".join(x))
            """,
            id="a split result escaping to an unknown function",
        ),
        pytest.param(
            """
            def f():
                rows = dict(k=["echo"])
                for item in rows.values():
                    item.append(input())
                os.system(" ".join(rows["k"]))
            """,
            id="a list given to dict() as a value",
        ),
        pytest.param(
            """
            from psycopg2 import sql

            def f():
                parts = sql.Literal(["echo"]).wrapped
                alias = parts
                alias.append(input())
                os.system(" ".join(parts))
            """,
            id="an attribute of a sanitized value may be a list",
        ),
    ],
)
def test_possibly_changed_values_stay_open(code: str) -> None:
    status, _ = statuses(code)[-1]
    assert status is not Status.SUPPRESSED


@pytest.mark.parametrize(
    "code",
    [
        """
        def f():
            names = ["a", "b"]
            names.append(input())
            for n in names:
                os.system("echo " + n)
        """,
        """
        def f():
            os.system(os.path.join("echo", input()))
        """,
        """
        def f():
            os.system("cat " + str(pathlib.Path(input())))
        """,
    ],
    ids=["input appended to a display", "join of input", "path of input"],
)
def test_untrusted_data_through_them_is_confirmed(code: str) -> None:
    assert statuses(code)[-1][0] is Status.CONFIRMED


def test_replaced_path_function_gives_no_constant() -> None:
    # A model counts only through a name the file does not replace (as sanitizers do).
    (status, _) = statuses(
        """
        os.path.join = lambda *parts: input()

        def f():
            os.system("ls " + os.path.join("/tmp", "x"))
        """
    )[-1]
    assert status is not Status.SUPPRESSED


ROWS_READS = (
    "for item in rows:\n        os.system(str(item))",
    "os.system(str(rows[0]))",
    "os.system(str(rows))",
)
BOX_READS = ("os.system(str(box['k']))", "os.system(str(box))")
STORES = [  # (store, reads of the container it writes)
    ("rows.append(parts)", ROWS_READS),
    ("rows.insert(0, parts)", ROWS_READS),
    ("rows.extend([parts])", ROWS_READS),
    ("rows[0] = parts", ROWS_READS),
    ("rows += [parts]", ROWS_READS),
    ("box.setdefault('k', parts)", BOX_READS),
    ("box['k'] = parts", BOX_READS),
    ("box.update(k=parts)", BOX_READS),
    ("holder.parts = parts", ("os.system(str(holder.parts))",)),
]


@pytest.mark.parametrize(
    ("store", "read"),
    [(store, read) for store, reads in STORES for read in reads],
)
def test_a_stored_object_changed_later_is_seen_through_the_container(store: str, read: str) -> None:
    # A list stored in a container and changed afterwards through its own name: the container
    # refers to the changed list, so a sink reading the container is not constant.
    code = (
        "class Holder:\n    pass\n\n"
        "def f():\n    parts = ['echo ']\n    rows = ['echo a']\n"
        "    box = {}\n    holder = Holder()\n"
        f"    {store}\n    parts.append(input())\n    {read}\n"
    )
    status, _ = statuses(code)[-1]
    assert status is not Status.SUPPRESSED


@pytest.mark.parametrize("store", ['rows.append(["b"])', 'rows[0] = ["b"]'])
def test_a_list_display_stored_in_a_container_is_mutable(store: str) -> None:
    # The stored display has immutable elements, but it is itself a list: changed through the
    # loop variable, it changes what the container holds.
    code = (
        "def f():\n    rows = ['echo a']\n"
        f"    {store}\n"
        "    for item in rows:\n        if isinstance(item, list):\n"
        "            item.append(input())\n"
        "    os.system(str(rows))\n"
    )
    status, _ = statuses(code)[-1]
    assert status is not Status.SUPPRESSED


@pytest.mark.parametrize(
    "code",
    [
        """
        def f(flag):
            parts = ["echo "]
            rows = []
            rows.append(parts if flag else ["x"])
            parts.append(input())
            os.system(str(rows))
        """,
        """
        def f():
            table = {"k": ["echo "]}
            rows = []
            rows.append(table["k"])
            table["k"].append(input())
            os.system(str(rows))
        """,
    ],
    ids=["one of two alternatives stored", "an element of another container stored"],
)
def test_objects_stored_through_expressions_stay_linked(code: str) -> None:
    status, _ = statuses(code)[-1]
    assert status is not Status.SUPPRESSED


def test_storing_a_constant_list_alone_keeps_the_container_constant() -> None:
    # Linking a stored list to its container does not by itself make the container unknown.
    assert (
        statuses(
            """
        def f():
            args = ["ls", "-l"]
            config = {}
            config["args"] = args
            os.system(" ".join(config["args"]))
        """
        )[-1]
        == SUPPRESSED
    )
