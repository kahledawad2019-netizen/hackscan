import builtins


def calc(expression):
    return eval(expression)  # expect: VH-CODEI-001


def run_snippet(request):
    exec(request.form["code"])  # expect: VH-CODEI-001


def build(op, a, b):
    return eval(f"{a} {op} {b}")  # expect: VH-CODEI-001


def compiled(src):
    code = compile(src, "<user>", "exec")  # expect: VH-CODEI-001
    return code


def via_builtins(expr):
    return builtins.eval(expr)  # expect: VH-CODEI-001


def nested(x):
    return eval(eval(x))  # expect: VH-CODEI-001 VH-CODEI-001


def builtins_compile(src):
    return builtins.compile(src, "<user>", "exec")  # expect: VH-CODEI-001


def dead_constant_branch(src):
    if False:
        src = "1"
    return eval(src)  # expect: VH-CODEI-001
