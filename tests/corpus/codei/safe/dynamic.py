import ast
from mylib import eval  # a different `eval`, not the builtin


def literal(value):
    return ast.literal_eval(value)


def constant_eval():
    return eval_builtin_constant()


def eval_builtin_constant():
    import builtins

    return builtins.eval("1 + 1")


def constant_variable():
    code = "print('hello')"
    exec(code)  # expect-suppressed: HS-CODEI-001 taint:constant_input


def shadowed(expr):
    return eval(expr)


def parameter_named_eval(eval, expr):
    return eval(expr)
