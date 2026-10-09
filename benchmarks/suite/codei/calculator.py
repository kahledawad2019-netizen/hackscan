"""Expression evaluation endpoints and helpers."""

import ast
import json

from flask import Flask, request

app = Flask(__name__)
FORMULAS = {"double": "x * 2", "square": "x * x"}


@app.route("/calc")
def calc():
    expr = request.args.get("expr", "0")
    return {"result": eval(expr)}  # vuln: codei


@app.route("/run", methods=["POST"])
def run_snippet():
    code = request.get_data(as_text=True)
    scope = {}
    exec(code, scope)  # vuln: codei
    return {"keys": sorted(scope)}


@app.route("/parse")
def parse_literal():
    raw = request.args.get("value", "[]")
    return {"value": ast.literal_eval(raw)}  # safe: codei


@app.route("/config", methods=["POST"])
def load_config():
    return {"config": json.loads(request.get_data(as_text=True))}  # safe: codei


@app.route("/formula/<name>")
def formula(name):
    if name not in FORMULAS:
        return {"error": "unknown"}, 404
    x = 3
    return {"result": eval(FORMULAS[name], {"x": x})}  # safe: codei


def version_tuple():
    return eval("(3, 12)")  # safe: codei


def compile_rule(rule_text):
    return compile(rule_text, "<rule>", "eval")  # vuln: codei


@app.route("/rule")
def rule():
    return {"ok": eval(compile_rule(request.args["rule"]))}  # vuln: codei
