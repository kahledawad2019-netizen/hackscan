import os
import shlex
import sqlite3
import subprocess

from flask import Flask, request

app = Flask(__name__)
db = sqlite3.connect("app.db")


@app.route("/user")
def user():
    uid = request.args.get("id")
    return db.execute(f"SELECT * FROM users WHERE id = {uid}").fetchall()  # expect: VH-SQLI-001!


@app.route("/search")
def search():
    term = request.args["q"]
    query = "SELECT * FROM items WHERE name LIKE '%" + term + "%'"
    cur = db.cursor()
    cur.execute(query)  # expect: VH-SQLI-001!


@app.post("/ping")
def ping():
    host = request.form.get("host", "localhost")
    os.system("ping -c 1 " + host)  # expect: VH-CMDI-001!


@app.route("/files/<path:name>")
def show(name):
    return subprocess.check_output(f"cat {name}", shell=True)  # expect: VH-CMDI-001!


@app.route("/calc", methods=["POST"])
def calc():
    data = request.get_json()
    return str(eval(data["expr"]))  # expect: VH-CODEI-001!


@app.route("/safe-ping")
def safe_ping():
    host = shlex.quote(request.args.get("host", ""))
    os.system("ping -c 1 " + host)  # expect: VH-CMDI-001  (POSIX-quoted: kept, low confidence)


@app.route("/safe-user")
def safe_user():
    uid = int(request.args.get("id", "0"))
    return db.execute(f"SELECT * FROM users WHERE id = {uid}").fetchall()  # expect-suppressed: VH-SQLI-001 taint:sanitized


@app.route("/branches")
def branches():
    sort = "name"
    if request.args.get("by_date"):
        sort = request.args["by_date"]
    db.execute("SELECT * FROM t ORDER BY " + sort)  # expect: VH-SQLI-001!


@app.route("/loop")
def loop():
    parts = []
    for key in request.args:
        parts.append(key)
    db.execute("SELECT " + ", ".join(parts) + " FROM t")  # expect: VH-SQLI-001!


@app.route("/ignored")
def ignored():
    cmd = request.args["cmd"]
    os.system(cmd)  # vulnhawk: ignore[VH-CMDI-001]  expect-suppressed: VH-CMDI-001 inline:vulnhawk-ignore
