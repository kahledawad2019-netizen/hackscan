"""Flask reporting endpoints backed by sqlite3."""

import sqlite3

from flask import Flask, request

app = Flask(__name__)
ALLOWED_SORT = {"name", "created"}


def db():
    return sqlite3.connect("reports.db")


@app.route("/reports")
def list_reports():
    owner = request.args.get("owner", "")
    cur = db().cursor()
    cur.execute("SELECT * FROM reports WHERE owner = '" + owner + "'")  # vuln: sqli
    return {"rows": cur.fetchall()}


@app.route("/reports/search")
def search_reports():
    term = request.args["q"]
    query = f"SELECT id FROM reports WHERE title LIKE '%{term}%'"
    return {"rows": db().execute(query).fetchall()}  # vuln: sqli


@app.route("/reports/<report_id>")
def show_report(report_id):
    cur = db().cursor()
    cur.execute("SELECT * FROM reports WHERE id = %s" % report_id)  # vuln: sqli
    return {"row": cur.fetchone()}


@app.route("/reports/by-year")
def by_year():
    year = int(request.args.get("year", "2024"))
    cur = db().cursor()
    cur.execute(f"SELECT * FROM reports WHERE year = {year}")  # safe: sqli
    return {"rows": cur.fetchall()}


@app.route("/reports/by-owner")
def by_owner():
    owner = request.args.get("owner", "")
    cur = db().cursor()
    cur.execute("SELECT * FROM reports WHERE owner = ?", (owner,))  # safe: sqli
    return {"rows": cur.fetchall()}


@app.route("/reports/sorted")
def sorted_reports():
    column = request.args.get("sort", "name")
    if column not in ALLOWED_SORT:
        return {"error": "bad sort"}, 400
    cur = db().cursor()
    cur.execute(f"SELECT * FROM reports ORDER BY {column}")  # safe: sqli
    return {"rows": cur.fetchall()}


@app.route("/reports/count")
def count_reports():
    table = "reports"
    cur = db().cursor()
    cur.execute("SELECT COUNT(*) FROM " + table)  # safe: sqli
    return {"count": cur.fetchone()[0]}


@app.route("/reports/filter", methods=["POST"])
def filter_reports():
    filters = request.get_json()
    clauses = []
    for key, value in filters.items():
        clauses.append(f"{key} = '{value}'")
    where = " AND ".join(clauses)
    cur = db().cursor()
    cur.execute("SELECT * FROM reports WHERE " + where)  # vuln: sqli
    return {"rows": cur.fetchall()}
