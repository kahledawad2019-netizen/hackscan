"""Data-access helpers called from `sqli/api.py` (cross-file flows)."""

import sqlite3

CONN = sqlite3.connect(":memory:")


def find_user(name):
    cur = CONN.cursor()
    cur.execute("SELECT * FROM users WHERE name = '%s'" % name)  # vuln: sqli
    return cur.fetchone()


def find_user_safely(name):
    cur = CONN.cursor()
    cur.execute("SELECT * FROM users WHERE name = ?", (name,))  # safe: sqli
    return cur.fetchone()


def delete_user(user_id):
    CONN.execute(f"DELETE FROM users WHERE id = {user_id}")  # safe: sqli


def archive(table):
    CONN.execute("INSERT INTO archive SELECT * FROM " + table)  # safe: sqli
