import sqlite3

import pandas as pd
from sqlalchemy import text


def by_fstring(conn: sqlite3.Connection, user_id):
    cur = conn.cursor()
    cur.execute(f"SELECT * FROM users WHERE id = {user_id}")  # expect: VH-SQLI-001


def by_percent(cur, name):
    cur.execute("SELECT * FROM users WHERE name = '%s'" % name)  # expect: VH-SQLI-001


def by_concat(cur, name):
    cur.execute("SELECT * FROM users WHERE name = '" + name + "'")  # expect: VH-SQLI-001


def by_format(cur, table):
    cur.executemany("INSERT INTO {} VALUES (?)".format(table), [(1,)])  # expect: VH-SQLI-001


def via_variable(cur, email):
    query = "SELECT * FROM users WHERE email = '%s'" % email
    cur.execute(query)  # expect: VH-SQLI-001


def via_augmented(cur, order):
    query = "SELECT * FROM users"
    query += " ORDER BY " + order
    cur.execute(query)  # expect: VH-SQLI-001


def multiline(cur, uid):
    cur.execute(  # expect: VH-SQLI-001
        f"""
        SELECT *
        FROM users
        WHERE id = {uid}
        """
    )


def sqlalchemy_text(session, name):
    return session.execute(text(f"SELECT * FROM t WHERE n = '{name}'"))  # expect: VH-SQLI-001


def pandas_sql(conn, region):
    return pd.read_sql("SELECT * FROM sales WHERE region = '" + region + "'", conn)  # expect: VH-SQLI-001


def django_raw(User, username):
    return User.objects.raw(f"SELECT * FROM auth_user WHERE username = '{username}'")  # expect: VH-SQLI-001
