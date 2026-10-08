from sqlalchemy import text


def parameterized(cur, user_id):
    cur.execute("SELECT * FROM users WHERE id = ?", (user_id,))


def parameterized_named(cur, name):
    cur.execute("SELECT * FROM users WHERE name = %(name)s", {"name": name})


def constant_fstring(cur):
    cur.execute(f"SELECT 1")


def constant_variable(cur):
    query = "SELECT * FROM users"
    cur.execute(query)  # expect-suppressed: VH-SQLI-001 taint:constant_input


def constant_concat(cur):
    cur.execute("SELECT * " + "FROM users")


def sqlalchemy_bound(session, name):
    return session.execute(text("SELECT * FROM t WHERE n = :n"), {"n": name})


def not_sql(executor, job):
    # `.execute` on something with a non-string arg is not SQL formatting
    executor.execute(job)


def logging_format(log, user):
    log.info("user %s logged in" % user)


def later_constant(cur, user):
    query = "SELECT * FROM users WHERE name = '%s'" % user
    query = "SELECT 1"
    cur.execute(query)  # expect-suppressed: VH-SQLI-001 taint:constant_input


def job_runner(executor, user):
    # dynamic string, but neither a DB receiver nor SQL text
    executor.execute("job:" + user)


def lookalike_module(sqlite3evil, query):
    # `sqlite3evil` is not sqlite3: prefix matching must respect module boundaries
    sqlite3evil.connect().execute(query)
