from sqlalchemy import text


def parameterized(cur, user_id):
    cur.execute("SELECT * FROM users WHERE id = ?", (user_id,))


def parameterized_named(cur, name):
    cur.execute("SELECT * FROM users WHERE name = %(name)s", {"name": name})


def constant_fstring(cur):
    cur.execute(f"SELECT 1")


def constant_variable(cur):
    query = "SELECT * FROM users"
    cur.execute(query)


def constant_concat(cur):
    cur.execute("SELECT * " + "FROM users")


def sqlalchemy_bound(session, name):
    return session.execute(text("SELECT * FROM t WHERE n = :n"), {"n": name})


def not_sql(executor, job):
    # `.execute` on something with a non-string arg is not SQL formatting
    executor.execute(job)


def logging_format(log, user):
    log.info("user %s logged in" % user)
