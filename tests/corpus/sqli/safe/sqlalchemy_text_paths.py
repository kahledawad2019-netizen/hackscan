from sqlalchemy.sql.expression import text


def order_by_constant(query):
    return query.order_by(text("title asc"))


def bound_value(session, name):
    return session.execute(text("SELECT * FROM t WHERE n = :n"), {"n": name})


def constant_keyword(session):
    return session.execute(text(text="SELECT 1"))
