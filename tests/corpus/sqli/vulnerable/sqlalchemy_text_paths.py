from flask import request
from sqlalchemy.sql import expression
from sqlalchemy.sql.expression import text


def order_by_text(query, sort, order):
    return query.order_by(text(sort + " " + order))  # expect: HS-SQLI-001


def order_by_text_list(query, sort, order):
    return query.order_by(*[text(f"{sort} {order}")])  # expect: HS-SQLI-001


def expression_module_text(session, name):
    return session.execute(expression.text("SELECT * FROM t WHERE n = '" + name + "'"))  # expect: HS-SQLI-001


def text_keyword(session):
    return session.execute(text(text=request.args["q"]))  # expect: HS-SQLI-001


def text_unpacked(session, args):
    return session.execute(text(*args))  # expect: HS-SQLI-001


def text_unpacked_keywords(session, options):
    return session.execute(text(**options))  # expect: HS-SQLI-001
