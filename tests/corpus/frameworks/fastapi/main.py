import os
import sqlite3

from fastapi import FastAPI, Request

app = FastAPI()
conn = sqlite3.connect("app.db")


@app.get("/items/{item_id}")
def read_item(item_id: str):
    return conn.execute(f"SELECT * FROM items WHERE id = {item_id}").fetchall()  # expect: HS-SQLI-001!


@app.post("/run")
async def run(request: Request):
    body = await request.json()
    os.system(body["cmd"])  # expect: HS-CMDI-001!


@app.get("/search")
def search(q: str = ""):
    sql = "SELECT * FROM items WHERE name = '" + q + "'"
    return conn.execute(sql).fetchall()  # expect: HS-SQLI-001!


@app.get("/count")
def count(limit: int = 10):
    n = int(limit)
    return conn.execute(f"SELECT * FROM items LIMIT {n}").fetchall()  # expect-suppressed: HS-SQLI-001 taint:sanitized
