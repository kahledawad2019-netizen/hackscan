import hashlib
import os
import sqlite3

from flask import Flask, request

app = Flask(__name__)
db = sqlite3.connect("app.db")
API_TOKEN = "hackscan-fake-token-0123456789"


@app.route("/user")
def user():
    uid = request.args.get("id")
    return db.execute(f"SELECT * FROM users WHERE id = {uid}").fetchall()


@app.route("/ping")
def ping():
    os.system("ping -c 1 " + request.args["host"])


def checksum(data):
    return hashlib.md5(data).hexdigest()
