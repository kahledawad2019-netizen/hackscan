"""Network diagnostics exposed over HTTP."""

import os
import subprocess

from flask import Flask, request

app = Flask(__name__)


@app.route("/lookup")
def lookup():
    domain = request.args.get("domain", "")
    out = os.popen("nslookup " + domain).read()  # vuln: cmdi
    return {"out": out}


@app.route("/trace", methods=["POST"])
def trace():
    target = request.form["target"]
    args = "traceroute -m 5 {}".format(target)
    proc = subprocess.Popen(args, shell=True, stdout=subprocess.PIPE)  # vuln: cmdi
    return {"out": proc.communicate()[0].decode()}


@app.route("/whois")
def whois():
    domain = request.args.get("domain", "")
    proc = subprocess.run(["whois", domain], capture_output=True, text=True)  # safe: cmdi
    return {"out": proc.stdout}


@app.route("/port")
def port_check():
    port = int(request.args.get("port", "80"))
    code = os.system(f"nc -z localhost {port}")  # safe: cmdi
    return {"open": code == 0}


class Job:
    """Stores the command on the instance and runs it later."""

    def __init__(self, cmd):
        self.cmd = cmd

    def run(self):
        return subprocess.getoutput(self.cmd)  # vuln: cmdi


@app.route("/job")
def job():
    return {"out": Job("convert " + request.args["file"]).run()}
