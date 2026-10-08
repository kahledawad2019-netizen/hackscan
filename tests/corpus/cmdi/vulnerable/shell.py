import os
import subprocess
import subprocess as sp
from os import system


def os_system(host):
    os.system("ping -c 1 " + host)  # expect: HS-CMDI-001


def os_popen(path):
    return os.popen(f"ls {path}").read()  # expect: HS-CMDI-001


def from_import(name):
    system(f"echo {name}")  # expect: HS-CMDI-001


def shell_true(filename):
    subprocess.run(f"cat {filename}", shell=True)  # expect: HS-CMDI-001


def aliased_module(cmd):
    sp.check_output(cmd, shell=True)  # expect: HS-CMDI-001


def via_variable(branch):
    command = "git checkout " + branch
    subprocess.call(command, shell=True)  # expect: HS-CMDI-001


def getoutput(arg):
    return subprocess.getoutput("du -sh " + arg)  # expect: HS-CMDI-001


def keyword_args(target):
    subprocess.Popen(args="rm -rf " + target, shell=True)  # expect: HS-CMDI-001


def dead_constant_branch(cmd):
    if False:
        cmd = "ls"
    os.system(cmd)  # expect: HS-CMDI-001


def import_fallback(cmd):
    try:
        import subprocess as proc
    except ImportError:
        proc = None
    proc.run(cmd, shell=True)  # expect: HS-CMDI-001
