import os
import subprocess
import subprocess as sp
from os import system


def os_system(host):
    os.system("ping -c 1 " + host)  # expect: VH-CMDI-001


def os_popen(path):
    return os.popen(f"ls {path}").read()  # expect: VH-CMDI-001


def from_import(name):
    system(f"echo {name}")  # expect: VH-CMDI-001


def shell_true(filename):
    subprocess.run(f"cat {filename}", shell=True)  # expect: VH-CMDI-001


def aliased_module(cmd):
    sp.check_output(cmd, shell=True)  # expect: VH-CMDI-001


def via_variable(branch):
    command = "git checkout " + branch
    subprocess.call(command, shell=True)  # expect: VH-CMDI-001


def getoutput(arg):
    return subprocess.getoutput("du -sh " + arg)  # expect: VH-CMDI-001


def keyword_args(target):
    subprocess.Popen(args="rm -rf " + target, shell=True)  # expect: VH-CMDI-001
