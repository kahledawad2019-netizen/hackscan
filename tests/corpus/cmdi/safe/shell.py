import os
import shlex
import subprocess


def constant_command():
    os.system("clear")


def list_args(host):
    subprocess.run(["ping", "-c", "1", host], check=True)


def shell_false(filename):
    subprocess.run(f"cat {filename}", shell=False)


def no_shell_kwarg(path):
    subprocess.check_output(["ls", path])


def constant_variable():
    cmd = "uptime"
    subprocess.call(cmd, shell=True)  # expect-suppressed: VH-CMDI-001 taint:constant_input


def quoted_list(name):
    subprocess.run(["echo", shlex.quote(name)])


def unrelated_system(machine):
    machine.system("reboot " + machine.name)


def parameter_shadows_os(os, cmd):
    os.system(cmd)  # `os` here is a parameter, not the os module


def local_import_elsewhere():
    from os import system  # noqa: F401  (binds `system` only in this function)


def unrelated_system_name(system, cmd):
    system(cmd)
