"""A small operations CLI."""

import os
import shlex
import subprocess
import sys


def ping(host):
    os.system("ping -c 1 " + host)  # vuln: cmdi


def disk_usage(path):
    return subprocess.check_output(f"du -sh {path}", shell=True)  # vuln: cmdi


def tail_log(name):
    return subprocess.run(["tail", "-n", "50", name], capture_output=True)  # safe: cmdi


def compress(path):
    subprocess.call("tar czf backup.tgz " + shlex.quote(path), shell=True)  # safe: cmdi


def restart(service):
    allowed = {"nginx", "redis"}
    if service not in allowed:
        raise SystemExit("unknown service")
    os.system(f"systemctl restart {service}")  # safe: cmdi


def uptime():
    os.system("uptime")  # safe: cmdi


def main(argv):
    command, target = argv[1], argv[2]
    if command == "ping":
        ping(target)
    elif command == "du":
        print(disk_usage(target))
    elif command == "tail":
        print(tail_log(target).stdout)
    elif command == "backup":
        compress(target)
    elif command == "restart":
        restart(target)
    else:
        uptime()


if __name__ == "__main__":
    main(sys.argv)
