"""Backup helpers; `cmdi/scheduler.py` calls them (cross-file flows)."""

import subprocess


def snapshot(label):
    subprocess.run("zfs snapshot tank@" + label, shell=True)  # vuln: cmdi


def prune(keep):
    subprocess.run(f"zfs-prune --keep {keep}", shell=True)  # safe: cmdi


def notify(message):
    subprocess.run(["logger", message])  # safe: cmdi
