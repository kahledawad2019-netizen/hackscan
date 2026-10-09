"""Reads the snapshot label from stdin and calls `backup` (cross-file flows)."""

from cmdi import backup


def run_once():
    label = input("snapshot label: ")
    backup.snapshot(label)
    backup.prune(7)
    backup.notify("snapshot " + label)
