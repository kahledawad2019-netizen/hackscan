"""Plugin loading from the command line."""

import sys


def load_plugin(path):
    with open(path, encoding="utf-8") as handle:
        source = handle.read()
    exec(source, {"__name__": "plugin"})  # vuln: codei


def run_hook(hooks, name):
    hook_code = hooks.get(name, "pass")
    exec(hook_code)  # vuln: codei


DEFAULT_HOOKS = {"start": "print('starting')"}


def main():
    load_plugin(sys.argv[1])
    run_hook(DEFAULT_HOOKS, "start")
    run_hook({"custom": sys.argv[2]}, "custom")


if __name__ == "__main__":
    main()
