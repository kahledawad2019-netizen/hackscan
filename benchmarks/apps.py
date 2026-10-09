"""Scan known-vulnerable public Python apps and score tools against a hand review.

Each app is fetched at a pinned commit (only its `.py` files are extracted; nothing is
executed) into `benchmarks/.cache/`. Every tool's reports are reduced to distinct
(file, function, class) keys, as in `run.py`. `apps_review.json` records a verdict for
each key that any tool reported: "tp" (a real, reachable vulnerability of that class)
or "fp", with a short note; a "vuln" id groups keys that are the same vulnerability
reported at different places. There is no complete ground truth for these apps, so
recall is relative: the share of all distinct true positives (found by any tool) a tool
found. Metrics are only published for complete reviews.

Usage: `uv run python benchmarks/apps.py [--tools ...] [--list-unreviewed]`.
"""

from __future__ import annotations

import argparse
import io
import json
import shutil
import sys
import tarfile
import urllib.request
from pathlib import Path, PurePosixPath

sys.path.insert(0, str(Path(__file__).resolve().parent))

import run as bench  # noqa: E402

HERE = Path(__file__).resolve().parent
CACHE = HERE / ".cache"
REVIEW = HERE / "apps_review.json"
APPS = {
    "vulpy": ("fportantier/vulpy", "5249cc8b05a1c37f6b2f757b1cf16a509c327122"),
    "pygoat": ("adeyosemanputra/pygoat", "19d17cc8874861142b330636d068bbde54e86b85"),
    "dvpwa": ("anxolerd/dvpwa", "a1d8f89fac2e57093189853c6527c2b01fc1d9c1"),
}
MAX_DOWNLOAD = 200 * 1024 * 1024  # compressed archive
MAX_FILE = 5 * 1024 * 1024  # one extracted .py file
MAX_TOTAL = 100 * 1024 * 1024  # all extracted files
Key = tuple[str, str, str]


def safe_member_path(name: str) -> tuple[str, ...] | None:
    """Path parts below the archive's top directory, or None if the name could escape the
    extraction directory on any platform (absolute, `..`, backslashes, drive letters)."""
    if "\\" in name or ":" in name or "\0" in name or name.startswith("/"):
        return None
    raw = name.split("/")  # validated before any normalization
    if any(p in (".", "..") for p in raw) or "" in raw[:-1]:
        return None
    parts = PurePosixPath(name).parts[1:]  # drop `<repo>-<sha>/`
    return parts or None


def extract_python(data: bytes, target: Path) -> None:
    """Extract the `.py` regular files of a .tar.gz into a fresh `target` directory."""
    staging = target.with_name(target.name + ".partial")
    shutil.rmtree(staging, ignore_errors=True)
    staging.mkdir(parents=True)
    root = staging.resolve()
    total = 0
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        for member in archive.getmembers():
            parts = safe_member_path(member.name)
            if not member.isfile() or parts is None or not parts[-1].endswith(".py"):
                continue  # links, devices, directories and unsafe names are skipped
            if member.size > MAX_FILE:
                raise RuntimeError(f"{member.name}: larger than {MAX_FILE} bytes")
            total += member.size
            if total > MAX_TOTAL:
                raise RuntimeError(f"archive expands beyond {MAX_TOTAL} bytes")
            out = staging.joinpath(*parts)
            if not out.resolve().is_relative_to(root):
                raise RuntimeError(f"{member.name}: escapes the extraction directory")
            source = archive.extractfile(member)
            if source is None:
                continue
            content = source.read(MAX_FILE + 1)
            if len(content) > MAX_FILE:
                raise RuntimeError(f"{member.name}: larger than {MAX_FILE} bytes")
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_bytes(content)
    staging.rename(target)


def fetch(name: str) -> Path:
    """The app's `.py` files at the pinned commit (downloaded once)."""
    repo, sha = APPS[name]
    target = CACHE / f"{name}-{sha[:12]}"
    if target.is_dir():
        return target
    url = f"https://codeload.github.com/{repo}/tar.gz/{sha}"
    with urllib.request.urlopen(url, timeout=120) as response:  # noqa: S310 (fixed host)
        data = response.read(MAX_DOWNLOAD + 1)
    if len(data) > MAX_DOWNLOAD:
        raise RuntimeError(f"{name}: archive larger than {MAX_DOWNLOAD} bytes")
    extract_python(data, target)
    return target


def keys(root: Path, reports: list[bench.Report]) -> set[Key]:
    spans: dict[str, list[tuple[int, int, str]]] = {}
    out = set()
    for r in reports:
        if r.cls not in bench.CLASSES:
            continue
        if r.path not in spans:
            file = root / r.path
            try:
                spans[r.path] = bench.functions(file.read_text(encoding="utf-8"))
            except (OSError, SyntaxError, UnicodeDecodeError):
                spans[r.path] = []
        out.add((r.path, bench.enclosing(spans[r.path], r.line), r.cls))
    return out


def key_text(key: Key) -> str:
    return "::".join(key)


def vuln_id(verdicts: dict, key: Key) -> str:
    """A vulnerability can be reported at several keys (sink vs. source)."""
    return verdicts.get(key_text(key), {}).get("vuln", key_text(key))


def score_app(verdicts: dict, found: dict[str, set[Key]]) -> dict:
    """Per-tool counts for one app; `unreviewed` > 0 means the row has no metrics.
    Recall is relative to every tool's true positives, so one unreviewed key anywhere
    in the app leaves the shared denominator unknown (`complete` is False)."""
    every = {
        vuln_id(verdicts, k)
        for keys_ in found.values()
        for k in keys_
        if verdicts.get(key_text(k), {}).get("verdict") == "tp"
    }
    tools = {}
    for name, tool_keys in found.items():
        tp = {k for k in tool_keys if verdicts.get(key_text(k), {}).get("verdict") == "tp"}
        fp = {k for k in tool_keys if verdicts.get(key_text(k), {}).get("verdict") == "fp"}
        tools[name] = {
            "reports": len(tool_keys),
            "tp": len(tp),
            "fp": len(fp),
            "vulns": len({vuln_id(verdicts, k) for k in tp}),
            "unreviewed": len(tool_keys - tp - fp),
        }
    complete = all(t["unreviewed"] == 0 for t in tools.values())
    return {"all_vulns": len(every), "complete": complete, "tools": tools}


def totals(summary: dict) -> dict:
    """Per-tool sums over all apps (only tools that ran on every app)."""
    out: dict = {
        "all_vulns": sum(app["all_vulns"] for app in summary["apps"].values()),
        "complete": all(app.get("complete", True) for app in summary["apps"].values()),
    }
    names = [set(app["tools"]) for app in summary["apps"].values()]
    for name in sorted(set.intersection(*names)) if names else []:
        rows = [app["tools"][name] for app in summary["apps"].values()]
        out[name] = {k: sum(r[k] for r in rows) for k in rows[0]}
    return out


def _row(label: str, tool: str, counts: dict, all_vulns: int, complete: bool = True) -> str:
    if counts["unreviewed"]:
        missing = counts["unreviewed"]
        return f"| {label} | {tool} | {counts['reports']} | incomplete: {missing} unreviewed |||||"
    tp, fp, vulns = counts["tp"], counts["fp"], counts["vulns"]
    precision = f"{tp / (tp + fp):.0%}" if tp + fp else "-"
    relative = f"{vulns / all_vulns:.0%}" if all_vulns and complete else "-"
    return (
        f"| {label} | {tool} | {counts['reports']} | {tp} | {fp} | {vulns} | "
        f"{precision} | {relative} |"
    )


def total_rows(summary: dict) -> list[str]:
    """The "all apps" rows, as APPS.md and README.md show them (README drops the App
    column)."""
    sums = totals(summary)
    order = [n for n in next(iter(summary["apps"].values()))["tools"] if n in sums]
    return [
        _row("**all**", name, sums[name], sums["all_vulns"], sums["complete"]) for name in order
    ]


def render(summary: dict) -> str:
    lines = [
        "# Known-vulnerable applications",
        "",
        "Generated by `benchmarks/apps.py`. Reports are distinct (file, function, class) keys "
        "in the four benchmark classes; each was reviewed by hand (`apps_review.json`). "
        "Precision = TP / (TP + FP) over keys. A vulnerability reported at two keys (e.g. the "
        "sink helper and the view building the command) counts once under Vulns found; "
        "relative recall = vulns found / all distinct vulns any tool found (no tool sees "
        "everything, so absolute recall is unknown).",
        "",
        "| App | Tool | Reports | TP | FP | Vulns found | Precision | Relative recall |",
        "|---|---|---:|---:|---:|---:|---:|---:|",
    ]
    for app, entry in summary["apps"].items():
        for name, skipped in entry.get("skipped", {}).items():
            lines.append(f"| {app} | {name} | skipped: {skipped} |||||| ")
        for name, counts in entry["tools"].items():
            lines.append(_row(app, name, counts, entry["all_vulns"], entry.get("complete", True)))
    lines += total_rows(summary)
    lines += [
        "",
        "Apps (pinned commits): "
        + ", ".join(
            f"[{a}](https://github.com/{e['repo']}/tree/{e['commit']})"
            for a, e in summary["apps"].items()
        ),
    ]
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--tools", default=",".join(bench.TOOLS))
    parser.add_argument("--list-unreviewed", action="store_true")
    parser.add_argument("--out", type=Path, default=HERE / "APPS.md")
    args = parser.parse_args(argv)
    review = json.loads(REVIEW.read_text(encoding="utf-8")) if REVIEW.exists() else {}
    summary: dict = {"apps": {}}
    unreviewed: list[str] = []
    failed = False
    for app, (repo, sha) in APPS.items():
        root = fetch(app)
        verdicts = review.get(app, {})
        found: dict[str, set[Key]] = {}
        skipped: dict[str, str] = {}
        rules: dict[tuple[str, str], set[str]] = {}
        for tool in args.tools.split(","):
            for result in bench.TOOLS[tool](root):
                if result.skipped:
                    skipped[result.name] = result.skipped
                    failed = True
                    continue
                found[result.name] = keys(root, result.reports)
                for r in result.reports:
                    rules.setdefault((r.path, r.cls), set()).add(f"{r.line}:{r.rule}")
        entry = {"repo": repo, "commit": sha, **score_app(verdicts, found)}
        if skipped:
            entry["skipped"] = skipped
        summary["apps"][app] = entry
        for name, tool_keys in found.items():
            for k in sorted(tool_keys):
                if verdicts.get(key_text(k), {}).get("verdict") not in ("tp", "fp"):
                    rule_list = sorted(rules.get((k[0], k[2]), ()))
                    unreviewed.append(f"{app} {key_text(k)}  ({name}: {rule_list})")
    text = render(summary)
    args.out.write_text(text, encoding="utf-8")
    args.out.with_suffix(".json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(text)
    if unreviewed:
        print(
            f"\n{len(unreviewed)} unreviewed report(s); their rows have no metrics", file=sys.stderr
        )
        if args.list_unreviewed:
            print("\n".join(sorted(set(unreviewed))), file=sys.stderr)
    return 1 if unreviewed or failed else 0


if __name__ == "__main__":
    sys.exit(main())
