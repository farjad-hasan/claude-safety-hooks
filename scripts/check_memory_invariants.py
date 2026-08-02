#!/usr/bin/env python3
"""Check memory-index invariants: dead links, dead wikilinks, stale counts.

Usage: check_memory_invariants.py <file>
Exit 0 = clean or not an index file. Exit 2 = violations (listed on stderr).
"""
import re
import sys
from pathlib import Path

INDEX_NAMES = {"MEMORY.md", "INDEX.md"}
MD_LINK = re.compile(r"\[[^\]]*\]\(([^)#\s]+\.md)\)")
WIKILINK = re.compile(r"\[\[([^\]|#]+?)(?:\|[^\]]*)?\]\]")
COUNT_NOTE = re.compile(r"<!--\s*invariant-count:\s*(\S+)\s*-->")


def check(path: Path) -> list[str]:
    if path.name not in INDEX_NAMES:
        return []
    problems = []
    base = path.parent
    text = path.read_text(encoding="utf-8", errors="replace")

    for target in MD_LINK.findall(text):
        if not (base / target).exists():
            problems.append(f"dead link: ({target})")

    for name in WIKILINK.findall(text):
        name = name.strip()
        if not (base / f"{name}.md").exists() and not list(base.glob(f"**/{name}.md")):
            problems.append(f"dead wikilink: [[{name}]]")

    for line in text.splitlines():
        m = COUNT_NOTE.search(line)
        if not m:
            continue
        nums = re.findall(r"\b(\d+)\b", COUNT_NOTE.sub("", line))
        actual = len(list(base.glob(m.group(1))))
        if len(nums) != 1:
            problems.append(f"count line needs exactly one number: {line.strip()}")
        elif int(nums[0]) != actual:
            problems.append(
                f"stale count: line claims {nums[0]}, glob '{m.group(1)}' matches {actual}")
    return problems


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: check_memory_invariants.py <file>", file=sys.stderr)
        return 2
    path = Path(sys.argv[1])
    if not path.exists():
        return 0
    problems = check(path)
    if problems:
        print(f"Memory invariant violations in {path.name}:", file=sys.stderr)
        for p in problems:
            print(f"  - {p}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
