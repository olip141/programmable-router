#!/usr/bin/env python3
"""Aggregate evalpcap CSV summaries and NDJSON metrics files."""
import csv
import json
import sys
from pathlib import Path


def summarize_csv(path: Path) -> None:
    rows = list(csv.DictReader(path.open()))
    match = [r for r in rows if r.get("match") in ("0", "1")]
    ok = sum(1 for r in match if r.get("match") == "1")
    print(f"{path.name}: rows={len(rows)} compared={len(match)} accuracy={ok/len(match) if match else 0:.3f}")


def summarize_ndjson(path: Path) -> None:
    last = None
    for line in path.open():
        line = line.strip()
        if not line:
            continue
        last = json.loads(line)
    if not last:
        print(f"{path.name}: empty")
        return
    print(
        f"{path.name}: packets={last.get('Packets')} p50_handle_ns={last.get('HandleNsP50')} "
        f"rss={last.get('RSSBytes')} classified={last.get('FlowsClassified')}"
    )


def main() -> None:
    if len(sys.argv) < 2:
        print("usage: summarize.py <file-or-dir>", file=sys.stderr)
        sys.exit(2)
    root = Path(sys.argv[1])
    paths = [root] if root.is_file() else sorted(root.glob("*"))
    for p in paths:
        if p.suffix == ".csv":
            summarize_csv(p)
        elif p.suffix in (".ndjson", ".jsonl"):
            summarize_ndjson(p)


if __name__ == "__main__":
    main()
