#!/usr/bin/env python3
import re
import json
import argparse
from pathlib import Path
from collections import Counter, defaultdict

PHASE_PATTERNS = [
    r"\bphase\b[:= ]+([a-zA-Z0-9_\-]+)",
    r"\bstarting\b.*?\b([a-zA-Z0-9_\-]+)\b",
    r"\brunning\b.*?\b([a-zA-Z0-9_\-]+)\b",
    r"\bcompleted\b.*?\b([a-zA-Z0-9_\-]+)\b",
    r"\bfailed\b.*?\b([a-zA-Z0-9_\-]+)\b",
]

ERROR_PATTERNS = [
    r"AttributeError: .*",
    r"KeyError: .*",
    r"TypeError: .*",
    r"NameError: .*",
    r"ValueError: .*",
    r"NoneType.*",
    r"timeout.*",
    r"ConnectionError.*",
    r"Traceback \(most recent call last\):",
]

MODULE_PATTERNS = [
    r'logger\s*=\s*logging\.getLogger\("([^"]+)"\)',
    r"\[([A-Z_]+)\]",
]

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("logfile")
    ap.add_argument("--out", default="runtime_map_output")
    args = ap.parse_args()

    logfile = Path(args.logfile)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    text = logfile.read_text(encoding="utf-8", errors="ignore")
    lines = text.splitlines()

    phase_counter = Counter()
    phase_sequence = []
    error_counter = Counter()
    module_counter = Counter()
    suspicious = []

    for i, line in enumerate(lines, 1):
        lower = line.lower()

        for p in PHASE_PATTERNS:
            for m in re.finditer(p, lower, re.I):
                phase = m.group(1)
                if len(phase) < 50:
                    phase_counter[phase] += 1
                    phase_sequence.append({"line": i, "phase": phase, "text": line[:300]})

        for p in ERROR_PATTERNS:
            m = re.search(p, line, re.I)
            if m:
                error_counter[m.group(0)] += 1
                suspicious.append({"line": i, "type": "error", "text": line[:500]})

        if "warning" in lower or "exception" in lower or "failed" in lower:
            suspicious.append({"line": i, "type": "warn/fail", "text": line[:500]})

        for p in MODULE_PATTERNS:
            for m in re.finditer(p, line):
                module_counter[m.group(1)] += 1

    data = {
        "logfile": str(logfile),
        "phases": dict(phase_counter),
        "phase_sequence": phase_sequence[:2000],
        "errors": dict(error_counter),
        "module_hits": dict(module_counter),
        "suspicious": suspicious[:2000],
    }

    with open(out / "runtime_map.json", "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    md = []
    md.append("# Runtime Map\n")
    md.append(f"## Log file\n`{logfile}`\n")

    md.append("## Phase frequency")
    for k, v in phase_counter.most_common():
        md.append(f"- **{k}**: {v}")
    md.append("")

    md.append("## Errors")
    for k, v in error_counter.most_common():
        md.append(f"- **{k}**: {v}")
    md.append("")

    md.append("## Top module/log tags")
    for k, v in module_counter.most_common(50):
        md.append(f"- **{k}**: {v}")
    md.append("")

    md.append("## First suspicious events")
    md.append("```text")
    for item in suspicious[:200]:
        md.append(f"[line {item['line']}] {item['type']}: {item['text']}")
    md.append("```")

    with open(out / "runtime_map.md", "w", encoding="utf-8") as f:
        f.write("\n".join(md))

    print(f"[+] Done. Output: {out}")
    print(f"[+] JSON: {out / 'runtime_map.json'}")
    print(f"[+] Markdown: {out / 'runtime_map.md'}")

if __name__ == "__main__":
    main()
