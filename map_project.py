#!/usr/bin/env python3
import os
import re
import ast
import json
import argparse
from collections import defaultdict, Counter
from pathlib import Path

PY_EXTENSIONS = {".py"}

TECHNIQUE_PATTERNS = {
    "recon": [r"\brecon\b", r"\bsubdomain\b", r"\blive host\b", r"\benumerat"],
    "crawl": [r"\bcrawl\b", r"\bspider\b", r"\bkatana\b", r"\bgau\b", r"\bwayback\b"],
    "js_hunting": [r"\bjavascript\b", r"\bjs_hunter\b", r"\bjs endpoint\b"],
    "param_mining": [r"\bparam\b", r"\bparameter\b", r"\barjun\b", r"\bparam_mine\b"],
    "auth_testing": [r"\bauth\b", r"\blogin\b", r"\bsession\b", r"\bcredential\b"],
    "classification": [r"\bclassif", r"\bclassifier\b"],
    "ranking": [r"\brank", r"\bscore", r"\bpriority"],
    "fuzzing": [r"\bfuzz", r"\bffuf\b", r"\bmutation\b", r"\bpayload\b"],
    "exploitation": [r"\bexploit\b", r"\brce\b", r"\bsqli\b", r"\bxss\b", r"\blfi\b", r"\bssrf\b"],
    "chain_planning": [r"\bchain\b", r"\bplanner\b", r"\battack graph\b"],
    "cve_analysis": [r"\bcve\b", r"\bnvd\b", r"\bvulnerability\b"],
    "ai_reasoning": [r"\bgroq\b", r"\bopenrouter\b", r"\bllm\b", r"\bai\b", r"\banalyzer\b"],
    "reporting": [r"\breport\b", r"\bmarkdown\b", r"\bjson dump\b"],
    "wordpress": [r"\bwordpress\b", r"\bwp\b", r"\bwpscan\b"],
    "network_tools": [r"\bnmap\b", r"\bhttpx\b", r"\bnikto\b", r"\bsubfinder\b", r"\bassetfinder\b"],
}

PHASE_HINTS = [
    "recon", "live", "wp", "toolkit", "crawl", "wp_detect_state",
    "js_hunter", "param_mine", "auth", "ml_classify", "classify", "rank",
    "fuzz", "exploit", "cve", "report", "chain", "selector"
]

DANGEROUS_CALLS = [
    "subprocess.run", "subprocess.Popen", "os.system",
    "requests.get", "requests.post", "httpx.get", "httpx.post"
]

def is_python_file(path: Path) -> bool:
    return path.suffix in PY_EXTENSIONS

def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return ""

def normalize_module(root: Path, path: Path) -> str:
    rel = path.relative_to(root).with_suffix("")
    return ".".join(rel.parts)

class FileAnalyzer(ast.NodeVisitor):
    def __init__(self, module_name: str, source: str):
        self.module_name = module_name
        self.source = source
        self.imports = []
        self.from_imports = []
        self.classes = []
        self.functions = []
        self.methods = []
        self.calls = []
        self.env_vars = []
        self.loggers = []
        self.strings = []
        self.current_class = None
        self.current_function = None

    def visit_Import(self, node):
        for alias in node.names:
            self.imports.append(alias.name)
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        mod = node.module or ""
        for alias in node.names:
            self.from_imports.append(f"{mod}.{alias.name}" if mod else alias.name)
        self.generic_visit(node)

    def visit_ClassDef(self, node):
        self.classes.append(node.name)
        prev = self.current_class
        self.current_class = node.name
        self.generic_visit(node)
        self.current_class = prev

    def visit_FunctionDef(self, node):
        fn = node.name
        if self.current_class:
            self.methods.append(f"{self.current_class}.{fn}")
        else:
            self.functions.append(fn)
        prev = self.current_function
        self.current_function = fn
        self.generic_visit(node)
        self.current_function = prev

    def visit_AsyncFunctionDef(self, node):
        self.visit_FunctionDef(node)

    def visit_Call(self, node):
        name = self._get_call_name(node.func)
        if name:
            caller = self.current_function or "<module>"
            if self.current_class:
                caller = f"{self.current_class}.{caller}"
            self.calls.append({"caller": caller, "callee": name, "lineno": getattr(node, "lineno", None)})
        self.generic_visit(node)

    def visit_Assign(self, node):
        try:
            if isinstance(node.value, ast.Call):
                name = self._get_call_name(node.value.func)
                if name == "logging.getLogger" and node.targets:
                    for t in node.targets:
                        if isinstance(t, ast.Name):
                            self.loggers.append(t.id)
        except Exception:
            pass
        self.generic_visit(node)

    def visit_Constant(self, node):
        if isinstance(node.value, str):
            self.strings.append(node.value)
            if "os.environ.get(" in self.source:
                pass
        self.generic_visit(node)

    def visit_Subscript(self, node):
        self.generic_visit(node)

    def _get_call_name(self, node):
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            parts = []
            cur = node
            while isinstance(cur, ast.Attribute):
                parts.append(cur.attr)
                cur = cur.value
            if isinstance(cur, ast.Name):
                parts.append(cur.id)
            return ".".join(reversed(parts))
        return None

def extract_env_vars(text: str):
    patterns = [
        r'os\.environ\.get\(\s*[\'"]([^\'"]+)[\'"]',
        r'os\.getenv\(\s*[\'"]([^\'"]+)[\'"]',
    ]
    out = set()
    for p in patterns:
        for m in re.finditer(p, text):
            out.add(m.group(1))
    return sorted(out)

def extract_phase_hits(text: str):
    found = set()
    lower = text.lower()
    for p in PHASE_HINTS:
        if p in lower:
            found.add(p)
    for m in re.finditer(r'phase[s]?\s*[:=]\s*[\'"]([^\'"]+)[\'"]', text, re.I):
        found.add(m.group(1).strip())
    return sorted(found)

def extract_subprocess_tools(text: str):
    tools = set()
    patterns = [
        r'subprocess\.(?:run|Popen)\((.*?)\)',
        r'os\.system\((.*?)\)',
    ]
    known = [
        "nmap", "httpx", "wpscan", "nikto", "sqlmap", "ffuf",
        "subfinder", "assetfinder", "katana", "gau", "waybackurls",
        "nuclei", "curl", "python", "bash"
    ]
    for k in known:
        if re.search(rf"\b{k}\b", text):
            tools.add(k)
    return sorted(tools)

def classify_techniques(text: str):
    hits = {}
    for tech, patterns in TECHNIQUE_PATTERNS.items():
        count = 0
        for p in patterns:
            count += len(re.findall(p, text, re.I))
        if count:
            hits[tech] = count
    return hits

def find_crash_signals(text: str):
    patterns = [
        r"try\s*:",
        r"except\s+Exception",
        r"except\s+[A-Za-z_][A-Za-z0-9_]*",
        r"timeout",
        r"NoneType",
        r"KeyError",
        r"AttributeError",
        r"json\.loads",
        r"json\.dumps",
        r"\.get\(",
        r"raise\s+",
        r"logger\.(?:error|exception|warning)",
    ]
    result = {}
    for p in patterns:
        result[p] = len(re.findall(p, text, re.I))
    return result

def build_tree(root: Path):
    lines = []
    for path, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in {".git", "__pycache__", "node_modules", "venv", ".venv", ".idea", ".mypy_cache", ".pytest_cache"}]
        level = len(Path(path).relative_to(root).parts)
        indent = "  " * level
        lines.append(f"{indent}{Path(path).name}/")
        for f in sorted(files):
            lines.append(f"{indent}  {f}")
    return lines

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("root", help="Project root")
    ap.add_argument("--out", default="project_map_output", help="Output dir")
    args = ap.parse_args()

    root = Path(args.root).resolve()
    out = Path(args.out).resolve()
    out.mkdir(parents=True, exist_ok=True)

    summary = {
        "root": str(root),
        "files": {},
        "modules": {},
        "imports_graph": defaultdict(list),
        "call_graph": defaultdict(list),
        "techniques": Counter(),
        "phases": Counter(),
        "env_vars": Counter(),
        "tools": Counter(),
        "crash_signals": {},
        "entrypoints": [],
    }

    tree_lines = build_tree(root)

    py_files = []
    for p in root.rglob("*"):
        if p.is_file() and is_python_file(p):
            if any(part in {".git", "__pycache__", "node_modules", "venv", ".venv"} for part in p.parts):
                continue
            py_files.append(p)

    for path in sorted(py_files):
        text = read_text(path)
        rel = str(path.relative_to(root))
        mod = normalize_module(root, path)

        file_data = {
            "module": mod,
            "classes": [],
            "functions": [],
            "methods": [],
            "imports": [],
            "from_imports": [],
            "phases": extract_phase_hits(text),
            "env_vars": extract_env_vars(text),
            "tools": extract_subprocess_tools(text),
            "techniques": classify_techniques(text),
            "crash_signals": find_crash_signals(text),
        }

        try:
            tree = ast.parse(text)
            analyzer = FileAnalyzer(mod, text)
            analyzer.visit(tree)
            file_data["classes"] = analyzer.classes
            file_data["functions"] = analyzer.functions
            file_data["methods"] = analyzer.methods
            file_data["imports"] = analyzer.imports
            file_data["from_imports"] = analyzer.from_imports

            for imp in analyzer.imports + analyzer.from_imports:
                summary["imports_graph"][mod].append(imp)

            for call in analyzer.calls:
                summary["call_graph"][call["caller"]].append({
                    "module": mod,
                    "callee": call["callee"],
                    "lineno": call["lineno"]
                })
        except SyntaxError as e:
            file_data["syntax_error"] = str(e)

        for k, v in file_data["techniques"].items():
            summary["techniques"][k] += v
        for p in file_data["phases"]:
            summary["phases"][p] += 1
        for ev in file_data["env_vars"]:
            summary["env_vars"][ev] += 1
        for t in file_data["tools"]:
            summary["tools"][t] += 1

        if re.search(r'if\s+__name__\s*==\s*[\'"]__main__[\'"]', text):
            summary["entrypoints"].append(rel)

        summary["files"][rel] = file_data
        summary["modules"][mod] = rel

    summary["imports_graph"] = dict(summary["imports_graph"])
    summary["call_graph"] = dict(summary["call_graph"])
    summary["techniques"] = dict(summary["techniques"])
    summary["phases"] = dict(summary["phases"])
    summary["env_vars"] = dict(summary["env_vars"])
    summary["tools"] = dict(summary["tools"])

    with open(out / "project_map.json", "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)

    md = []
    md.append(f"# Project Map\n")
    md.append(f"## Root\n`{root}`\n")

    md.append("## Entrypoints")
    for x in summary["entrypoints"] or ["(none found)"]:
        md.append(f"- `{x}`")
    md.append("")

    md.append("## Detected Techniques")
    for k, v in sorted(summary["techniques"].items(), key=lambda x: (-x[1], x[0])):
        md.append(f"- **{k}**: {v}")
    md.append("")

    md.append("## Detected Phases")
    for k, v in sorted(summary["phases"].items(), key=lambda x: (-x[1], x[0])):
        md.append(f"- **{k}**: {v} files")
    md.append("")

    md.append("## Detected External Tools")
    for k, v in sorted(summary["tools"].items(), key=lambda x: (-x[1], x[0])):
        md.append(f"- **{k}**: {v}")
    md.append("")

    md.append("## Environment Variables")
    for k, v in sorted(summary["env_vars"].items(), key=lambda x: (-x[1], x[0])):
        md.append(f"- **{k}**: {v} files")
    md.append("")

    md.append("## File Tree")
    md.append("```text")
    md.extend(tree_lines)
    md.append("```")
    md.append("")

    md.append("## File Breakdown")
    for rel, info in summary["files"].items():
        md.append(f"### `{rel}`")
        md.append(f"- Module: `{info['module']}`")
        if info.get("classes"):
            md.append(f"- Classes: {', '.join(f'`{x}`' for x in info['classes'])}")
        if info.get("functions"):
            md.append(f"- Functions: {', '.join(f'`{x}`' for x in info['functions'][:30])}")
        if info.get("methods"):
            md.append(f"- Methods: {', '.join(f'`{x}`' for x in info['methods'][:40])}")
        if info.get("imports"):
            md.append(f"- Imports: {', '.join(f'`{x}`' for x in info['imports'][:20])}")
        if info.get("from_imports"):
            md.append(f"- From imports: {', '.join(f'`{x}`' for x in info['from_imports'][:20])}")
        if info.get("phases"):
            md.append(f"- Phase hints: {', '.join(f'`{x}`' for x in info['phases'])}")
        if info.get("tools"):
            md.append(f"- External tools: {', '.join(f'`{x}`' for x in info['tools'])}")
        if info.get("env_vars"):
            md.append(f"- Env vars: {', '.join(f'`{x}`' for x in info['env_vars'])}")
        if info.get("techniques"):
            md.append("- Technique scores:")
            for tk, tv in sorted(info["techniques"].items(), key=lambda x: (-x[1], x[0])):
                md.append(f"  - {tk}: {tv}")
        if info.get("syntax_error"):
            md.append(f"- Syntax error: `{info['syntax_error']}`")
        md.append("")

    with open(out / "project_map.md", "w", encoding="utf-8") as f:
        f.write("\n".join(md))

    mermaid = []
    mermaid.append("graph TD")
    for mod, imports in summary["imports_graph"].items():
        safe_mod = mod.replace(".", "_").replace("-", "_")
        for imp in imports[:30]:
            safe_imp = imp.replace(".", "_").replace("-", "_")
            mermaid.append(f'    {safe_mod}["{mod}"] --> {safe_imp}["{imp}"]')

    with open(out / "imports_graph.mmd", "w", encoding="utf-8") as f:
        f.write("\n".join(mermaid))

    call_md = ["# Simplified Call Graph\n", "```text"]
    for caller, callees in sorted(summary["call_graph"].items()):
        targets = [c["callee"] for c in callees]
        top = Counter(targets).most_common(15)
        call_md.append(f"{caller}")
        for name, cnt in top:
            call_md.append(f"  -> {name} ({cnt})")
        call_md.append("")
    call_md.append("```")

    with open(out / "call_graph.md", "w", encoding="utf-8") as f:
        f.write("\n".join(call_md))

    print(f"[+] Done. Output: {out}")
    print(f"[+] JSON: {out / 'project_map.json'}")
    print(f"[+] Markdown: {out / 'project_map.md'}")
    print(f"[+] Mermaid: {out / 'imports_graph.mmd'}")
    print(f"[+] Call graph: {out / 'call_graph.md'}")

if __name__ == "__main__":
    main()
