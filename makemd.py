import os
import ast
from collections import defaultdict

ROOT = "."

IGNORE = {
    "__pycache__",
    "venv",
    ".venv",
    "env",
    ".git",
    "results",
    "data"
}


class CodeAnalyzer(ast.NodeVisitor):

    def __init__(self):
        self.calls = defaultdict(list)
        self.imports = []
        self.current = None

    def visit_FunctionDef(self, node):

        prev = self.current
        self.current = node.name

        self.generic_visit(node)

        self.current = prev

    def visit_Call(self, node):

        if self.current:

            if isinstance(node.func, ast.Name):
                self.calls[self.current].append(node.func.id)

            elif isinstance(node.func, ast.Attribute):
                self.calls[self.current].append(node.func.attr)

        self.generic_visit(node)

    def visit_Import(self, node):
        for n in node.names:
            self.imports.append(n.name)

    def visit_ImportFrom(self, node):
        if node.module:
            self.imports.append(node.module)


def scan():

    results = {}

    for root, dirs, files in os.walk(ROOT):

        dirs[:] = [d for d in dirs if d not in IGNORE]

        for f in files:

            if not f.endswith(".py"):
                continue

            path = os.path.join(root, f)

            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as file:
                    tree = ast.parse(file.read())
            except:
                continue

            analyzer = CodeAnalyzer()
            analyzer.visit(tree)

            results[path] = analyzer

    return results


def detect_tools(results):

    tools = defaultdict(list)

    for file, analyzer in results.items():

        for imp in analyzer.imports:

            if "runner" in imp or "scan" in imp or "nuclei" in imp:
                tools[file].append(imp)

    return tools


def detect_ai_modules(results):

    ai = []

    for file in results:

        if "/ai/" in file:
            ai.append(file)

    return ai


def detect_recon(results):

    recon = []

    for file in results:

        if "recon" in file or "crawler" in file or "subdomain" in file:
            recon.append(file)

    return recon


def detect_exploit(results):

    exploit = []

    for file in results:

        if "exploit" in file or "sqli" in file or "xss" in file:
            exploit.append(file)

    return exploit


def detect_chains(results):

    chains = []

    for file in results:

        if "chain" in file or "attack_graph" in file:
            chains.append(file)

    return chains


def write_md(name, lines):

    with open(name, "w") as f:
        f.write("\n".join(lines))

    print("generated", name)


def main():

    results = scan()

    tools = detect_tools(results)
    ai = detect_ai_modules(results)
    recon = detect_recon(results)
    exploit = detect_exploit(results)
    chains = detect_chains(results)

    recon_md = ["# Recon Pipeline\n"]

    for r in recon:
        recon_md.append(f"- {r}")

    exploit_md = ["# Exploit Pipeline\n"]

    for e in exploit:
        exploit_md.append(f"- {e}")

    tool_md = ["# Tool Usage\n"]

    for file, t in tools.items():

        tool_md.append(f"## {file}")

        for tool in t:
            tool_md.append(f"- {tool}")

    ai_md = ["# AI Decision Modules\n"]

    for a in ai:
        ai_md.append(f"- {a}")

    chain_md = ["# Attack Chain System\n"]

    for c in chains:
        chain_md.append(f"- {c}")

    write_md("RECON_PIPELINE.md", recon_md)
    write_md("EXPLOIT_PIPELINE.md", exploit_md)
    write_md("TOOL_USAGE.md", tool_md)
    write_md("AI_DECISION_FLOW.md", ai_md)
    write_md("ATTACK_CHAIN_FLOW.md", chain_md)


if __name__ == "__main__":
    main()