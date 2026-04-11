#!/usr/bin/env python3
import ast
import argparse
from pathlib import Path

class AgentPipelineVisitor(ast.NodeVisitor):
    def __init__(self):
        self.methods = {}
        self.current = None

    def visit_FunctionDef(self, node):
        old = self.current
        self.current = node.name
        self.methods[node.name] = []
        self.generic_visit(node)
        self.current = old

    def visit_Call(self, node):
        if self.current:
            name = self._get_call_name(node.func)
            if name:
                self.methods[self.current].append(name)
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

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("agent_file")
    args = ap.parse_args()

    path = Path(args.agent_file)
    src = path.read_text(encoding="utf-8", errors="ignore")
    tree = ast.parse(src)

    v = AgentPipelineVisitor()
    v.visit(tree)

    print("# Agent pipeline summary\n")
    for method, calls in sorted(v.methods.items()):
        if method.startswith("_run") or "phase" in method or method in {"run", "start", "__init__"}:
            print(f"## {method}")
            seen = set()
            for c in calls:
                if c not in seen:
                    print(f"- {c}")
                    seen.add(c)
            print()

if __name__ == "__main__":
    main()
