#!/usr/bin/env python3
"""Reject process execution and outbound-client surfaces from runtime source."""

from __future__ import annotations

import ast
import json
from pathlib import Path
from typing import List, Tuple


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src" / "detection_platform"
FORBIDDEN_MODULES = {
    "ctypes",
    "ftplib",
    "paramiko",
    "requests",
    "socket",
    "subprocess",
    "telnetlib",
}
FORBIDDEN_CALLS = {
    "eval",
    "exec",
    "compile",
    "os.system",
    "os.popen",
    "os.spawnv",
    "os.spawnl",
}


def dotted_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = dotted_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""


def inspect_file(path: Path) -> List[Tuple[int, str]]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    findings: List[Tuple[int, str]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".", 1)[0] in FORBIDDEN_MODULES:
                    findings.append((node.lineno, f"forbidden import: {alias.name}"))
        elif isinstance(node, ast.ImportFrom) and node.module:
            if node.module.split(".", 1)[0] in FORBIDDEN_MODULES:
                findings.append((node.lineno, f"forbidden import: {node.module}"))
        elif isinstance(node, ast.Call) and dotted_name(node.func) in FORBIDDEN_CALLS:
            findings.append((node.lineno, f"forbidden call: {dotted_name(node.func)}"))
    return findings


def main() -> int:
    findings = [
        {"file": str(path.relative_to(ROOT)), "line": line, "detail": detail}
        for path in sorted(SOURCE.rglob("*.py"))
        for line, detail in inspect_file(path)
    ]
    print(
        json.dumps(
            {"passed": not findings, "findings": findings}, indent=2, sort_keys=True
        )
    )
    return 0 if not findings else 1


if __name__ == "__main__":
    raise SystemExit(main())
