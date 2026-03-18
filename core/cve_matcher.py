"""
core/cve_matcher.py - Version/range matching helpers for CVE applicability.
"""

import re
from typing import Iterable, Optional, Tuple


def normalize_version(v: str) -> Optional[Tuple[int, ...]]:
    if not v:
        return None
    v = str(v).strip().lower()
    if v in {"unknown", "n/a", "na", "none", "-"}:
        return None
    parts = re.findall(r"\d+", v)
    if not parts:
        return None
    return tuple(int(p) for p in parts[:4])


def _cmp(a: Tuple[int, ...], b: Tuple[int, ...]) -> int:
    ln = max(len(a), len(b))
    aa = a + (0,) * (ln - len(a))
    bb = b + (0,) * (ln - len(b))
    if aa < bb:
        return -1
    if aa > bb:
        return 1
    return 0


def match_single_range(version: str, rule: str) -> Optional[bool]:
    v = normalize_version(version)
    if v is None:
        return None
    rule = (rule or "").strip()
    if not rule:
        return None

    # range syntax: "1.2.0-1.4.7"
    if "-" in rule and not rule.startswith("-"):
        lo, hi = [x.strip() for x in rule.split("-", 1)]
        vlo = normalize_version(lo)
        vhi = normalize_version(hi)
        if vlo is None or vhi is None:
            return None
        return _cmp(v, vlo) >= 0 and _cmp(v, vhi) <= 0

    for op in ("<=", ">=", "<", ">", "==", "="):
        if rule.startswith(op):
            rv = normalize_version(rule[len(op):].strip())
            if rv is None:
                return None
            c = _cmp(v, rv)
            if op == "<=":
                return c <= 0
            if op == ">=":
                return c >= 0
            if op == "<":
                return c < 0
            if op == ">":
                return c > 0
            return c == 0

    # bare version means exact match
    rv = normalize_version(rule)
    if rv is None:
        return None
    return _cmp(v, rv) == 0


def match_any_range(version: str, rules: Iterable[str]) -> Optional[bool]:
    known = False
    for r in rules or []:
        m = match_single_range(version, str(r))
        if m is None:
            continue
        known = True
        if m:
            return True
    return False if known else None
