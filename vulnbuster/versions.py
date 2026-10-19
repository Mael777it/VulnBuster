# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Marcin Lewandowski <marcin.lewandowski.x@gmail.com>
"""Porównywanie wersji oprogramowania z różnych ekosystemów.

Obsługiwane formaty (heurystycznie, bez zależności):
  * semver / klasyczne:            14.11, 2.4.58, 1.1.1w, 9.6p1
  * prerelease:                    1.0rc1 < 1.0, 2.0-beta2 < 2.0
  * Debian/RPM z epoką i rewizją:  1:2.4.57-2+deb12u1, 2.4.37-62.el8_9
  * Windows build:                 10.0.19045.4529
  * Cisco IOS / FortiOS itp.:      15.2(4)M7, 7.2.5 build1517
"""
from __future__ import annotations

import re
from functools import cmp_to_key

_PRE = {"dev": -5, "alpha": -4, "a": -4, "beta": -3, "b": -3,
        "pre": -2, "preview": -2, "rc": -1, "cr": -1}
_TOK = re.compile(r"\d+|[a-z]+")
_EPOCH = re.compile(r"^(\d+):(.+)$")


def parse(v):
    """Zwraca (epoka, [tokeny]) lub None, gdy nie da się odczytać wersji."""
    if v is None:
        return None
    s = str(v).strip().lower()
    if not s:
        return None
    if re.match(r"^v\d", s):
        s = s[1:]
    epoch = 0
    m = _EPOCH.match(s)
    if m:
        epoch, s = int(m.group(1)), m.group(2)
    toks = []
    for t in _TOK.findall(s):
        if t.isdigit():
            toks.append((1, int(t)))
        elif t in _PRE:
            toks.append((0, _PRE[t]))
        else:
            toks.append((2, t))
    if not toks or toks[0][0] != 1:
        return None  # wersja musi zaczynać się od liczby
    return epoch, toks


_END = (1, 0)


def compare(a, b):
    """-1 / 0 / 1; None gdy któraś wersja jest nieczytelna."""
    pa, pb = (a if isinstance(a, tuple) else parse(a)), (b if isinstance(b, tuple) else parse(b))
    if pa is None or pb is None:
        return None
    if pa[0] != pb[0]:
        return -1 if pa[0] < pb[0] else 1
    ta, tb = pa[1], pb[1]
    for i in range(max(len(ta), len(tb))):
        x = ta[i] if i < len(ta) else _END
        y = tb[i] if i < len(tb) else _END
        if x != y:
            return -1 if x < y else 1
    return 0


def numeric_prefix(v):
    """Wiodące składniki liczbowe: '14.9' -> [14, 9], '15.2(4)M7' -> [15, 2, 4]."""
    p = v if isinstance(v, tuple) else parse(v)
    if p is None:
        return []
    out = []
    for kind, val in p[1]:
        if kind != 1:
            break
        out.append(val)
    return out


def branch_nums(branch: str):
    """'14' -> [14]; '9.6.x' -> [9, 6]; '*' -> []"""
    b = str(branch or "").strip().lower()
    b = re.sub(r"[.\-_ ]*(x|\*)$", "", b)
    if not b or b in ("*", "all", "wszystkie"):
        return []
    return numeric_prefix(b)


def is_wildcard(branch) -> bool:
    return branch_nums(branch) == [] and str(branch or "").strip().lower() in ("", "*", "all", "wszystkie", "x")


def derive_branch(fixed: str) -> str:
    """Z wersji naprawionej zgaduje gałąź: 14.11 -> 14, 2.4.58 -> 2.4, 10.0.19045.4529 -> 10.0.19045."""
    n = numeric_prefix(fixed)
    if len(n) >= 4:
        return ".".join(map(str, n[:3]))
    if len(n) == 3:
        return ".".join(map(str, n[:2]))
    if len(n) == 2:
        return str(n[0])
    return "*"


def max_version(versions):
    vs = [v for v in versions if v and parse(v) is not None]
    if not vs:
        return None
    return sorted(vs, key=cmp_to_key(lambda a, b: compare(a, b) or 0))[-1]


def sort_key():
    return cmp_to_key(lambda a, b: (compare(a, b) if compare(a, b) is not None else (a > b) - (a < b)))
