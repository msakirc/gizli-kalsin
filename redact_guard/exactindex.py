"""Find every known value in a text without one giant regex.

The old approach compiled an alternation of every vaulted value and recompiled it whenever
the vault grew, which got quadratic. This index is built incrementally: values are keyed
by their first PREFIX characters, and a scan checks only the candidates for each position.
"""
from __future__ import annotations

from collections import defaultdict

PREFIX = 4


_NAME_CHARS = set("-._/\\@:")


def _alnum(c: str) -> bool:
    return c.isascii() and c.isalnum()


class ExactIndex:
    def __init__(self) -> None:
        self._by_prefix: dict[str, list[str]] = defaultdict(list)   # exact, word-bounded
        self._strong: dict[str, list[str]] = defaultdict(list)      # lowercase, unbounded
        self.values: dict[str, str] = {}                            # value -> token
        self.strong_lower: dict[str, str] = {}                      # lower(value) -> value
        self.whole_name: set[str] = set()                           # stricter neighbours

    def __len__(self) -> int:
        return len(self.values)

    def add(self, value: str, token: str, strong: bool = False, whole_name: bool = False) -> None:
        """``whole_name``: only match where the value stands alone, not inside a larger name
        (dbs inside dbs-server, /var/log/dbs-server or dbs.internal)."""
        if len(value) < PREFIX or value in self.values:
            return
        self.values[value] = token
        if whole_name:
            self.whole_name.add(value)
        lst = self._by_prefix[value[:PREFIX]]
        lst.append(value)
        lst.sort(key=len, reverse=True)
        if strong:
            low = value.lower()
            if len(low) == len(value) and low not in self.strong_lower:
                self.strong_lower[low] = value
                sl = self._strong[low[:PREFIX]]
                sl.append(low)
                sl.sort(key=len, reverse=True)

    def find(self, text: str, start: int = 0, end: int | None = None):
        """Yield (start, end, matched_text, is_strong) for non-overlapping matches, left to
        right, longest first. Exact matches need non-alphanumeric neighbours; strong (random)
        secrets match anywhere and in any letter case."""
        end = len(text) if end is None else end
        low = text.lower() if self._strong else None
        if low is not None and len(low) != len(text):
            low = None
        i = start
        while i <= end - PREFIX:
            hit = None
            cands = self._by_prefix.get(text[i:i + PREFIX])
            if cands:
                for v in cands:
                    j = i + len(v)
                    if j <= end and text.startswith(v, i) and \
                            (i == 0 or not _alnum(text[i - 1])) and (j >= len(text) or not _alnum(text[j])):
                        if v in self.whole_name and ((i and text[i - 1] in _NAME_CHARS) or
                                                     (j < len(text) and text[j] in _NAME_CHARS)):
                            continue
                        hit = (i, j, v, False)
                        break
            if hit is None and low is not None:
                sc = self._strong.get(low[i:i + PREFIX])
                if sc:
                    for v in sc:
                        j = i + len(v)
                        if j <= end and low.startswith(v, i):
                            hit = (i, j, text[i:j], True)
                            break
            if hit:
                yield hit
                i = hit[1]
            else:
                i += 1
