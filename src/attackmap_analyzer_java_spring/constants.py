"""Same-repo string constants for Spring Security arguments (#11).

Real configurations name roles and paths through constants:
`hasAuthority(AuthoritiesConstants.ADMIN)`,
`@PreAuthorize("hasAuthority(\\"" + AuthoritiesConstants.ADMIN + "\\")")`,
`@Secured(Roles.ADMIN)`. This module collects `static final String NAME = "...";`
(Java) and `const val NAME = "..."` (Kotlin, in an `object` or a companion object)
declarations, keyed by `ClassName.NAME`, and resolves an argument expression made
of string literals and such class-qualified constants joined by `+`.

Anything else stays unresolved, and the caller then answers `unknown`. That
covers an unqualified name (static import, same class), a constant whose value
isn't a plain literal, a `Class.NAME` declared with different values in two
places, Kotlin `$templates`, method calls and ternaries. Everything is bounded.
"""

from __future__ import annotations

import re

from .annotations import class_scopes, innermost_scope, split_top_level

MAX_CONSTANTS = 50_000
MAX_CONSTANTS_PER_FILE = 2_000
MAX_VALUE_CHARS = 256
MAX_EXPRESSION_CHARS = 2_000
MAX_PIECES = 32

_JAVA_CONSTANT_RE = re.compile(
    r"\b((?:(?:public|private|protected|static|final)\s+)+)String\s+([A-Za-z_]\w*)\s*=\s*"
    r'"((?:[^"\\\n]|\\.)*)"\s*;'
)
_KOTLIN_CONSTANT_RE = re.compile(
    r'\bconst\s+val\s+([A-Za-z_]\w*)\s*(?::\s*String\s*)?=\s*"((?:[^"\\\n$]|\\.)*)"'
)
_CLASS_NAME_RE = re.compile(r"(?:class|interface|object)\s+([A-Za-z_]\w*)")
_STRING_LITERAL_RE = re.compile(r'"((?:[^"\\\n]|\\.)*)"')
# `AuthoritiesConstants.ADMIN` or `com.example.AuthoritiesConstants.ADMIN`.
_QUALIFIED_REF_RE = re.compile(r"(?:[A-Za-z_]\w*\.){0,16}([A-Za-z_]\w*)\.([A-Za-z_]\w*)")
_ESCAPE_RE = re.compile(r"\\(.)")
_ESCAPES = {"n": "\n", "t": "\t", "r": "\r"}


def unescape(value: str) -> str:
    return _ESCAPE_RE.sub(lambda m: _ESCAPES.get(m.group(1), m.group(1)), value)


class ConstantTable:
    """`ClassName.NAME` -> the literal values declared for it."""

    def __init__(self) -> None:
        self._values: dict[str, set[str]] = {}
        self._count = 0

    def add(self, key: str, value: str) -> None:
        if self._count >= MAX_CONSTANTS or len(value) > MAX_VALUE_CHARS:
            return
        self._count += 1
        self._values.setdefault(key, set()).add(value)

    def lookup(self, key: str) -> str | None:
        """The value of ``key``, or None when it is unknown or ambiguous."""
        values = self._values.get(key)
        if values is None or len(values) != 1:
            return None
        return next(iter(values))

    def collect(self, masked: str) -> None:
        """Add the constants declared in one comment-masked file."""
        if "String" not in masked and "const" not in masked:
            return
        found: list[tuple[int, str, str]] = []
        for m in _JAVA_CONSTANT_RE.finditer(masked):
            modifiers = m.group(1).split()
            if "static" in modifiers and "final" in modifiers:
                found.append((m.start(), m.group(2), unescape(m.group(3))))
            if len(found) >= MAX_CONSTANTS_PER_FILE:
                break
        for m in _KOTLIN_CONSTANT_RE.finditer(masked):
            found.append((m.start(), m.group(1), unescape(m.group(2))))
            if len(found) >= MAX_CONSTANTS_PER_FILE:
                break
        if not found:
            return
        scopes = class_scopes(masked)
        for offset, name, value in found:
            scope = innermost_scope(scopes, offset)
            if scope is None:
                continue  # a top-level constant isn't referenced as Class.NAME
            m = _CLASS_NAME_RE.match(masked, scope.keyword_at)
            if m is not None:
                self.add(f"{m.group(1)}.{name}", value)


EMPTY = ConstantTable()


def resolve_expression(expr: str, table: ConstantTable | None) -> str | None:
    """The string an argument expression evaluates to, or None if it can't be read.

    The expression is string literals and class-qualified constants from ``table``,
    joined by `+` (`"hasAuthority(\\"" + AuthoritiesConstants.ADMIN + "\\")"`).
    """
    expr = expr.strip()
    if not expr or len(expr) > MAX_EXPRESSION_CHARS:
        return None
    pieces = split_top_level(expr, "+")
    if not pieces or len(pieces) > MAX_PIECES:
        return None
    out: list[str] = []
    for piece in pieces:
        literal = _STRING_LITERAL_RE.fullmatch(piece)
        if literal is not None:
            if "$" in literal.group(1):
                return None  # a Kotlin string template
            out.append(unescape(literal.group(1)))
            continue
        ref = _QUALIFIED_REF_RE.fullmatch(piece)
        if ref is None or table is None:
            return None
        value = table.lookup(f"{ref.group(1)}.{ref.group(2)}")
        if value is None:
            return None
        out.append(value)
    return "".join(out)


__all__ = ["EMPTY", "ConstantTable", "resolve_expression", "unescape"]
