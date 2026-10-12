"""Same-repo string constants for Spring Security arguments (#11).

Real configurations name roles and paths through constants:
`hasAuthority(AuthoritiesConstants.ADMIN)`,
`@PreAuthorize("hasAuthority(\\"" + AuthoritiesConstants.ADMIN + "\\")")`,
`@Secured(Roles.ADMIN)`. This module records every member declaration of every
class, interface, enum, record and Kotlin object (companion objects count as
their class), keyed by `ClassName.NAME`. A key resolves only when every
declaration of it in the repo is a string constant with the same plain-literal
value:

- Java: a `static final String` field (implicitly static final in an
  interface) initialised with string literals joined by `+`;
- Kotlin: `const val NAME[: String] = ` literals joined by `+`, on one line.

Any other declaration of the same `Class.NAME` poisons the key: a non-final or
non-String field, a field without a literal initialiser, a text block or raw
string, a `$template`, an enum constant, a `val`/`var`, or a class with the same
simple name in another package or nested elsewhere that declares the name
differently. So does hitting a size cap, which makes every lookup fail.
Unresolved references leave the caller's decision `unknown`.
"""

from __future__ import annotations

import re

from .annotations import BracketIndex, _find_body_open, split_top_level

MAX_CONSTANTS = 50_000
MAX_DECLARATIONS_PER_FILE = 5_000
MAX_TYPES_PER_FILE = 1_000
MAX_VALUE_CHARS = 256
MAX_EXPRESSION_CHARS = 2_000
MAX_PIECES = 32

_TYPE_DECL_RE = re.compile(r"(?<![\w.$@])(class|interface|enum|record|object)\s+([A-Za-z_]\w*)")
_ENUM_BEFORE_RE = re.compile(r"\benum\s*\Z")
_COMPANION_RE = re.compile(r"\bcompanion\s+object\b[^;{}]*\Z")
_ANNOTATION_USE_RE = re.compile(r'@[A-Za-z_][\w.]*(?:\s*\((?:[^()"]|"(?:[^"\\\n]|\\.)*")*\))?')
_IDENT_RE = re.compile(r"[A-Za-z_]\w*")
_KOTLIN_PROPERTY_RE = re.compile(r"\b(val|var)\s+([A-Za-z_]\w*)")
_KOTLIN_CONST_RE = re.compile(r"(?:^|\s)const\s+val\s+[A-Za-z_]\w*\s*(?::\s*(?:kotlin\.)?String\s*)?=(.*)\Z", re.DOTALL)
_STRING_LITERAL_RE = re.compile(r'"((?:[^"\\\n]|\\.)*)"')
# `AuthoritiesConstants.ADMIN` or `com.example.AuthoritiesConstants.ADMIN`.
_QUALIFIED_REF_RE = re.compile(r"(?:[A-Za-z_]\w*\.){0,16}([A-Za-z_]\w*)\.([A-Za-z_]\w*)")
_ESCAPE_RE = re.compile(r"\\(.)")
_ESCAPES = {"n": "\n", "t": "\t", "r": "\r"}
_JAVA_MODIFIERS = frozenset(
    {"public", "private", "protected", "static", "final", "transient", "volatile", "abstract", "default"}
)
_POISON = object()


def unescape(value: str) -> str:
    return _ESCAPE_RE.sub(lambda m: _ESCAPES.get(m.group(1), m.group(1)), value)


class ConstantTable:
    """`ClassName.NAME` -> every value declared for it (or a poison marker)."""

    def __init__(self) -> None:
        self._values: dict[str, set[object]] = {}
        self._count = 0
        # A cap was hit: declarations were dropped and could conflict.
        self.overflow = False

    def add(self, key: str, value: object) -> None:
        if self._count >= MAX_CONSTANTS:
            self.overflow = True
            return
        if isinstance(value, str) and len(value) > MAX_VALUE_CHARS:
            value = _POISON
        self._count += 1
        self._values.setdefault(key, set()).add(value)

    def poison(self, key: str) -> None:
        self.add(key, _POISON)

    def lookup(self, key: str) -> str | None:
        """The value of ``key``, or None when it is unknown, ambiguous or poisoned."""
        if self.overflow:
            return None
        values = self._values.get(key)
        if values is None or len(values) != 1:
            return None
        value = next(iter(values))
        return value if isinstance(value, str) else None

    def collect(self, masked: str, *, kotlin: bool = False) -> None:
        """Record the member declarations of every type in one comment-masked file."""
        brackets = BracketIndex(masked)
        budget = [MAX_DECLARATIONS_PER_FILE]
        for count, m in enumerate(_TYPE_DECL_RE.finditer(masked)):
            if count >= MAX_TYPES_PER_FILE:
                self.overflow = True
                return
            open_at = _find_body_open(masked, m.end())
            if open_at is None:
                continue
            close = brackets.close(open_at)
            if close is None:
                self.overflow = True  # unbalanced: we can't tell what's declared where
                return
            kind = m.group(1)
            is_enum = kind == "enum" or (kotlin and _ENUM_BEFORE_RE.search(masked, max(0, m.start() - 40), m.start()))
            statements = _member_statements(masked, open_at + 1, close - 1, brackets, kotlin)
            self._record(m.group(2), statements, kotlin=kotlin, interface=kind == "interface" and not kotlin,
                         enum=bool(is_enum), budget=budget)
            if budget[0] <= 0:
                self.overflow = True
                return

    def _record(
        self, cls: str, statements: list[str], *, kotlin: bool, interface: bool, enum: bool, budget: list[int]
    ) -> None:
        for index, statement in enumerate(statements):
            budget[0] -= 1
            if budget[0] <= 0:
                return
            if enum and index == 0:
                # Enum constants: `ADMIN, USER("x")` are members named like constants.
                for element in split_top_level(statement):
                    ident = _IDENT_RE.match(element.strip())
                    if ident is not None:
                        self.poison(f"{cls}.{ident.group(0)}")
                continue
            if kotlin:
                self._record_kotlin(cls, statement)
            else:
                self._record_java(cls, statement, interface)

    def _record_kotlin(self, cls: str, statement: str) -> None:
        prop = _KOTLIN_PROPERTY_RE.search(statement)
        if prop is None:
            return
        key = f"{cls}.{prop.group(2)}"
        const = _KOTLIN_CONST_RE.search(statement)
        value = _literal_value(const.group(1)) if const is not None and prop.group(1) == "val" else None
        if value is None:
            self.poison(key)
        else:
            self.add(key, value)

    def _record_java(self, cls: str, statement: str, interface: bool) -> None:
        text = _ANNOTATION_USE_RE.sub(" ", statement).strip()
        if not text or "(" in text.split("=", 1)[0]:
            return  # a method, constructor or initializer, not a field
        declarators = split_top_level(text)
        if not declarators:
            return
        head = declarators[0]
        left, sep, right = _split_assignment(head)
        tokens = _IDENT_RE.findall(left)
        if len(tokens) < 2:
            return  # not `Type name` (a statement fragment)
        name = tokens[-1]
        modifiers = set(tokens[:-2])
        type_name = tokens[-2]
        is_constant = (interface or {"static", "final"} <= modifiers) and type_name == "String"
        is_constant = is_constant and modifiers <= _JAVA_MODIFIERS and "[" not in left and "<" not in left
        value = _literal_value(right) if sep and is_constant and len(declarators) == 1 else None
        if value is None:
            self.poison(f"{cls}.{name}")
        else:
            self.add(f"{cls}.{name}", value)
        for other in declarators[1:]:
            # `String A = "x", B = "y"`: every further declarator is unread.
            other_left, _, _ = _split_assignment(other)
            ident = _IDENT_RE.findall(other_left)
            if ident:
                self.poison(f"{cls}.{ident[-1]}")


def _split_assignment(text: str) -> tuple[str, str, str]:
    """Split at the first `=` that isn't part of `==`, `!=`, `<=`, `>=`."""
    for i, c in enumerate(text):
        if c == "=" and (i + 1 >= len(text) or text[i + 1] != "=") and (i == 0 or text[i - 1] not in "=!<>"):
            return text[:i], "=", text[i + 1 :]
    return text, "", ""


def _literal_value(expr: str) -> str | None:
    """String literals joined by `+`, or None (constants, calls, raw strings...)."""
    return resolve_expression(expr, None)


def _member_statements(masked: str, start: int, end: int, brackets: BracketIndex, kotlin: bool) -> list[str]:
    """The member-level statements of a type body.

    Nested `{...}` blocks (method bodies, nested types, initialisers) end a
    statement and are skipped, except a Kotlin `companion object`, whose
    members belong to the enclosing class. Parentheses and brackets are
    skipped whole, so lambdas in initialisers don't split statements.
    Statements end at `;`, and in Kotlin also at a newline outside brackets.
    """
    statements: list[str] = []
    current: list[str] = []
    i = start
    while i < end:
        c = masked[i]
        if c in "([":
            close = brackets.close(i)
            if close is None or close > end:
                current.append(masked[i:end])
                break
            current.append(masked[i:close])
            i = close
            continue
        if c == '"' or c == "'":
            j = i + 1
            while j < end and masked[j] != c and masked[j] != "\n":
                j += 2 if masked[j] == "\\" else 1
            current.append(masked[i : j + 1])
            i = j + 1
            continue
        if c == "{":
            close = brackets.close(i)
            if close is None or close > end:
                break
            prefix = "".join(current)
            if _COMPANION_RE.search(prefix):
                statements.extend(_member_statements(masked, i + 1, close - 1, brackets, kotlin))
            elif _split_assignment(prefix)[1] == "=":
                current.append(masked[i:close])  # `= { ... }` initializer: keep it in the statement
                i = close
                continue
            current = []
            i = close
            continue
        if c == ";" or (kotlin and c == "\n"):
            text = "".join(current).strip()
            if text:
                statements.append(text)
            current = []
        else:
            current.append(c)
        i += 1
    text = "".join(current).strip()
    if text:
        statements.append(text)
    return statements


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
