"""A small Java/Kotlin annotation reader for route extraction (#2).

Single-string regexes miss most real mapping shapes: bare ``@GetMapping``,
``path = "/x"``, arrays (``{"/a", "/b"}``, Kotlin ``["/a"]`` and
``arrayOf("/a")``) and ``method = {RequestMethod.GET, RequestMethod.POST}``.
This module finds annotations with their (balanced) argument lists, splits the
arguments into positional and named values, and works out whether each
annotation block sits on a class or on a member, and which class body a
member belongs to. It is a lexer-level reader, not a parser: it skips
comments and string literals so braces and parentheses inside them don't
confuse it, and gives up gracefully (no route) on anything it can't read,
such as a path built from a constant.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

_ANNOTATION_RE = re.compile(r"(?<![\w.])@([A-Za-z_]\w*)\b")
_CLASS_DECL_RE = re.compile(r"(?<![\w.])(?:class|interface|object)\s+[A-Za-z_]\w*")
_MODIFIERS = frozenset(
    {
        "public", "private", "protected", "abstract", "final", "static", "open",
        "internal", "data", "sealed", "inner", "annotation", "override", "suspend",
        "default", "synchronized", "strictfp", "lateinit", "operator", "inline",
    }
)
_CLASS_KEYWORDS = ("class", "interface", "object")
# Tokens that end a class header without a body (a Kotlin `class Foo(val x: Int)`
# followed by other declarations).
_HEADER_STOP_WORDS = frozenset({"fun", "class", "val", "var", "object", "interface"})
_STRING_RE = re.compile(r'"((?:[^"\\\n]|\\.)*)"')
_WORD_RE = re.compile(r"[A-Za-z_]\w*")


@dataclass
class Annotation:
    name: str
    start: int
    end: int
    # None for a bare annotation (`@GetMapping` with no parentheses).
    args: str | None = None
    positional: list[str] = field(default_factory=list)
    named: dict[str, str] = field(default_factory=dict)


@dataclass
class AnnotationBlock:
    """Consecutive annotations on one declaration."""

    annotations: list[Annotation]
    # Offset of the `class`/`interface`/`object` keyword when the block
    # annotates a class, else None (a method, field or parameter).
    class_keyword_at: int | None = None

    def get(self, *names: str) -> list[Annotation]:
        return [a for a in self.annotations if a.name in names]


# ---------- Lexing helpers ----------


def mask_comments(content: str) -> str:
    """Return ``content`` with comments replaced by spaces (newlines kept).

    Offsets and line numbers stay valid. String and char literals are left
    alone, so `"http://x"` isn't mistaken for a line comment.
    """
    out = list(content)
    i, n = 0, len(content)
    while i < n:
        ch = content[i]
        if content.startswith('"""', i):
            end = content.find('"""', i + 3)
            i = n if end == -1 else end + 3
        elif ch in "\"'":
            i = _skip_quoted(content, i)
        elif content.startswith("//", i):
            end = content.find("\n", i)
            end = n if end == -1 else end
            for j in range(i, end):
                out[j] = " "
            i = end
        elif content.startswith("/*", i):
            end = content.find("*/", i + 2)
            end = n if end == -1 else end + 2
            for j in range(i, end):
                if out[j] != "\n":
                    out[j] = " "
            i = end
        else:
            i += 1
    return "".join(out)


def _skip_quoted(content: str, i: int) -> int:
    """Index just past the string/char literal that starts at ``i``."""
    quote = content[i]
    j = i + 1
    n = len(content)
    while j < n:
        c = content[j]
        if c == "\\":
            j += 2
            continue
        if c == quote or c == "\n":
            return j + 1
        j += 1
    return n


def _skip_literal(content: str, i: int) -> int | None:
    """If a string/char literal starts at ``i``, return the index past it."""
    if content.startswith('"""', i):
        end = content.find('"""', i + 3)
        return len(content) if end == -1 else end + 3
    if content[i] in "\"'":
        return _skip_quoted(content, i)
    return None


def match_bracket(content: str, open_at: int) -> int | None:
    """Index just past the bracket that closes the one at ``open_at``.

    Brackets inside string literals are ignored. Returns None if unbalanced.
    """
    pairs = {"(": ")", "{": "}", "[": "]"}
    stack = [pairs[content[open_at]]]
    i = open_at + 1
    n = len(content)
    while i < n:
        skipped = _skip_literal(content, i)
        if skipped is not None:
            i = skipped
            continue
        c = content[i]
        if c in pairs:
            stack.append(pairs[c])
        elif c in ")}]":
            if c != stack[-1]:
                return None
            stack.pop()
            if not stack:
                return i + 1
        i += 1
    return None


def split_top_level(text: str, sep: str = ",") -> list[str]:
    """Split ``text`` on ``sep`` outside brackets and string literals."""
    parts: list[str] = []
    depth = 0
    start = 0
    i = 0
    n = len(text)
    while i < n:
        skipped = _skip_literal(text, i)
        if skipped is not None:
            i = skipped
            continue
        c = text[i]
        if c in "({[":
            depth += 1
        elif c in ")}]":
            depth -= 1
        elif c == sep and depth == 0:
            parts.append(text[start:i])
            start = i + 1
        i += 1
    parts.append(text[start:])
    return [p.strip() for p in parts if p.strip()]


def _skip_ws(content: str, i: int) -> int:
    n = len(content)
    while i < n and content[i].isspace():
        i += 1
    return i


# ---------- Annotation values ----------


def string_values(value: str) -> list[str] | None:
    """String literal(s) in an annotation value, or None if it isn't literal.

    Handles `"/x"`, `{"/a", "/b"}`, Kotlin `["/a", "/b"]` and
    `arrayOf("/a", "/b")`. Elements that aren't literals (constants) are
    dropped; if nothing literal remains the value is unreadable (None), except
    for an explicitly empty array, which is `[]`.
    """
    v = value.strip()
    inner: str | None = None
    if (v.startswith("{") and v.endswith("}")) or (v.startswith("[") and v.endswith("]")):
        inner = v[1:-1]
    else:
        m = re.fullmatch(r"arrayOf\s*\((.*)\)", v, re.DOTALL)
        if m:
            inner = m.group(1)
    elements = split_top_level(inner) if inner is not None else [v]
    if inner is not None and not elements:
        return []
    found: list[str] = []
    for element in elements:
        m = _STRING_RE.fullmatch(element.strip())
        if m:
            found.append(m.group(1))
    return found or None


def _parse_args(annotation: Annotation) -> None:
    if annotation.args is None:
        return
    for part in split_top_level(annotation.args):
        m = re.match(r"([A-Za-z_]\w*)\s*=(?!=)\s*(.*)\Z", part, re.DOTALL)
        if m:
            annotation.named[m.group(1)] = m.group(2).strip()
        else:
            annotation.positional.append(part)


def annotation_paths(annotation: Annotation, keys: tuple[str, ...]) -> list[str] | None:
    """Paths declared by ``annotation`` under ``keys`` or positionally.

    Returns `[""]` for a bare annotation or one with no path argument (the
    mapping inherits the class path), and None when a path argument exists but
    isn't a literal we can read.
    """
    values: list[str] = []
    present = False
    # Java allows one positional `value`; Kotlin passes an array `value` as
    # varargs (`@GetMapping("/a", "/b")`), so read every positional argument.
    sources = [*annotation.positional, *(annotation.named[k] for k in keys if k in annotation.named)]
    for source in sources:
        present = True
        parsed = string_values(source)
        if parsed is not None:
            values.extend(parsed)
    if not present:
        return [""]
    if not values:
        # `{}` is an explicit empty path list (same as bare); a constant is unknown.
        return [""] if any(string_values(s) == [] for s in sources) else None
    return list(dict.fromkeys(values))


# ---------- Blocks and class scopes ----------


def find_annotations(masked: str, names: frozenset[str] | None = None) -> list[Annotation]:
    """Every annotation in ``masked`` (comments already masked)."""
    found: list[Annotation] = []
    i = 0
    n = len(masked)
    while i < n:
        skipped = _skip_literal(masked, i)
        if skipped is not None:
            i = skipped
            continue
        if masked[i] != "@":
            i += 1
            continue
        m = _ANNOTATION_RE.match(masked, i)
        if m is None or (i > 0 and (masked[i - 1].isalnum() or masked[i - 1] in "_.")):
            i += 1
            continue
        name = m.group(1)
        end = m.end()
        args: str | None = None
        paren = _skip_ws(masked, end)
        if paren < n and masked[paren] == "(":
            close = match_bracket(masked, paren)
            if close is not None:
                args = masked[paren + 1 : close - 1]
                end = close
        annotation = Annotation(name=name, start=i, end=end, args=args)
        _parse_args(annotation)
        found.append(annotation)
        i = end
    if names is not None:
        # Filter after scanning so a skipped annotation's arguments are still
        # consumed and can't be read as separate annotations.
        return [a for a in found if a.name in names]
    return found


def group_blocks(masked: str, annotations: list[Annotation]) -> list[AnnotationBlock]:
    """Group annotations that sit on the same declaration.

    Two annotations are in one block when only whitespace or modifiers
    separate them. Each block records whether it annotates a class.
    """
    blocks: list[AnnotationBlock] = []
    current: list[Annotation] = []
    for annotation in annotations:
        if current and not _only_modifiers_between(masked, current[-1].end, annotation.start):
            blocks.append(_finish_block(masked, current))
            current = []
        current.append(annotation)
    if current:
        blocks.append(_finish_block(masked, current))
    return blocks


def _only_modifiers_between(masked: str, start: int, end: int) -> bool:
    gap = masked[start:end].split()
    return all(token in _MODIFIERS for token in gap)


def _finish_block(masked: str, annotations: list[Annotation]) -> AnnotationBlock:
    i = annotations[-1].end
    n = len(masked)
    while True:
        i = _skip_ws(masked, i)
        m = _WORD_RE.match(masked, i) if i < n else None
        if m is None:
            return AnnotationBlock(annotations)
        word = m.group(0)
        if word in _CLASS_KEYWORDS:
            return AnnotationBlock(annotations, class_keyword_at=i)
        if word not in _MODIFIERS:
            return AnnotationBlock(annotations)
        i += len(word)


@dataclass
class ClassScope:
    keyword_at: int
    body_start: int
    body_end: int


def class_scopes(masked: str) -> list[ClassScope]:
    """Every class/interface/object body in the file, by brace matching."""
    scopes: list[ClassScope] = []
    for m in _CLASS_DECL_RE.finditer(masked):
        body_open = _find_body_open(masked, m.end())
        if body_open is None:
            continue
        close = match_bracket(masked, body_open)
        scopes.append(ClassScope(m.start(), body_open, close if close is not None else len(masked)))
    return scopes


def _find_body_open(masked: str, i: int) -> int | None:
    n = len(masked)
    while i < n:
        skipped = _skip_literal(masked, i)
        if skipped is not None:
            i = skipped
            continue
        c = masked[i]
        if c == "{":
            return i
        if c in "([<":
            if c == "<":
                close = masked.find(">", i)
                i = n if close == -1 else close + 1
                continue
            close = match_bracket(masked, i)
            if close is None:
                return None
            i = close
            continue
        if c in ";}=@":
            return None
        if c.isalpha() or c == "_":
            m = _WORD_RE.match(masked, i)
            assert m is not None
            if m.group(0) in _HEADER_STOP_WORDS:
                return None
            i += len(m.group(0))
            continue
        i += 1
    return None


def innermost_scope(scopes: list[ClassScope], offset: int) -> ClassScope | None:
    best: ClassScope | None = None
    for scope in scopes:
        if scope.body_start < offset < scope.body_end:
            if best is None or scope.body_start > best.body_start:
                best = scope
    return best


__all__ = [
    "Annotation",
    "AnnotationBlock",
    "ClassScope",
    "annotation_paths",
    "class_scopes",
    "find_annotations",
    "group_blocks",
    "innermost_scope",
    "mask_comments",
    "match_bracket",
    "split_top_level",
    "string_values",
]
