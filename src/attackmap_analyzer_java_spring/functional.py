"""Spring WebFlux / WebMvc.fn functional endpoints (#3).

Shapes read:

- `RouterFunctions.route(GET("/x"), h).andRoute(POST("/y"), h)` and
  `RequestPredicates.GET("/x").and(accept(JSON))`;
- `RouterFunctions.nest(path("/api"), route(...))` and `.andNest(path("/api"), ...)`;
- the builder: `route().GET("/x", h).POST("/y", accept(JSON), h)`,
  `.path("/api", b -> b.GET(...))` and `.nest(path("/api"), b -> ...)`;
- Kotlin `router { }` / `coRouter { }` with `GET("/x", h)`, `"/api".nest { }`,
  `path("/api").nest { }` and `accept(JSON).nest { }`.

A verb call whose path isn't a string literal (a constant, a Kotlin string
template) is skipped, and so is everything inside a nest whose prefix can't be
read, so a route is never reported under the wrong path. The caller gates on
the functional API being imported.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .annotations import BracketIndex, bracket_end, split_top_level

# Imports of the functional API (WebFlux and WebMvc.fn), or its entry points.
FUNCTIONAL_GATE_RE = re.compile(
    r"\borg\.springframework\.web\.(?:reactive\.function\.server|servlet\.function)\b"
    r"|\bRouterFunctions\b|\bRequestPredicates\b"
)
# `GET("/x"`, `.GET("/x"`, `RequestPredicates.GET("/x"` but not `@GET("/x")`.
_VERB_CALL_RE = re.compile(r"(?<![\w@$])(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s*\(")
# Java nest calls: `nest(pred, ...)`, `.andNest(pred, ...)`, builder `.nest(pred, b -> ...)`.
_NEST_CALL_RE = re.compile(r"(?<![\w$])(?:andNest|nest)\s*\(")
# Builder `.path("/api", b -> ...)`.
_BUILDER_PATH_RE = re.compile(r"\.\s*path\s*\(")
# Kotlin DSL `<receiver>.nest {` or infix `<receiver> nest {`.
_KOTLIN_NEST_RE = re.compile(r"(?<![\w$])nest\s*\{")
_PATH_PREDICATE_RE = re.compile(r"(?<![\w$])path\s*\(")
_STRING_LITERAL_RE = re.compile(r'"((?:[^"\\\n]|\\.)*)"')
_KOTLIN_RECEIVER_PATH_RE = re.compile(r'(?:path\s*\(\s*)?"([^"\\\n$]*)"\s*\)?')

MAX_SCOPES = 500
MAX_ROUTES = 2000


@dataclass
class FunctionalRoute:
    method: str
    path: str
    offset: int


@dataclass
class _Scope:
    start: int
    end: int
    # None when the prefix isn't a readable literal: routes inside are skipped.
    prefix: str | None


def _literal(text: str) -> str | None:
    m = _STRING_LITERAL_RE.fullmatch(text.strip())
    if m is None or "$" in m.group(1):
        return None
    return m.group(1)


def _predicate_prefix(predicate: str) -> str | None:
    """Path prefix of a nest predicate: `path("/api")`, `path("/api").and(...)`,
    `accept(JSON)` (no prefix). None when a `path(...)` isn't a literal."""
    m = _PATH_PREDICATE_RE.search(predicate)
    if m is None:
        # A predicate that names a path some other way can't be read.
        return None if _STRING_LITERAL_RE.search(predicate) else ""
    close = bracket_end(predicate, m.end() - 1)
    if close is None:
        return None
    return _literal(predicate[m.end() : close - 1])


def _join(prefix: str, suffix: str) -> str:
    if not prefix:
        path = suffix
    elif not suffix:
        path = prefix
    else:
        path = prefix.rstrip("/") + "/" + suffix.lstrip("/")
    path = path or "/"
    return path if path.startswith("/") else "/" + path


def _scopes(masked: str, brackets: BracketIndex) -> list[_Scope]:
    scopes: list[_Scope] = []
    for count, m in enumerate(_NEST_CALL_RE.finditer(masked)):
        if count >= MAX_SCOPES:
            break
        close = brackets.close(m.end() - 1)
        if close is None:
            continue
        parts = split_top_level(masked[m.end() : close - 1])
        if len(parts) < 2:
            continue
        scopes.append(_Scope(m.end(), close - 1, _predicate_prefix(parts[0])))
    for count, m in enumerate(_BUILDER_PATH_RE.finditer(masked)):
        if count >= MAX_SCOPES:
            break
        close = brackets.close(m.end() - 1)
        if close is None:
            continue
        parts = split_top_level(masked[m.end() : close - 1])
        if len(parts) < 2:
            # `RequestPredicates.path("/x")` is a predicate, not a scope.
            continue
        scopes.append(_Scope(m.end(), close - 1, _literal(parts[0])))
    for count, m in enumerate(_KOTLIN_NEST_RE.finditer(masked)):
        if count >= MAX_SCOPES:
            break
        brace = m.end() - 1
        close = brackets.close(brace)
        if close is None:
            continue
        line_start = masked.rfind("\n", 0, m.start()) + 1
        receiver = masked[line_start : m.start()].strip().rstrip(".").strip()
        scopes.append(_Scope(brace + 1, close - 1, _kotlin_receiver_prefix(receiver)))
    return scopes


def _kotlin_receiver_prefix(receiver: str) -> str | None:
    """`"/api"` or `path("/api")` -> "/api"; a predicate call such as
    `accept(JSON)` -> ""; anything else (a variable that may hold a path
    String, a `"/x" and accept(...)` combination) -> None."""
    m = _KOTLIN_RECEIVER_PATH_RE.fullmatch(receiver)
    if m is not None:
        return m.group(1)
    if '"' in receiver or _PATH_PREDICATE_RE.search(receiver) or not receiver.endswith(")"):
        return None
    return ""


def functional_routes(masked: str) -> list[FunctionalRoute]:
    """Functional routes in a comment-masked file, with nest prefixes applied."""
    brackets = BracketIndex(masked)
    scopes = _scopes(masked, brackets)
    routes: list[FunctionalRoute] = []
    for count, m in enumerate(_VERB_CALL_RE.finditer(masked)):
        if count >= MAX_ROUTES:
            break
        close = brackets.close(m.end() - 1)
        if close is None:
            continue
        parts = split_top_level(masked[m.end() : close - 1])
        if not parts:
            continue
        suffix = _literal(parts[0])
        if suffix is None:
            continue
        enclosing = sorted(
            (s for s in scopes if s.start <= m.start() < s.end),
            key=lambda s: (s.start, -s.end),
        )
        if any(s.prefix is None for s in enclosing):
            continue
        path = ""
        for scope in enclosing:
            path = _join(path, scope.prefix or "")
        routes.append(FunctionalRoute(method=m.group(1), path=_join(path, suffix), offset=m.start()))
    return routes


__all__ = ["FUNCTIONAL_GATE_RE", "FunctionalRoute", "functional_routes"]
