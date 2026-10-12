"""Spring Security `HttpSecurity` / `ServerHttpSecurity` rules -> route auth (#3).

Reads the authorization DSL of a security filter chain:

- `authorizeHttpRequests` / `authorizeRequests` / `authorizeExchange`, in the
  lambda form (`auth -> auth.requestMatchers("/a").permitAll()...`, block
  lambdas with one statement per rule), the pre-lambda chain form
  (`.authorizeRequests().antMatchers("/a").permitAll().and()`), and the Kotlin
  DSL (`authorizeHttpRequests { authorize("/a", permitAll) }`);
- matchers `requestMatchers` / `antMatchers` / `mvcMatchers` / `pathMatchers`
  (with an optional `HttpMethod.X`), `anyRequest()` / `anyExchange()`, the
  wrappers `antMatcher("/x")`, `mvc.pattern("/x")`, `new AntPathRequestMatcher(...)`,
  and `PathRequest.toStaticResources().atCommonLocations()`;
- access decisions `permitAll()` / `anonymous()` (anonymous), `authenticated()` /
  `fullyAuthenticated()` / `rememberMe()` / `hasRole(..)` / `hasAnyRole(..)` /
  `hasAuthority(..)` / `hasAnyAuthority(..)` / `denyAll()` (required), and
  `access(..)` when its expression is readable;
- `web.ignoring().requestMatchers(...)` (requests that bypass every chain) and a
  chain's `securityMatcher(...)` scope.

Rules are applied to a route the way Spring applies them: the first matcher that
matches decides. Matching is Ant/PathPattern style (`/**`, `/*`, `?`, `{var}`,
`{*var}`) on path segments. A matcher that *might* match the route (a
`{var}` route segment against a literal, a method-specific matcher against a
method-less `@RequestMapping`, or a matcher we can't read such as a constant or
`regexMatchers`) doesn't decide on its own: the route gets the first full match's
decision only when every such possible match before it agrees, else it stays
unknown. Everything here is a bounded, linear scan over comment-masked text, so
it never raises on hostile or truncated input.
"""

from __future__ import annotations

import re
from bisect import bisect_right
from dataclasses import dataclass, field

from .annotations import BracketIndex, bracket_end, split_top_level

# Results of matching a route against a matcher.
NONE, PARTIAL, FULL = 0, 1, 2

MATCH_FULL, MATCH_NONE, MATCH_METHOD, MATCH_VALUE, MATCH_OPAQUE = "full", "none", "method", "value", "opaque"

ANONYMOUS = "anonymous"
REQUIRED = "required"
UNKNOWN = "unknown"

# Bounds: hostile repos can contain anything.
MAX_BODY_CHARS = 50_000
# Arguments of one matcher or decision call.
MAX_CALL_CHARS = 5_000
MAX_RULES_PER_CHAIN = 500
MAX_RULES_PER_FILE = 1000
MAX_SCOPE_CALLS = 64
MAX_IGNORING_CALLS = 64
MAX_CHAINS = 64
MAX_AUTHORIZE_CALLS = 256
MAX_ENTRIES_PER_MATCHER = 200
MAX_PATTERN_CHARS = 512
MAX_SEGMENTS = 32
MAX_SEGMENT_CHARS = 128
MAX_DOUBLE_WILDCARDS = 4
_EVIDENCE_CHARS = 160

HTTP_METHODS = frozenset({"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE"})

# ---------- Patterns (module level: they run on hostile input) ----------

# Cheap per-file gate before any parsing.
SECURITY_GATE_RE = re.compile(r"\bauthorize(?:HttpRequests|Requests|Exchange)\b|\bignoring\s*\(")
_AUTHORIZE_RE = re.compile(r"\bauthorize(?:HttpRequests|Requests|Exchange)\b")
_IGNORING_RE = re.compile(r"\bignoring\s*\(\s*\)")
# One rule's matcher call inside an authorize body. `authorize(` is the Kotlin DSL.
_RULE_CALL_RE = re.compile(
    r"(?<![\w$])(requestMatchers|antMatchers|mvcMatchers|pathMatchers|regexMatchers|"
    r"dispatcherTypeMatchers|anyRequest|anyExchange|authorize)\s*\("
)
_CHAINED_CALL_RE = re.compile(r"\s*\.\s*([A-Za-z_]\w*)\s*\(")
_MATCHER_NAMES = frozenset({"requestMatchers", "antMatchers", "mvcMatchers", "pathMatchers", "regexMatchers"})
# A chain's own scope: `http.securityMatcher("/api/**")`, the pre-6 singular
# `http.antMatcher("/api/**")`, and `http.requestMatchers().antMatchers(...)` /
# `securityMatchers(m -> ...)` outside the authorize body.
_SCOPE_CALL_RE = re.compile(
    r"(?<![\w$])(securityMatchers?|requestMatchers)\s*\(|\.\s*(antMatcher|mvcMatcher|regexMatcher|requestMatcher)\s*\("
)
_STRING_LITERAL_RE = re.compile(r'"((?:[^"\\\n]|\\.)*)"')
_HTTP_METHOD_ARG_RE = re.compile(r"(?:[A-Za-z_][\w.]*\.)?HttpMethod\.([A-Z]+)")
# Matcher wrappers whose arguments are a pattern (and maybe a method).
_WRAPPER_RE = re.compile(
    r"(?:new\s+)?(?:[A-Za-z_][\w.]*\.)?"
    r"(antMatcher|pattern|pathMatchers|AntPathRequestMatcher|PathPatternRequestMatcher|"
    r"PathPatternParserServerWebExchangeMatcher|MvcRequestMatcher)\s*\(",
)
_STATIC_RESOURCES_RE = re.compile(r"(?:[A-Za-z_][\w.]*\.)?toStaticResources\s*\(\s*\)\s*\.\s*atCommonLocations\s*\(\s*\)")
_ANY_REQUEST_ARG_RE = re.compile(r"(?:[A-Za-z_][\w.]*\.)?(?:anyRequest|anyExchange)(?:\s*\(\s*\))?")
_ACCESS_REQUIRED_RE = re.compile(
    r"\b(?:hasRole|hasAnyRole|hasAuthority|hasAnyAuthority|isAuthenticated|isFullyAuthenticated|"
    r"authenticated|fullyAuthenticated|denyAll|hasPermission)\b"
)
_ACCESS_PERMIT_RE = re.compile(r"\b(?:permitAll|isAnonymous|anonymous)\b")
# `access(...)` arguments we can read: a SpEL string (Spring Security 5), the
# same wrapped in a WebExpressionAuthorizationManager, or a stock manager call.
_SPEL_ARG_RE = re.compile(r'(?:new\s+WebExpressionAuthorizationManager\s*\(\s*)?"((?:[^"\\\n]|\\.)*)"\s*\)?')
_MANAGER_ARG_RE = re.compile(
    r"(?:[A-Za-z_][\w.]*\.)?(?:authenticated|fullyAuthenticated|rememberMe|hasRole|hasAnyRole|"
    r"hasAuthority|hasAnyAuthority)\s*\([^()]*\)"
)
_AND_CALL_RE = re.compile(r"\.\s*and\s*\(\s*\)")
_IDENT_RE = re.compile(r"[A-Za-z_]\w*")
_TRAILING_IDENT_RE = re.compile(r"([A-Za-z_]\w*)\s*\Z")
_NEWLINE_RE = re.compile(r"\n")
_CLASS_HEADER_RE = re.compile(r"(?<![\w.$])(?:class|interface|object|enum)\b")

# Spring Boot's StaticResourceLocation patterns.
STATIC_RESOURCE_PATTERNS = ("/css/**", "/js/**", "/images/**", "/webjars/**", "/favicon.*", "/*/icon-*")

_ANON_DECISIONS = frozenset({"permitAll", "anonymous"})
_REQUIRED_DECISIONS = frozenset(
    {
        "authenticated", "fullyAuthenticated", "rememberMe", "hasRole", "hasAnyRole",
        "hasAuthority", "hasAnyAuthority", "denyAll",
    }
)


# ---------- Model ----------


@dataclass
class Matcher:
    # (HTTP method or None for any method, path pattern). Pattern None = any path.
    entries: list[tuple[str | None, str | None]] = field(default_factory=list)
    # Part of the matcher couldn't be read (a constant, regexMatchers, a custom
    # RequestMatcher): it may match any route.
    opaque: bool = False

    def match(self, path: str, method: str) -> str:
        """How this matcher covers requests to a route.

        `full`: every request; `none`: none; `method`: the requests of one
        method of a method-less route; `value`: some values of the route's
        path variables (`/a/me` against `/a/{id}`); `opaque`: unknown, since
        part of the matcher couldn't be read.
        """
        kinds: set[str] = set()
        for entry_method, pattern in self.entries:
            path_result = FULL if pattern is None else match_path(pattern, path)
            if path_result == NONE:
                continue
            method_subset = entry_method is not None and entry_method != method
            if method_subset and method != "ANY":
                continue
            if path_result == FULL and not method_subset:
                return MATCH_FULL
            kinds.add(MATCH_VALUE if path_result == PARTIAL else MATCH_METHOD)
        if self.opaque:
            return MATCH_OPAQUE
        if MATCH_VALUE in kinds:
            return MATCH_VALUE
        if MATCH_METHOD in kinds:
            return MATCH_METHOD
        return MATCH_NONE


@dataclass
class Rule:
    matcher: Matcher
    decision: str  # ANONYMOUS / REQUIRED / UNKNOWN
    guard: str  # e.g. `hasAuthority("ADMIN")`
    evidence: str  # `file:line <source text>`


@dataclass
class SecurityChain:
    file: str
    rules: list[Rule]
    # The chain's securityMatcher; None when the chain matches every request.
    scope: Matcher | None = None


@dataclass
class FileSecurity:
    chains: list[SecurityChain] = field(default_factory=list)
    # `web.ignoring()` rules: these requests skip every chain.
    ignored: list[Rule] = field(default_factory=list)


# ---------- Path matching ----------


def _segments(path: str) -> list[str] | None:
    segs = [s for s in path.split("/") if s]
    if len(segs) > MAX_SEGMENTS or any(len(s) > MAX_SEGMENT_CHARS for s in segs):
        return None
    return segs


def _is_variable(seg: str) -> bool:
    """A route segment that stands for many values (`{id}`, `{id}.json`, `*`)."""
    return "{" in seg or "*" in seg


def _glob_match(pattern: str, text: str) -> bool:
    """`*`/`?` wildcard match of one segment (`{var}` already turned into `*`).

    Dynamic programming, O(len(pattern) * len(text)); no regex backtracking.
    """
    prev = [False] * (len(text) + 1)
    prev[0] = True
    for p in pattern:
        cur = [False] * (len(text) + 1)
        if p == "*":
            cur[0] = prev[0]
            for j in range(1, len(text) + 1):
                cur[j] = prev[j] or cur[j - 1]
        else:
            for j in range(1, len(text) + 1):
                cur[j] = prev[j - 1] and (p == "?" or p == text[j - 1])
        prev = cur
    return prev[len(text)]


def _template_to_glob(seg: str) -> tuple[str, bool]:
    """Replace `{var}` / `{var:regex}` with `*`. Returns (glob, had_regex)."""
    out: list[str] = []
    had_regex = False
    i = 0
    while i < len(seg):
        if seg[i] == "{":
            close = seg.find("}", i)
            if close == -1:
                out.append(seg[i:])
                break
            if ":" in seg[i:close]:
                had_regex = True
            out.append("*")
            i = close + 1
        else:
            out.append(seg[i])
            i += 1
    return "".join(out), had_regex


def _match_segment(pattern_seg: str, route_seg: str) -> int:
    if pattern_seg == "*":
        return FULL
    if pattern_seg.startswith("{") and pattern_seg.endswith("}") and pattern_seg.count("{") == 1:
        # `{var}` matches any one segment; `{var:regex}` only some of them.
        return PARTIAL if ":" in pattern_seg else FULL
    is_glob = any(c in pattern_seg for c in "*?{")
    if _is_variable(route_seg):
        if is_glob:
            return PARTIAL
        # Some values of the route variable equal the literal, unless the
        # route segment's own literal parts rule it out (`*.lesson` vs `favicon.ico`).
        route_glob, _ = _template_to_glob(route_seg)
        return PARTIAL if _glob_match(route_glob, pattern_seg) else NONE
    if not is_glob:
        return FULL if pattern_seg == route_seg else NONE
    glob, had_regex = _template_to_glob(pattern_seg)
    if not _glob_match(glob, route_seg):
        return NONE
    return PARTIAL if had_regex else FULL


def match_path(pattern: str, path: str) -> int:
    """Match an Ant/PathPattern ``pattern`` against a route path template.

    FULL when every request to the route matches, PARTIAL when some might,
    NONE when none can. `/api/**` matches `/api` too, as in Spring.
    """
    if len(pattern) > MAX_PATTERN_CHARS:
        return PARTIAL
    psegs = _segments(pattern)
    rsegs = _segments(path)
    if psegs is None or rsegs is None or sum(s == "**" or s.startswith("{*") for s in psegs) > MAX_DOUBLE_WILDCARDS:
        return PARTIAL
    memo: dict[tuple[int, int], int] = {}

    def walk(i: int, j: int) -> int:
        key = (i, j)
        if key in memo:
            return memo[key]
        if i == len(psegs):
            result = FULL if j == len(rsegs) else NONE
        else:
            p = psegs[i]
            if p == "**" or (p.startswith("{*") and p.endswith("}")):
                result = walk(i + 1, j)
                k = j
                while result != FULL and k < len(rsegs):
                    result = max(result, walk(i + 1, k + 1))
                    k += 1
            elif j == len(rsegs):
                result = NONE
            else:
                seg = _match_segment(p, rsegs[j])
                result = NONE if seg == NONE else min(seg, walk(i + 1, j + 1))
        memo[key] = result
        return result

    return walk(0, 0)


# ---------- Argument readers ----------


def _string_literal(text: str) -> str | None:
    m = _STRING_LITERAL_RE.fullmatch(text.strip())
    if m is None:
        return None
    value = m.group(1)
    # A Kotlin string template isn't a fixed pattern.
    return None if "$" in value else value


def _with_slash(pattern: str) -> str:
    return pattern if pattern.startswith("/") else "/" + pattern


def read_matcher_args(args: str, *, depth: int = 0) -> Matcher:
    """Read `requestMatchers(...)`-style arguments into a Matcher.

    Arguments are an optional `HttpMethod.X` followed by path patterns or
    matcher objects. Anything unreadable makes the matcher opaque.
    """
    matcher = Matcher()
    method: str | None = None
    patterns: list[str] = []
    parts = split_top_level(args)
    for part in parts[:MAX_ENTRIES_PER_MATCHER]:
        literal = _string_literal(part)
        if literal is not None:
            patterns.append(_with_slash(literal))
            continue
        m = _HTTP_METHOD_ARG_RE.fullmatch(part)
        if m:
            if m.group(1) in HTTP_METHODS:
                method = m.group(1)
            else:
                matcher.opaque = True
            continue
        if _STATIC_RESOURCES_RE.fullmatch(part):
            matcher.entries.extend((None, p) for p in STATIC_RESOURCE_PATTERNS)
            continue
        if _ANY_REQUEST_ARG_RE.fullmatch(part):
            matcher.entries.append((None, None))
            continue
        wrapper = _WRAPPER_RE.match(part)
        if wrapper and depth < 2:
            close = bracket_end(part, wrapper.end() - 1)
            if close == len(part):
                inner = _read_wrapper(wrapper.group(1), part[wrapper.end() : close - 1], depth)
                matcher.entries.extend(inner.entries)
                matcher.opaque = matcher.opaque or inner.opaque
                continue
        matcher.opaque = True
    if len(parts) > MAX_ENTRIES_PER_MATCHER:
        matcher.opaque = True
    if patterns:
        matcher.entries.extend((method, p) for p in patterns)
    elif method is not None and not matcher.entries and not matcher.opaque:
        # `antMatchers(HttpMethod.OPTIONS)`: every path for that method.
        matcher.entries.append((method, None))
    elif method is not None:
        matcher.entries = [(method, p) for _, p in matcher.entries]
    if not parts:
        matcher.opaque = True
    return matcher


def _read_wrapper(name: str, args: str, depth: int) -> Matcher:
    parts = split_top_level(args)
    if name == "MvcRequestMatcher":
        # new MvcRequestMatcher(introspector, "/x")
        parts = parts[1:]
    if name == "AntPathRequestMatcher" and len(parts) >= 2:
        # new AntPathRequestMatcher("/x", "POST"[, caseSensitive])
        pattern = _string_literal(parts[0])
        method = _string_literal(parts[1])
        if pattern is not None and method is not None and method.upper() in HTTP_METHODS:
            return Matcher(entries=[(method.upper(), _with_slash(pattern))])
        return Matcher(opaque=True)
    return read_matcher_args(", ".join(parts), depth=depth + 1)


def _decision(name: str, args: str | None) -> str:
    if name in _ANON_DECISIONS:
        return ANONYMOUS
    if name in _REQUIRED_DECISIONS:
        return REQUIRED
    if name == "access" and args is not None:
        args = args.strip()
        spel = _SPEL_ARG_RE.fullmatch(args)
        if spel is not None:
            required = _ACCESS_REQUIRED_RE.search(spel.group(1)) is not None
            permit = _ACCESS_PERMIT_RE.search(spel.group(1)) is not None
            # `isAnonymous() or isAuthenticated()` is neither.
            if required != permit:
                return REQUIRED if required else ANONYMOUS
            return UNKNOWN
        if _MANAGER_ARG_RE.fullmatch(args):
            return REQUIRED
    return UNKNOWN


def _kotlin_decision(expr: str) -> tuple[str, str]:
    """Decision of a Kotlin DSL `authorize(..., <expr>)` last argument."""
    expr = expr.strip()
    m = _IDENT_RE.match(expr)
    if m is None:
        return UNKNOWN, expr
    name = m.group(0)
    rest = expr[m.end():].strip()
    if rest and not (rest.startswith("(") and rest.endswith(")")):
        return UNKNOWN, expr
    return _decision(name, rest[1:-1] if rest.startswith("(") else None), expr


def _clip(text: str) -> str:
    text = " ".join(text.split())
    return text if len(text) <= _EVIDENCE_CHARS else text[: _EVIDENCE_CHARS - 1] + "…"


# ---------- Parsing ----------


def _skip_ws(text: str, i: int) -> int:
    n = len(text)
    while i < n and text[i].isspace():
        i += 1
    return i


def _chain_end(masked: str, start: int, brackets: BracketIndex) -> int:
    """End of a pre-lambda `.authorizeRequests()` chain: `.and()`, `;`, or the
    bracket that closes the enclosing expression."""
    limit = min(len(masked), start + MAX_BODY_CHARS)
    i = start
    while i < limit:
        c = masked[i]
        if c in "\"'":
            close = _skip_quoted(masked, i)
            i = close
            continue
        if c in "({[":
            close = brackets.close(i)
            if close is None:
                return limit
            i = close
            continue
        if c in ")}];":
            return i
        if c == "." and _AND_CALL_RE.match(masked, i, min(limit, i + 40)):
            return i
        i += 1
    return limit


def _skip_quoted(text: str, i: int) -> int:
    quote = text[i]
    j = i + 1
    while j < len(text):
        if text[j] == "\\":
            j += 2
            continue
        if text[j] == quote or text[j] == "\n":
            return j + 1
        j += 1
    return len(text)


def _authorize_body(masked: str, name_end: int, brackets: BracketIndex) -> tuple[int, int, int] | None:
    """(body_start, body_end, call_end) of the authorize call ending its name at ``name_end``."""
    i = _skip_ws(masked, name_end)
    if i >= len(masked):
        return None
    if masked[i] == "{":
        close = brackets.close(i)
        if close is None:
            return None
        return i + 1, close - 1, close
    if masked[i] != "(":
        return None
    close = brackets.close(i)
    if close is None:
        return None
    if masked[i + 1 : close - 1].strip():
        return i + 1, close - 1, close
    # Pre-lambda chain: `.authorizeRequests().antMatchers(...)...and()`; or a
    # Kotlin trailing lambda after empty parentheses.
    j = _skip_ws(masked, close)
    if j < len(masked) and masked[j] == "{":
        brace = brackets.close(j)
        if brace is None:
            return None
        return j + 1, brace - 1, brace
    end = _chain_end(masked, close, brackets)
    return close, end, end


class _Lines:
    """1-based line numbers by offset, from one pass over the file."""

    def __init__(self, text: str) -> None:
        self._newlines = [m.start() for m in _NEWLINE_RE.finditer(text)]

    def __call__(self, offset: int) -> int:
        return bisect_right(self._newlines, offset - 1) + 1


def _parse_rules(
    masked: str,
    start: int,
    end: int,
    file: str,
    rules: list[Rule],
    line_at: _Lines,
    budget: list[int],
    brackets: BracketIndex,
) -> None:
    """Append the rules found in ``masked[start:end]`` in source order.

    ``budget`` is the file's remaining rule allowance (shared across chains)."""
    pos = start
    while pos < end and len(rules) < MAX_RULES_PER_CHAIN and budget[0] > 0:
        m = _RULE_CALL_RE.search(masked, pos, end)
        if m is None:
            return
        # Every matcher call costs budget, not just the ones that become rules.
        budget[0] -= 1
        name = m.group(1)
        open_at = m.end() - 1
        close = brackets.close(open_at)
        if close is None or close > end or close - open_at > MAX_CALL_CHARS:
            return
        args = masked[open_at + 1 : close - 1]
        if name == "authorize":
            _kotlin_rule(masked, m.start(), close, args, file, rules, line_at)
            pos = close
            continue
        if name == "dispatcherTypeMatchers":
            # Forward/error dispatches, not requests to a route.
            pos = close
            continue
        if name in ("anyRequest", "anyExchange"):
            matcher = Matcher(entries=[(None, None)])
        elif name == "regexMatchers":
            matcher = Matcher(opaque=True)
        else:
            matcher = read_matcher_args(args)
        decision_call = _CHAINED_CALL_RE.match(masked, close, end)
        if decision_call is None:
            pos = close
            continue
        d_open = decision_call.end() - 1
        d_close = brackets.close(d_open)
        if d_close is None or d_close > end or d_close - d_open > MAX_CALL_CHARS:
            return
        d_name = decision_call.group(1)
        d_args = masked[d_open + 1 : d_close - 1]
        if d_name in _MATCHER_NAMES:
            # `antMatchers("/a").antMatchers(...)` isn't a rule.
            pos = close
            continue
        decision = _decision(d_name, d_args)
        guard = _clip(f"{d_name}({d_args.strip()})")
        evidence = _clip(f"{file}:{line_at(m.start())} {masked[m.start():d_close]}")
        rules.append(Rule(matcher, decision, guard, evidence))
        pos = d_close


def _kotlin_rule(
    masked: str, start: int, close: int, args: str, file: str, rules: list[Rule], line_at: _Lines
) -> None:
    parts = split_top_level(args)
    if len(parts) < 2:
        return
    decision, guard = _kotlin_decision(parts[-1])
    matcher = read_matcher_args(", ".join(parts[:-1]))
    evidence = _clip(f"{file}:{line_at(start)} {masked[start:close]}")
    rules.append(Rule(matcher, decision, _clip(guard), evidence))


class _BraceIndex:
    """Every `{...}` pair of a file from one linear pass, with parent links.

    Used to find the method body (the "unit") an `authorize*` call sits in:
    the outermost block below a class body, or the outermost block when there
    is no class (Kotlin top-level functions and `beans {}`).
    """

    def __init__(self, masked: str, brackets: BracketIndex) -> None:
        self.masked = masked
        self.starts = brackets.brace_starts
        self.ends = brackets.brace_ends
        self.parents = brackets.brace_parents
        self._class_body: dict[int, bool] = {}

    def _is_class_body(self, idx: int) -> bool:
        if idx not in self._class_body:
            start = self.starts[idx]
            header_start = max(0, start - 200)
            header = self.masked[header_start:start]
            cut = max(header.rfind(";"), header.rfind("{"), header.rfind("}"))
            self._class_body[idx] = _CLASS_HEADER_RE.search(header, cut + 1) is not None
        return self._class_body[idx]

    def unit(self, offset: int) -> tuple[int, int]:
        idx = bisect_right(self.starts, offset) - 1
        while idx >= 0 and self.ends[idx] <= offset:
            idx = self.parents[idx]
        if idx < 0:
            return 0, len(self.masked)
        while self.parents[idx] != -1 and not self._is_class_body(self.parents[idx]):
            idx = self.parents[idx]
        return self.starts[idx], self.ends[idx]


def _scope_matcher(
    masked: str, start: int, end: int, excluded: list[tuple[int, int]], brackets: BracketIndex
) -> Matcher | None:
    """A chain's securityMatcher scope inside ``masked[start:end]``, or None."""
    scope: Matcher | None = None
    pos = start
    for _ in range(MAX_SCOPE_CALLS):
        m = _SCOPE_CALL_RE.search(masked, pos, end)
        if m is None:
            break
        if any(a <= m.start() < b for a, b in excluded) or _static_call(masked, m):
            pos = m.end()
            continue
        open_at = m.end() - 1
        close = brackets.close(open_at)
        if close is None or close > end or close - open_at > MAX_CALL_CHARS:
            break
        args = masked[open_at + 1 : close - 1]
        if scope is None:
            scope = Matcher()
        name = m.group(1) or m.group(2)
        if name == "regexMatcher":
            scope.opaque = True
        elif not args.strip():
            # `http.requestMatchers().antMatchers("/api/**")...`
            chained = _read_chained_matchers(masked, close, end, brackets)
            scope.entries.extend(chained.entries)
            scope.opaque = scope.opaque or chained.opaque or not chained.entries
        elif "->" in args or "{" in args:
            # `securityMatchers(m -> m.requestMatchers("/api/**"))`: literals only.
            literals = [_with_slash(v) for v in _STRING_LITERAL_RE.findall(args) if "$" not in v]
            scope.entries.extend((None, p) for p in literals[:MAX_ENTRIES_PER_MATCHER])
            scope.opaque = scope.opaque or not literals
        else:
            inner = read_matcher_args(args)
            scope.entries.extend(inner.entries)
            scope.opaque = scope.opaque or inner.opaque
        pos = close
    return scope


def _static_call(masked: str, m: re.Match[str]) -> bool:
    """`AntPathRequestMatcher.antMatcher("/x")` builds a matcher for something
    else (CSRF, an entry point); only `http.antMatcher(...)` scopes the chain."""
    if m.group(2) is None:
        return False
    before = _TRAILING_IDENT_RE.search(masked, max(0, m.start() - 80), m.start())
    return before is not None and before.group(1)[0].isupper()


def _read_chained_matchers(masked: str, pos: int, end: int, brackets: BracketIndex) -> Matcher:
    """`.antMatchers("/a").mvcMatchers("/b")...` calls chained at ``pos``."""
    matcher = Matcher()
    for _ in range(MAX_ENTRIES_PER_MATCHER):
        call = _CHAINED_CALL_RE.match(masked, pos, end)
        if call is None or call.group(1) not in _MATCHER_NAMES:
            break
        open_at = call.end() - 1
        close = brackets.close(open_at)
        if close is None or close > end or close - open_at > MAX_CALL_CHARS:
            break
        if call.group(1) == "regexMatchers":
            matcher.opaque = True
        else:
            inner = read_matcher_args(masked[open_at + 1 : close - 1])
            matcher.entries.extend(inner.entries)
            matcher.opaque = matcher.opaque or inner.opaque
        pos = close
    return matcher


def parse_security(masked: str, file: str) -> FileSecurity:
    """Every security chain and `web.ignoring()` rule in one comment-masked file."""
    found = FileSecurity()
    if not SECURITY_GATE_RE.search(masked):
        return found
    brackets = BracketIndex(masked)
    braces = _BraceIndex(masked, brackets)
    line_at = _Lines(masked)
    budget = [MAX_RULES_PER_FILE]
    calls = 0
    units: dict[tuple[int, int], tuple[list[Rule], list[tuple[int, int]]]] = {}
    for m in _AUTHORIZE_RE.finditer(masked):
        calls += 1
        if len(units) >= MAX_CHAINS or calls > MAX_AUTHORIZE_CALLS:
            break
        body = _authorize_body(masked, m.end(), brackets)
        if body is None:
            continue
        body_start, body_end, call_end = body
        unit = braces.unit(m.start())
        rules, spans = units.setdefault(unit, ([], []))
        spans.append((m.start(), call_end))
        _parse_rules(masked, body_start, body_end, file, rules, line_at, budget, brackets)
    for (unit_start, unit_end), (rules, spans) in units.items():
        scope = _scope_matcher(masked, unit_start, unit_end, spans, brackets)
        found.chains.append(SecurityChain(file=file, rules=rules, scope=scope))

    for count, m in enumerate(_IGNORING_RE.finditer(masked)):
        if count >= MAX_IGNORING_CALLS:
            break
        call = _CHAINED_CALL_RE.match(masked, m.end())
        if call is None or call.group(1) not in _MATCHER_NAMES:
            continue
        matcher = _read_chained_matchers(masked, m.end(), min(len(masked), m.end() + MAX_BODY_CHARS), brackets)
        if not matcher.entries and not matcher.opaque:
            continue
        evidence = _clip(f"{file}:{line_at(m.start())} web.{masked[m.start():m.end()]}…")
        found.ignored.append(Rule(matcher, ANONYMOUS, "web.ignoring()", evidence))
        if len(found.ignored) >= MAX_RULES_PER_CHAIN:
            break
    return found


# ---------- Resolution ----------


@dataclass
class Resolution:
    decision: str  # ANONYMOUS / REQUIRED
    guards: list[str]
    evidence: str


def evaluate_rules(rules: list[Rule], path: str, method: str) -> Rule | None | str:
    """First-match evaluation of ``rules`` for one route.

    Returns the deciding Rule, None (no rule can match), or UNKNOWN. A rule
    that only *might* match changes the outcome as follows:

    - `opaque` (unreadable matcher): the first full match decides only if the
      opaque rules before it agree with it;
    - `value` (a literal such as `/articles/feed` against `/articles/{slug}`):
      those requests may even go to another handler, so the generic remainder
      decides when it is anonymous; a `required` remainder needs every such
      rule to be `required` too;
    - `method` (`POST /users` against a method-less `/users` mapping): an
      anonymous one makes the handler reachable without auth, so it decides
      unless an earlier possible match could have caught those requests first.
    """
    opaque: list[Rule] = []
    value: list[Rule] = []
    method_rules: list[Rule] = []
    reachable_by_method: Rule | None = None
    for rule in rules:
        kind = rule.matcher.match(path, method)
        if kind == MATCH_NONE:
            continue
        if kind == MATCH_FULL:
            if rule.decision == UNKNOWN or any(r.decision != rule.decision for r in opaque):
                return UNKNOWN
            if rule.decision == ANONYMOUS:
                return rule
            if reachable_by_method is not None:
                return reachable_by_method
            if any(r.decision != REQUIRED for r in (*value, *method_rules)):
                return UNKNOWN
            return rule
        if kind == MATCH_OPAQUE:
            opaque.append(rule)
        elif kind == MATCH_VALUE:
            value.append(rule)
        else:
            if (
                rule.decision == ANONYMOUS
                and reachable_by_method is None
                and all(r.decision == ANONYMOUS for r in (*opaque, *method_rules))
            ):
                reachable_by_method = rule
            method_rules.append(rule)
    if reachable_by_method is not None:
        return reachable_by_method
    return UNKNOWN if (opaque or value or method_rules) else None


def _resolve_chain(chain: SecurityChain, ignored: list[Rule], path: str, method: str) -> Rule | None:
    outcome = evaluate_rules([*ignored, *chain.rules], path, method)
    return outcome if isinstance(outcome, Rule) else None


def resolve_route(
    chains: list[SecurityChain],
    ignored: list[Rule],
    path: str,
    method: str,
    route_dir: str,
) -> Resolution | None:
    """The auth state the filter chains give a route, or None when unknown.

    A chain whose securityMatcher fully matches the route is preferred over
    catch-all chains (Spring requires the catch-all chain to come last). When
    several chains could apply, they must agree; chains whose config file sits
    in a parent package of the route are preferred (Spring Boot component scan),
    which separates two applications living in one module.
    """
    if not chains:
        return None
    full: list[SecurityChain] = []
    partial: list[SecurityChain] = []
    catch_all: list[SecurityChain] = []
    for chain in chains:
        if chain.scope is None:
            catch_all.append(chain)
            continue
        result = chain.scope.match(path, method)
        if result == MATCH_FULL:
            full.append(chain)
        elif result != MATCH_NONE:
            partial.append(chain)
    considered = full + partial if full else partial + catch_all
    if not considered:
        return None
    if len(considered) > 1:
        nearby = [c for c in considered if _is_ancestor_dir(_dirname(c.file), route_dir)]
        if nearby and len(nearby) < len(considered) and not partial:
            considered = nearby
    decided: list[Rule] = []
    for chain in considered:
        rule = _resolve_chain(chain, ignored, path, method)
        if rule is None:
            return None
        decided.append(rule)
    decisions = {rule.decision for rule in decided}
    if len(decisions) != 1:
        return None
    decision = decisions.pop()
    guards = list(dict.fromkeys(rule.guard for rule in decided)) if decision == REQUIRED else []
    return Resolution(decision, guards, decided[0].evidence)


def _dirname(path: str) -> str:
    return path.rsplit("/", 1)[0] if "/" in path else ""


def _is_ancestor_dir(ancestor: str, path_dir: str) -> bool:
    if not ancestor:
        return True
    return path_dir == ancestor or path_dir.startswith(ancestor + "/")


__all__ = [
    "ANONYMOUS",
    "FileSecurity",
    "Matcher",
    "REQUIRED",
    "Resolution",
    "Rule",
    "SecurityChain",
    "UNKNOWN",
    "evaluate_rules",
    "match_path",
    "parse_security",
    "read_matcher_args",
    "resolve_route",
]
