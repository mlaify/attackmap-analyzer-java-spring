"""Same-repo string constants in Spring Security arguments (#11)."""

from __future__ import annotations

import random
import time
from pathlib import Path

import pytest

from attackmap_analyzer_java_spring import JavaSpringAnalyzer
from attackmap_analyzer_java_spring.annotations import mask_comments
from attackmap_analyzer_java_spring.constants import ConstantTable, resolve_expression

_BOOT3_POM = (
    "<project><parent><groupId>org.springframework.boot</groupId>"
    "<artifactId>spring-boot-starter-parent</artifactId><version>3.2.5</version></parent></project>"
)
_AUTHORITIES = (
    "package app.security;\n"
    "public final class AuthoritiesConstants {\n"
    '    public static final String ADMIN = "ROLE_ADMIN";\n'
    '    public static final String ANONYMOUS = "ROLE_ANONYMOUS";\n'
    '    public static final String API = "/api";\n'
    '    private final String notStatic = "x";\n'
    "    public static final String DERIVED = ADMIN + \"_X\";\n"
    "    private AuthoritiesConstants() {}\n"
    "}\n"
)


def _write(root: Path, rel: str, text: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _table(*sources: str) -> ConstantTable:
    table = ConstantTable()
    for source in sources:
        table.collect(mask_comments(source))
    return table


def test_collects_java_static_final_and_kotlin_const_val() -> None:
    table = _table(
        _AUTHORITIES,
        'object Roles { const val USER = "ROLE_USER" }\n'
        'class Paths { companion object { const val ADMIN: String = "/admin" } }\n'
        'const val TOP = "/top"\n',
    )
    assert table.lookup("AuthoritiesConstants.ADMIN") == "ROLE_ADMIN"
    assert table.lookup("Roles.USER") == "ROLE_USER"
    assert table.lookup("Paths.ADMIN") == "/admin"
    # Not static, not a plain literal, or top-level: not collected.
    assert table.lookup("AuthoritiesConstants.notStatic") is None
    assert table.lookup("AuthoritiesConstants.DERIVED") is None


def test_ambiguous_constants_stay_unresolved() -> None:
    a = 'class Roles { static final String ADMIN = "ROLE_ADMIN"; }\n'
    b = 'class Roles { static final String ADMIN = "ROLE_ROOT"; }\n'
    assert _table(a, b).lookup("Roles.ADMIN") is None
    assert _table(a, a).lookup("Roles.ADMIN") == "ROLE_ADMIN"  # same value twice is fine


@pytest.mark.parametrize(
    ("expr", "expected"),
    [
        ('"/a"', "/a"),
        ('"hasAuthority(\\"" + AuthoritiesConstants.ADMIN + "\\")"', 'hasAuthority("ROLE_ADMIN")'),
        ("AuthoritiesConstants.API + \"/**\"", "/api/**"),
        ("app.security.AuthoritiesConstants.ADMIN", "ROLE_ADMIN"),
        ("AuthoritiesConstants.MISSING", None),
        ("ADMIN", None),  # unqualified (static import or same class)
        ('"$base/x"', None),
        ("Roles.of(AuthoritiesConstants.ADMIN)", None),
        ("flag ? AuthoritiesConstants.ADMIN : \"x\"", None),
        ("", None),
    ],
)
def test_resolve_expression(expr: str, expected: str | None) -> None:
    assert resolve_expression(expr, _table(_AUTHORITIES)) == expected


def test_resolution_never_raises_on_garbage() -> None:
    rng = random.Random(11)
    table = _table(_AUTHORITIES)
    alphabet = 'A.B+"\\ $(){}x_ static final String const val = ;\n'
    for _ in range(500):
        text = "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 120)))
        resolve_expression(text, table)
        ConstantTable().collect(text)


def test_collection_is_bounded() -> None:
    body = "".join(f'    static final String C{i} = "v{i}";\n' for i in range(5000))
    start = time.perf_counter()
    table = _table("class K {\n" + body + "}\n")
    assert time.perf_counter() - start < 5
    assert table.lookup("K.C10") == "v10"
    assert table.lookup("K.C4999") is None  # past the per-file cap


def _app(tmp_path: Path, controller: str, rules: str) -> dict[tuple[str, str], str]:
    _write(tmp_path, "pom.xml", _BOOT3_POM)
    _write(tmp_path, "src/main/java/app/security/AuthoritiesConstants.java", _AUTHORITIES)
    _write(tmp_path, "src/main/java/app/Api.java", controller)
    _write(tmp_path, "src/main/java/app/Sec.java", (
        "@EnableMethodSecurity(securedEnabled = true)\n"
        f"class Sec {{ SecurityFilterChain c(HttpSecurity http) {{\n    return http.authorizeHttpRequests(a -> a{rules}).build(); }} }}\n"
    ))
    return {(r.method, r.path): r.auth for r in JavaSpringAnalyzer().analyze(tmp_path).routes}


def test_constant_authorities_in_rules(tmp_path: Path) -> None:
    auth = _app(
        tmp_path,
        '@RestController class Api {\n'
        '    @PostMapping("/api/admin/users") Object a() { return null; }\n'
        '    @PostMapping("/api/open") Object b() { return null; }\n'
        '    @PostMapping("/api/other") Object c() { return null; }\n'
        '}\n',
        '.requestMatchers(AuthoritiesConstants.API + "/admin/**").hasAuthority(AuthoritiesConstants.ADMIN)'
        '.requestMatchers("/api/open").hasAnyAuthority(AuthoritiesConstants.ANONYMOUS, "ROLE_USER")'
        '.requestMatchers("/api/other").hasAuthority(Unknown.ROLE)'
        '.anyRequest().permitAll()',
    )
    assert auth[("POST", "/api/admin/users")] == "required"
    assert auth[("POST", "/api/open")] == "anonymous"
    assert auth[("POST", "/api/other")] == "unknown"


def test_constant_authorities_in_method_security(tmp_path: Path) -> None:
    auth = _app(
        tmp_path,
        '@RestController class Api {\n'
        '    @PreAuthorize("hasAuthority(\\"" + AuthoritiesConstants.ADMIN + "\\")")\n'
        '    @PostMapping("/pre") Object a() { return null; }\n'
        '    @Secured({AuthoritiesConstants.ADMIN, "ROLE_OPS"}) @PostMapping("/secured") Object b() { return null; }\n'
        '    @Secured(AuthoritiesConstants.ANONYMOUS) @PostMapping("/anon") Object c() { return null; }\n'
        '    @PreAuthorize("hasRole(\'" + Missing.ROLE + "\')") @PostMapping("/missing") Object d() { return null; }\n'
        '}\n',
        ".anyRequest().permitAll()",
    )
    assert auth == {
        ("POST", "/pre"): "required",
        ("POST", "/secured"): "required",
        ("POST", "/anon"): "anonymous",
        ("POST", "/missing"): "unknown",
    }


def test_constants_declared_only_in_tests_are_not_used(tmp_path: Path) -> None:
    _write(tmp_path, "pom.xml", _BOOT3_POM)
    _write(tmp_path, "src/test/java/TestRoles.java", 'class TestRoles { static final String ADMIN = "ROLE_ADMIN"; }\n')
    _write(tmp_path, "src/main/java/Api.java", '@RestController class Api { @PostMapping("/x") Object a() { return null; } }\n')
    _write(tmp_path, "src/main/java/Sec.java", (
        "class Sec { SecurityFilterChain c(HttpSecurity http) {\n"
        "    return http.authorizeHttpRequests(a -> a.requestMatchers(\"/x\").hasAuthority(TestRoles.ADMIN)"
        ".anyRequest().permitAll()).build(); } }\n"
    ))
    assert JavaSpringAnalyzer().analyze(tmp_path).routes[0].auth == "unknown"
