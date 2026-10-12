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


def _table(*sources: str, kotlin: bool = False) -> ConstantTable:
    table = ConstantTable()
    for source in sources:
        table.collect(mask_comments(source), kotlin=kotlin)
    return table


def test_collects_java_static_final_and_kotlin_const_val() -> None:
    table = _table(_AUTHORITIES)
    table.collect(mask_comments(
        'object Roles { const val USER = "ROLE_USER" }\n'
        'class Paths { companion object { const val ADMIN: String = "/admin" } }\n'
        'const val TOP = "/top"\n'
    ), kotlin=True)
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
    # Past the per-file cap declarations were dropped, so nothing resolves.
    assert table.overflow
    assert table.lookup("K.C10") is None


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


# ---------- Review: never resolve to the wrong value ----------


@pytest.mark.parametrize(
    ("declaration", "expected"),
    [
        ('const val R = "ROLE_" + "ANONYMOUS"', "ROLE_ANONYMOUS"),
        ('const val R: String = "ROLE_ADMIN"', "ROLE_ADMIN"),
        ('const val R = """ROLE_ANONYMOUS"""', None),
        ('const val R = "ROLE_" + OTHER', None),
        ('const val R = "ROLE_$X"', None),
        ('const val R =\n        "ROLE_ADMIN"', None),
        ('val R = "ROLE_ADMIN"', None),
    ],
)
def test_kotlin_const_val_reads_the_whole_value(declaration: str, expected: str | None) -> None:
    table = _table(f"object Roles {{\n    {declaration}\n}}\n", kotlin=True)
    assert table.lookup("Roles.R") == expected


@pytest.mark.parametrize(
    ("other", "expected"),
    [
        # The same declaration again (another copy of the file) is fine.
        ('package b; class Roles { public static final String ADMIN = "ROLE_ADMIN"; }', "ROLE_ADMIN"),
        # Any other declaration of Roles.ADMIN poisons the key.
        ('package b; class Roles { public static final String ADMIN = "ROLE_ROOT"; }', None),
        ('package b; class Roles { public static String ADMIN = "ROLE_ADMIN"; }', None),
        ('package b; class Roles { static final Object ADMIN = "ROLE_ADMIN"; }', None),
        ("package b; class Roles { static final String ADMIN; static { ADMIN = load(); } }", None),
        ('package b; class Roles { static final String ADMIN = System.getenv("R"); }', None),
        ('package b; class Roles { static final String ADMIN = """\n  ROLE_ADMIN"""; }', None),
        ('class Sec { static class Roles { static final String ADMIN = "ROLE_ANONYMOUS"; } }', None),
        ("enum Roles { ADMIN, USER }", None),
        ('package b; class Roles { static final String A = "x", ADMIN = "ROLE_ADMIN"; }', None),
    ],
)
def test_every_declaration_of_a_key_must_agree(other: str, expected: str | None) -> None:
    base = 'package a; public final class Roles { public static final String ADMIN = "ROLE_ADMIN"; }'
    assert _table(base, other).lookup("Roles.ADMIN") == expected


def test_kotlin_property_poisons_a_java_constant_of_the_same_key() -> None:
    table = _table('class Roles { static final String ADMIN = "ROLE_ADMIN"; }')
    table.collect(mask_comments('class Roles { companion object { var ADMIN = "ROLE_ANONYMOUS" } }'), kotlin=True)
    assert table.lookup("Roles.ADMIN") is None


def test_enums_records_and_interfaces_are_keyed_under_their_own_name() -> None:
    table = _table(
        'enum Level { LOW, HIGH("h"); public static final String PREFIX = "ROLE_"; Level() {} Level(String s) {} }\n'
        'record Point(int x) { static final String KIND = "point"; }\n'
        'interface Roles { String ADMIN = "ROLE_ADMIN"; Object OTHER = "x"; String user(); }\n'
    )
    assert table.lookup("Level.LOW") is None  # an enum constant, not a String
    assert table.lookup("Level.HIGH") is None
    assert table.lookup("Level.PREFIX") == "ROLE_"
    assert table.lookup("Point.KIND") == "point"
    assert table.lookup("Roles.ADMIN") == "ROLE_ADMIN"  # implicitly static final
    assert table.lookup("Roles.OTHER") is None


def test_hitting_the_constant_cap_makes_every_lookup_fail(monkeypatch: pytest.MonkeyPatch) -> None:
    import attackmap_analyzer_java_spring.constants as constants

    monkeypatch.setattr(constants, "MAX_CONSTANTS", 2)
    table = _table('class A { static final String X = "a"; static final String Y = "b"; }')
    assert table.lookup("A.X") == "a"
    # A third declaration (which might have conflicted) is dropped: nothing resolves now.
    table.collect(mask_comments('class A { static final String X = "c"; }'))
    assert table.overflow and table.lookup("A.X") is None


def test_kotlin_concatenated_anonymous_constant_is_not_required(tmp_path: Path) -> None:
    _write(tmp_path, "pom.xml", _BOOT3_POM)
    _write(tmp_path, "src/main/kotlin/Roles.kt", 'object Roles {\n    const val ANON = "ROLE_" + "ANONYMOUS"\n}\n')
    _write(tmp_path, "src/main/java/Api.java", '@RestController class Api { @PostMapping("/x") Object a() { return null; } }\n')
    _write(tmp_path, "src/main/java/Sec.java", (
        "class Sec { SecurityFilterChain c(HttpSecurity http) {\n"
        "    return http.authorizeHttpRequests(a -> a.requestMatchers(\"/x\").hasAuthority(Roles.ANON)"
        ".anyRequest().authenticated()).build(); } }\n"
    ))
    assert JavaSpringAnalyzer().analyze(tmp_path).routes[0].auth == "anonymous"


def test_java_constant_split_across_lines() -> None:
    table = _table('class Roles {\n    public static final String ADMIN =\n        "ROLE_" +\n        "ADMIN";\n}\n')
    assert table.lookup("Roles.ADMIN") == "ROLE_ADMIN"
