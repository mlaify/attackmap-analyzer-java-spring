"""Functional routes, Spring Security HttpSecurity rules and JAX-RS pairing (#3).

Each test writes realistic Java/Kotlin into tmp_path and asserts on the
resulting routes and their `auth` / `guards` / `guard_evidence`.
"""

from __future__ import annotations

import random
from pathlib import Path

import pytest

from attackmap_analyzer_java_spring import JavaSpringAnalyzer
from attackmap_analyzer_java_spring.annotations import BracketIndex, mask_comments, match_bracket
from attackmap_analyzer_java_spring.functional import functional_routes
from attackmap_analyzer_java_spring.security_dsl import (
    FULL,
    NONE,
    PARTIAL,
    match_path,
    parse_security,
    read_matcher_args,
)


def _write(root: Path, rel: str, text: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _routes(result) -> set[tuple[str, str]]:
    return {(r.method, r.path) for r in result.routes}


def _auth(result) -> dict[tuple[str, str], str]:
    return {(r.method, r.path): r.auth for r in result.routes}


def _route(result, method: str, path: str):
    return next(r for r in result.routes if (r.method, r.path) == (method, path))


# ---------- Functional endpoints ----------


def test_java_router_functions_route_and_route_and_nest(tmp_path: Path) -> None:
    _write(tmp_path, "Router.java", (
        'import org.springframework.web.reactive.function.server.RouterFunction;\n'
        'import static org.springframework.web.reactive.function.server.RequestPredicates.*;\n'
        'import static org.springframework.web.reactive.function.server.RouterFunctions.*;\n'
        '\n'
        '@Configuration\n'
        'public class Router {\n'
        '    @Bean\n'
        '    RouterFunction<ServerResponse> routes(ItemHandler h) {\n'
        '        return RouterFunctions.route(GET("/fn/items/{id}"), h::get)\n'
        '            .andRoute(POST("/fn/items").and(accept(APPLICATION_JSON)), h::create)\n'
        '            .andNest(path("/api"), route(DELETE("/items/{id}"), h::delete)\n'
        '                .andRoute(RequestPredicates.PUT("/items/{id}"), h::update))\n'
        '            .andNest(accept(APPLICATION_JSON), route(GET("/plain"), h::plain));\n'
        '    }\n'
        '\n'
        '    RouterFunction<ServerResponse> nested(ItemHandler h) {\n'
        '        return nest(RequestPredicates.path("/v1"), nest(path("/inner"), route(GET(""), h::list)));\n'
        '    }\n'
        '}\n'
    ))
    result = JavaSpringAnalyzer().analyze(tmp_path)
    assert _routes(result) == {
        ("GET", "/fn/items/{id}"),
        ("POST", "/fn/items"),
        ("DELETE", "/api/items/{id}"),
        ("PUT", "/api/items/{id}"),
        ("GET", "/plain"),
        ("GET", "/v1/inner"),
    }
    assert _route(result, "GET", "/fn/items/{id}").line == 9


def test_java_route_builder_with_path_and_nest(tmp_path: Path) -> None:
    _write(tmp_path, "Routes.java", (
        'import org.springframework.web.servlet.function.RouterFunction;\n'
        'import static org.springframework.web.servlet.function.RouterFunctions.route;\n'
        'import static org.springframework.web.servlet.function.RequestPredicates.*;\n'
        '\n'
        'class Routes {\n'
        '    RouterFunction<ServerResponse> routes(PersonHandler h) {\n'
        '        return route()\n'
        '            .GET("/people/{id}", accept(APPLICATION_JSON), h::getPerson)\n'
        '            .POST("/people", h::createPerson)\n'
        '            .path("/admin", b -> b\n'
        '                .DELETE("/people/{id}", h::delete)\n'
        '                .nest(path("/audit"), b2 -> b2.GET("/log", h::log)))\n'
        '            .nest(accept(APPLICATION_JSON), b -> b.PATCH("/people/{id}", h::patch))\n'
        '            .build();\n'
        '    }\n'
        '}\n'
    ))
    result = JavaSpringAnalyzer().analyze(tmp_path)
    assert _routes(result) == {
        ("GET", "/people/{id}"),
        ("POST", "/people"),
        ("DELETE", "/admin/people/{id}"),
        ("GET", "/admin/audit/log"),
        ("PATCH", "/people/{id}"),
    }


def test_kotlin_router_and_corouter_dsl(tmp_path: Path) -> None:
    _write(tmp_path, "Routes.kt", (
        'import org.springframework.web.reactive.function.server.coRouter\n'
        'import org.springframework.web.servlet.function.router\n'
        '\n'
        'fun mvcRoutes(h: UserHandler) = router {\n'
        '    "/api".nest {\n'
        '        GET("/users", h::list)\n'
        '        accept(APPLICATION_JSON).nest {\n'
        '            POST("/users", h::create)\n'
        '        }\n'
        '        path("/admin").nest {\n'
        '            DELETE("/users/{id}") { req -> ok().build() }\n'
        '        }\n'
        '    }\n'
        '    GET("/", h::index)\n'
        '    resources("/**", ClassPathResource("static/"))\n'
        '}\n'
        '\n'
        'fun reactiveRoutes(h: UserHandler) = coRouter {\n'
        '    "/v2" nest {\n'
        '        GET("/users/{id}", h::get)\n'
        '    }\n'
        '}\n'
    ))
    result = JavaSpringAnalyzer().analyze(tmp_path)
    assert _routes(result) == {
        ("GET", "/api/users"),
        ("POST", "/api/users"),
        ("DELETE", "/api/admin/users/{id}"),
        ("GET", "/"),
        ("GET", "/v2/users/{id}"),
    }


def test_functional_routes_need_the_functional_api(tmp_path: Path) -> None:
    # Uppercase GET("...") calls in a file that doesn't use the functional API
    # (here a custom DSL) are not routes.
    _write(tmp_path, "Dsl.java", (
        'public class Dsl {\n'
        '    void setup() { GET("/not/a/route"); POST("/nope"); }\n'
        '}\n'
    ))
    assert JavaSpringAnalyzer().analyze(tmp_path).routes == []


def test_functional_routes_skip_unreadable_paths_and_annotations(tmp_path: Path) -> None:
    _write(tmp_path, "Mixed.kt", (
        'import org.springframework.web.reactive.function.server.router\n'
        '\n'
        'interface Api {\n'
        '    @GET("/retrofit/path")\n'
        '    fun call(): Call<Unit>\n'
        '}\n'
        '\n'
        'fun routes(h: H, base: String) = router {\n'
        '    GET(Paths.CONSTANT, h::x)\n'
        '    GET("$base/templated", h::y)\n'
        '    base.nest {\n'
        '        GET("/hidden", h::z)\n'
        '    }\n'
        '    (accept(TEXT_HTML) and "/html").nest {\n'
        '        GET("/page", h::page)\n'
        '    }\n'
        '    // GET("/commented", h::c)\n'
        '    GET("/ok", h::ok)\n'
        '}\n'
    ))
    result = JavaSpringAnalyzer().analyze(tmp_path)
    # Constant and templated paths are skipped, and so is everything inside a
    # nest whose prefix can't be read, rather than reported under a wrong path.
    assert _routes(result) == {("GET", "/ok")}


def test_functional_routes_reader_never_raises_on_garbage() -> None:
    rng = random.Random(1234)
    alphabet = 'GETPOSnest(path"/a{}).,->; \n route() andNest andRoute coRouter router'
    base = (
        'route(GET("/a"), h).andNest(path("/b"), route(POST("/c"), h))\n'
        'router { "/x".nest { GET("/y", h) } }\n'
    )
    for _ in range(400):
        text = "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 200)))
        functional_routes(text)
        cut = rng.randint(0, len(base))
        functional_routes(base[:cut])
        functional_routes(base[cut:] + text)


# ---------- Spring Security: matching ----------


@pytest.mark.parametrize(
    ("pattern", "path", "expected"),
    [
        ("/admin/**", "/admin/users", FULL),
        ("/admin/**", "/admin", FULL),
        ("/admin/**", "/administrator", NONE),
        ("/api/*", "/api/users", FULL),
        ("/api/*", "/api/users/1", NONE),
        ("/api/users/{id}", "/api/users/{login}", FULL),
        ("/api/users/*", "/api/users/{id}", FULL),
        ("/api/users/me", "/api/users/{id}", PARTIAL),
        ("/api/users/{id:\\d+}", "/api/users/{id}", PARTIAL),
        ("/*.js", "/main.js", FULL),
        ("/*.js", "/main.css", NONE),
        ("/favicon.*", "/favicon.ico", FULL),
        ("/favicon.ico", "/*.lesson", NONE),
        ("/files/{*rest}", "/files/a/b", FULL),
        # A multi-segment route wildcard is only covered by a pattern `**`.
        ("/files/*", "/files/**", PARTIAL),
        ("/files/{name}", "/files/{*rest}", PARTIAL),
        ("/files/**", "/files/**", FULL),
        ("/files/**", "/files/{*rest}", FULL),
        ("/files", "/files/**", PARTIAL),
        ("/other/*", "/files/**", NONE),
        # A pattern with a trailing slash never matches a path without one.
        ("/admin/", "/admin", NONE),
        ("/admin/", "/admin/", FULL),
        ("/**", "/", FULL),
        ("/a?c", "/abc", FULL),
    ],
)
def test_ant_pattern_matching(pattern: str, path: str, expected: int) -> None:
    assert match_path(pattern, path) == expected


def test_match_path_is_bounded_on_hostile_patterns() -> None:
    # Over the bounds (too many `**`, segments or characters): undecided.
    assert match_path("/" + "/".join(["**"] * 60) + "/x", "/" + "/".join(["a"] * 30)) == PARTIAL
    assert match_path("/x" * 1000, "/x") == PARTIAL
    assert match_path("/a", "/" + "/".join(["a"] * 40)) == PARTIAL
    # Within the bounds, still exact.
    assert match_path("/**/**/**/**/x", "/" + "/".join(["a"] * 30)) == NONE
    assert match_path("/**/**/**/**/x", "/" + "/".join(["a"] * 30) + "/x") == FULL
    assert match_path("/" + "*a" * 8, "/" + "a" * 120) == FULL
    assert match_path("/" + "*a" * 60, "/" + "a" * 120) == PARTIAL  # too many wildcards: undecided


def test_read_matcher_args_forms() -> None:
    m = read_matcher_args('HttpMethod.POST, "/a", "/b"')
    assert m.entries == [("POST", "/a", False), ("POST", "/b", False)] and not m.opaque
    assert read_matcher_args("HttpMethod.OPTIONS").entries == [("OPTIONS", None, True)]
    # Ant matchers don't cover `/x/` for `/x`; MVC-mirroring `mvc.pattern` does.
    assert read_matcher_args('antMatcher("/h2/**"), mvc.pattern("/x")').entries == [
        (None, "/h2/**", False),
        (None, "/x", True),
    ]
    assert read_matcher_args('new AntPathRequestMatcher("/x", "DELETE")').entries == [("DELETE", "/x", False)]
    # Ant never matches a pattern without a leading slash; other matchers may.
    assert read_matcher_args('"admin/**"').opaque
    assert read_matcher_args("url").opaque
    assert read_matcher_args("PathRequest.toStaticResources().atCommonLocations()").entries[0][:2] == (None, "/css/**")


@pytest.mark.parametrize(
    ("decision", "expected"),
    [
        ('access("hasRole(\'ADMIN\')")', "required"),
        ('access("permitAll")', "anonymous"),
        ('access("isAnonymous() or isAuthenticated()")', "unknown"),
        ('access("hasRole(\'A\') or hasIpAddress(\'10.0.0.1\')")', "unknown"),
        ('access("hasRole(\'A\') or permitAll")', "unknown"),
        ('access("hasRole(\'A\') or hasRole(\'B\')")', "required"),
        ('access("hasIpAddress(\'10.0.0.1\') and isAuthenticated()")', "required"),
        ('access("(hasRole(\'A\') or permitAll) and true")', "unknown"),
        ('access("!isAnonymous()")', "unknown"),
        ('access("hasAnyRole(\'ANONYMOUS\', \'USER\')")', "anonymous"),
        ('hasAnyRole("ANONYMOUS", "USER")', "anonymous"),
        ('hasAuthority("ROLE_ANONYMOUS")', "anonymous"),
        # A non-literal authority can't be read: it might be anonymous.
        ("hasAuthority(AuthoritiesConstants.ANONYMOUS)", "unknown"),
        ("hasAuthority(AuthoritiesConstants.ADMIN)", "unknown"),
        ('access("hasRole(@roles.ADMIN)")', "unknown"),
        ('access("#id == principal.id")', "unknown"),
        ('access("isAuthenticated() ? true : false")', "unknown"),
        ('access("hasRole(\'A\') eq true")', "unknown"),
        ('access("principal.enabled and isAuthenticated()")', "unknown"),
        ("access(AuthorityAuthorizationManager.hasRole(ROLE))", "unknown"),
        ('access(AuthorityAuthorizationManager.hasRole("ADMIN"))', "required"),
        ('hasAnyAuthority("ROLE_USER", "ROLE_ADMIN")', "required"),
        ('access("hasIpAddress(\'10.0.0.0/8\')")', "unknown"),
        ('access(new WebExpressionAuthorizationManager("isAuthenticated()"))', "required"),
        ("access(AuthenticatedAuthorizationManager.authenticated())", "required"),
        ("access(manager == null ? AuthenticatedAuthorizationManager.authenticated() : manager)", "unknown"),
        ("not().permitAll()", "unknown"),
        ("hasIpAddress(\"127.0.0.1\")", "unknown"),
        ("denyAll()", "required"),
        ("anonymous()", "anonymous"),
    ],
)
def test_access_decisions(decision: str, expected: str) -> None:
    text = "class S { void c(HttpSecurity http) { http.authorizeHttpRequests(a -> a.anyRequest()." + decision + "); } }"
    rules = parse_security(text, "S.java").chains[0].rules
    assert [r.decision for r in rules] == [expected]


# ---------- Spring Security: route auth ----------

_CONTROLLER = (
    'import org.springframework.web.bind.annotation.*;\n'
    '\n'
    '@RestController\n'
    'public class AdminController {\n'
    '    @PostMapping("/admin/users")\n'
    '    public Object create() { return null; }\n'
    '\n'
    '    @DeleteMapping("/admin/users/{id}")\n'
    '    public void delete() {}\n'
    '\n'
    '    @PostMapping("/api/orders")\n'
    '    public Object order() { return null; }\n'
    '}\n'
)


def test_permit_all_on_admin_makes_admin_routes_explicitly_anonymous(tmp_path: Path) -> None:
    _write(tmp_path, "src/main/java/app/AdminController.java", _CONTROLLER)
    _write(tmp_path, "src/main/java/app/SecurityConfig.java", (
        'import org.springframework.security.config.annotation.web.builders.HttpSecurity;\n'
        '\n'
        '@Configuration\n'
        '@EnableWebSecurity\n'
        'public class SecurityConfig {\n'
        '    @Bean\n'
        '    SecurityFilterChain filterChain(HttpSecurity http) throws Exception {\n'
        '        http.csrf(c -> c.disable())\n'
        '            .authorizeHttpRequests(auth -> auth\n'
        '                .requestMatchers("/admin/**").permitAll()\n'
        '                .anyRequest().authenticated());\n'
        '        return http.build();\n'
        '    }\n'
        '}\n'
    ))
    result = JavaSpringAnalyzer().analyze(tmp_path)
    admin = _route(result, "POST", "/admin/users")
    assert admin.auth == "anonymous"
    assert admin.guards == []
    assert admin.guard_evidence is not None
    assert "SecurityConfig.java:10" in admin.guard_evidence and "permitAll" in admin.guard_evidence
    assert _route(result, "DELETE", "/admin/users/{id}").auth == "anonymous"
    orders = _route(result, "POST", "/api/orders")
    assert orders.auth == "required"
    assert orders.guards == ["authenticated()"]


def test_rules_apply_in_first_match_order(tmp_path: Path) -> None:
    _write(tmp_path, "AdminController.java", _CONTROLLER)
    _write(tmp_path, "SecurityConfig.java", (
        'class SecurityConfig {\n'
        '    SecurityFilterChain chain(HttpSecurity http) {\n'
        '        http.authorizeHttpRequests(authz -> authz\n'
        '            .requestMatchers("/**").authenticated()\n'
        '            .requestMatchers("/admin/**").permitAll());\n'
        '        return http.build();\n'
        '    }\n'
        '}\n'
    ))
    result = JavaSpringAnalyzer().analyze(tmp_path)
    # `/**` comes first, so the later permitAll never applies.
    assert set(_auth(result).values()) == {"required"}


def test_specific_role_rule_before_catch_all(tmp_path: Path) -> None:
    _write(tmp_path, "pom.xml", _BOOT3_POM)
    _write(tmp_path, "AdminController.java", _CONTROLLER)
    _write(tmp_path, "SecurityConfig.java", (
        'class SecurityConfig {\n'
        '    SecurityFilterChain chain(HttpSecurity http) {\n'
        '        http.authorizeHttpRequests(authz -> authz\n'
        '            .requestMatchers(HttpMethod.DELETE, "/admin/users/*").hasRole("SUPER")\n'
        '            .requestMatchers("/admin/**").hasAuthority("ADMIN")\n'
        '            .anyRequest().permitAll());\n'
        '        if (dev) {\n'
        '            http.authorizeHttpRequests(authz -> authz.requestMatchers("/h2-console/**").permitAll());\n'
        '        }\n'
        '        return http.build();\n'
        '    }\n'
        '}\n'
    ))
    result = JavaSpringAnalyzer().analyze(tmp_path)
    assert _route(result, "DELETE", "/admin/users/{id}").guards == ['hasRole("SUPER")']
    assert _route(result, "POST", "/admin/users").guards == ['hasAuthority("ADMIN")']
    assert _route(result, "POST", "/api/orders").auth == "anonymous"


def test_pre_lambda_authorize_requests_chain(tmp_path: Path) -> None:
    _write(tmp_path, "Api.java", (
        'import org.springframework.web.bind.annotation.*;\n'
        'import static org.springframework.web.bind.annotation.RequestMethod.POST;\n'
        '@RestController\n'
        'class Api {\n'
        '    @GetMapping("/articles/feed") Object feed() { return null; }\n'
        '    @GetMapping("/articles/{slug}") Object article() { return null; }\n'
        '    @PutMapping("/articles/{slug}") Object update() { return null; }\n'
        '    @RequestMapping(path = "/users", method = POST) Object register() { return null; }\n'
        '    @RequestMapping("/any") Object any() { return null; }\n'
        '}\n'
    ))
    _write(tmp_path, "WebSecurityConfig.java", (
        'public class WebSecurityConfig extends WebSecurityConfigurerAdapter {\n'
        '  @Override\n'
        '  protected void configure(HttpSecurity http) throws Exception {\n'
        '    http.csrf().disable()\n'
        '        .authorizeRequests()\n'
        '        .antMatchers(HttpMethod.OPTIONS).permitAll()\n'
        '        .antMatchers(HttpMethod.GET, "/articles/feed").authenticated()\n'
        '        .antMatchers(HttpMethod.POST, "/users", "/users/login", "/any").permitAll()\n'
        '        .antMatchers(HttpMethod.GET, "/articles/**").permitAll()\n'
        '        .anyRequest().authenticated()\n'
        '        .and()\n'
        '        .httpBasic();\n'
        '  }\n'
        '}\n'
    ))
    result = JavaSpringAnalyzer().analyze(tmp_path)
    auth = _auth(result)
    # Spring Boot 2 routes `GET /articles/feed/` to the same handler, the Ant
    # pattern `/articles/feed` doesn't match it, and `/articles/**` permits it.
    assert auth[("GET", "/articles/feed")] == "unknown"
    # `/articles/feed` is one value of {slug}; the rest of the route is public.
    assert auth[("GET", "/articles/{slug}")] == "anonymous"
    assert auth[("PUT", "/articles/{slug}")] == "required"
    # `method = POST` (static import) is read as POST, not ANY.
    assert auth[("POST", "/users")] == "anonymous"
    # A method-less mapping reachable anonymously by POST is anonymous.
    assert auth[("ANY", "/any")] == "anonymous"


def test_partial_value_match_with_required_remainder_stays_unknown(tmp_path: Path) -> None:
    _write(tmp_path, "Api.java", (
        '@RestController\n'
        'class Api {\n'
        '    @GetMapping("/users/{id}") Object user() { return null; }\n'
        '}\n'
    ))
    _write(tmp_path, "Sec.java", (
        'class Sec {\n'
        '    SecurityFilterChain chain(HttpSecurity http) {\n'
        '        return http.authorizeHttpRequests(a -> a\n'
        '            .requestMatchers("/users/me").permitAll()\n'
        '            .anyRequest().authenticated()).build();\n'
        '    }\n'
        '}\n'
    ))
    result = JavaSpringAnalyzer().analyze(tmp_path)
    assert _route(result, "GET", "/users/{id}").auth == "unknown"


def test_kotlin_security_dsl(tmp_path: Path) -> None:
    _write(tmp_path, "Api.kt", (
        'import org.springframework.web.bind.annotation.*\n'
        '@RestController\n'
        'class Api {\n'
        '    @PostMapping("/public/signup") fun signup() = Unit\n'
        '    @GetMapping("/reports") fun reports() = Unit\n'
        '    @DeleteMapping("/reports/{id}") fun delete() = Unit\n'
        '}\n'
    ))
    _write(tmp_path, "SecurityConfig.kt", (
        'import org.springframework.security.config.annotation.web.invoke\n'
        '@Configuration\n'
        'class SecurityConfig {\n'
        '    @Bean\n'
        '    fun filterChain(http: HttpSecurity): SecurityFilterChain {\n'
        '        http {\n'
        '            csrf { disable() }\n'
        '            authorizeHttpRequests {\n'
        '                authorize("/public/**", permitAll)\n'
        '                authorize(HttpMethod.DELETE, "/reports/**", hasRole("ADMIN"))\n'
        '                authorize(anyRequest, authenticated)\n'
        '            }\n'
        '        }\n'
        '        return http.build()\n'
        '    }\n'
        '}\n'
    ))
    result = JavaSpringAnalyzer().analyze(tmp_path)
    assert _route(result, "POST", "/public/signup").auth == "anonymous"
    assert _route(result, "GET", "/reports").guards == ["authenticated"]
    assert _route(result, "DELETE", "/reports/{id}").guards == ['hasRole("ADMIN")']


def test_webflux_authorize_exchange_applies_to_functional_routes(tmp_path: Path) -> None:
    _write(tmp_path, "Router.java", (
        'import org.springframework.web.reactive.function.server.RouterFunctions;\n'
        'import static org.springframework.web.reactive.function.server.RequestPredicates.*;\n'
        'class Router {\n'
        '    RouterFunction<ServerResponse> r(H h) {\n'
        '        return RouterFunctions.route(GET("/actuator/health"), h::health)\n'
        '            .andNest(path("/api"), RouterFunctions.route(POST("/orders"), h::order));\n'
        '    }\n'
        '}\n'
    ))
    _write(tmp_path, "Sec.java", (
        'import org.springframework.security.config.web.server.ServerHttpSecurity;\n'
        '@EnableWebFluxSecurity\n'
        'class Sec {\n'
        '    @Bean\n'
        '    SecurityWebFilterChain chain(ServerHttpSecurity http) {\n'
        '        return http.authorizeExchange(ex -> ex\n'
        '                .pathMatchers("/actuator/**").permitAll()\n'
        '                .anyExchange().authenticated())\n'
        '            .build();\n'
        '    }\n'
        '}\n'
    ))
    result = JavaSpringAnalyzer().analyze(tmp_path)
    assert _route(result, "GET", "/actuator/health").auth == "anonymous"
    assert _route(result, "POST", "/api/orders").auth == "required"


def test_unreadable_matcher_before_a_match_leaves_auth_unknown(tmp_path: Path) -> None:
    _write(tmp_path, "AdminController.java", _CONTROLLER)
    _write(tmp_path, "SecurityConfig.java", (
        'class SecurityConfig {\n'
        '    SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception {\n'
        '        httpSecurity.authorizeHttpRequests(registry -> {\n'
        '            for (String url : ignoreUrlsConfig.getUrls()) {\n'
        '                registry.requestMatchers(url).permitAll();\n'
        '            }\n'
        '            registry.regexMatchers("^/admin.*").denyAll();\n'
        '            registry.anyRequest().authenticated();\n'
        '        });\n'
        '        return httpSecurity.build();\n'
        '    }\n'
        '}\n'
    ))
    result = JavaSpringAnalyzer().analyze(tmp_path)
    assert set(_auth(result).values()) == {"unknown"}


def test_conditional_chains_must_agree(tmp_path: Path) -> None:
    _write(tmp_path, "AdminController.java", _CONTROLLER + (
        '@RestController class Home { @GetMapping("/") Object home() { return null; } }\n'
    ))
    _write(tmp_path, "SecurityEnabledConfig.java", (
        '@ConditionalOnProperty(name = "security.enable", havingValue = "true")\n'
        'class SecurityEnabledConfig {\n'
        '    SecurityWebFilterChain chain(ServerHttpSecurity http) {\n'
        '        return http.authorizeExchange().pathMatchers("/").permitAll()\n'
        '            .anyExchange().authenticated().and().build();\n'
        '    }\n'
        '}\n'
    ))
    _write(tmp_path, "SecurityDisabledConfig.java", (
        '@ConditionalOnProperty(name = "security.enable", havingValue = "false")\n'
        'class SecurityDisabledConfig {\n'
        '    SecurityWebFilterChain chain(ServerHttpSecurity http) {\n'
        '        return http.authorizeExchange().anyExchange().permitAll().and().csrf().disable().build();\n'
        '    }\n'
        '}\n'
    ))
    result = JavaSpringAnalyzer().analyze(tmp_path)
    auth = _auth(result)
    assert auth[("GET", "/")] == "anonymous"  # both chains permit it
    assert auth[("POST", "/admin/users")] == "unknown"  # they disagree


def test_security_matcher_scopes_a_chain(tmp_path: Path) -> None:
    _write(tmp_path, "Api.java", (
        '@RestController\n'
        'class Api {\n'
        '    @PostMapping("/api/orders") Object order() { return null; }\n'
        '    @PostMapping("/web/contact") Object contact() { return null; }\n'
        '}\n'
    ))
    _write(tmp_path, "Sec.java", (
        'class Sec {\n'
        '    @Bean @Order(1)\n'
        '    SecurityFilterChain api(HttpSecurity http) {\n'
        '        http.securityMatcher("/api/**")\n'
        '            .csrf(c -> c.ignoringRequestMatchers(AntPathRequestMatcher.antMatcher("/web/**")))\n'
        '            .authorizeHttpRequests(a -> a.anyRequest().hasRole("API"));\n'
        '        return http.build();\n'
        '    }\n'
        '    @Bean\n'
        '    SecurityFilterChain web(HttpSecurity http) {\n'
        '        http.authorizeHttpRequests(a -> a.anyRequest().permitAll());\n'
        '        return http.build();\n'
        '    }\n'
        '}\n'
    ))
    result = JavaSpringAnalyzer().analyze(tmp_path)
    assert _route(result, "POST", "/api/orders").guards == ['hasRole("API")']
    assert _route(result, "POST", "/web/contact").auth == "anonymous"


def test_web_ignoring_makes_routes_anonymous(tmp_path: Path) -> None:
    _write(tmp_path, "Api.java", (
        '@RestController\n'
        'class Api {\n'
        '    @PostMapping("/h2-console/login") Object h2() { return null; }\n'
        '    @PostMapping("/api/x") Object x() { return null; }\n'
        '}\n'
    ))
    _write(tmp_path, "Sec.java", (
        'class Sec {\n'
        '    @Bean WebSecurityCustomizer ignore() {\n'
        '        return (web) -> web.ignoring().requestMatchers("/h2-console/**").requestMatchers("/i18n/**");\n'
        '    }\n'
        '    @Bean SecurityFilterChain chain(HttpSecurity http) {\n'
        '        return http.authorizeHttpRequests(a -> a.anyRequest().authenticated()).build();\n'
        '    }\n'
        '}\n'
    ))
    result = JavaSpringAnalyzer().analyze(tmp_path)
    h2 = _route(result, "POST", "/h2-console/login")
    assert h2.auth == "anonymous" and "ignoring" in (h2.guard_evidence or "")
    assert _route(result, "POST", "/api/x").auth == "required"


def test_method_security_combines_with_chain(tmp_path: Path) -> None:
    _write(tmp_path, "Api.java", (
        '@RestController\n'
        '@PreAuthorize("hasRole(\'USER\')")\n'
        'class Api {\n'
        '    @PreAuthorize("hasRole(\'ADMIN\')")\n'
        '    @PostMapping("/open/admin") Object admin() { return null; }\n'
        '    @PostMapping("/open/class-guarded") Object classGuarded() { return null; }\n'
        '    @PermitAll\n'
        '    @PostMapping("/closed/permit") Object permit() { return null; }\n'
        '}\n'
        '@RestController\n'
        'class Plain {\n'
        '    @PreAuthorize("permitAll()")\n'
        '    @PostMapping("/open/plain") Object plain() { return null; }\n'
        '}\n'
    ))
    _write(tmp_path, "Sec.java", (
        '@EnableMethodSecurity\n'
        'class Sec {\n'
        '    SecurityFilterChain chain(HttpSecurity http) {\n'
        '        return http.authorizeHttpRequests(a -> a\n'
        '            .requestMatchers("/open/**").permitAll()\n'
        '            .anyRequest().authenticated()).build();\n'
        '    }\n'
        '}\n'
    ))
    result = JavaSpringAnalyzer().analyze(tmp_path)
    admin = _route(result, "POST", "/open/admin")
    assert admin.auth == "required"
    assert admin.guards == ['@PreAuthorize("hasRole(\'ADMIN\')")']
    assert "Api.java:4" in (admin.guard_evidence or "")
    assert _route(result, "POST", "/open/class-guarded").guards == ['@PreAuthorize("hasRole(\'USER\')")']
    # @PermitAll can't open a route the filter chain protects.
    assert _route(result, "POST", "/closed/permit").auth == "required"
    assert _route(result, "POST", "/open/plain").auth == "anonymous"


def test_method_security_without_filter_chain(tmp_path: Path) -> None:
    _write(tmp_path, "Res.java", (
        'import jakarta.ws.rs.*;\n'
        '@Path("/orders")\n'
        'public class Res {\n'
        '    @DELETE @Path("{id}") @RolesAllowed("admin")\n'
        '    public void delete() {}\n'
        '    @POST @PermitAll\n'
        '    public void create() {}\n'
        '}\n'
    ))
    # Without Jersey's RolesAllowedDynamicFeature (or jsr250Enabled) @RolesAllowed does nothing.
    assert JavaSpringAnalyzer().analyze(tmp_path).routes[0].auth == "unknown"
    _write(tmp_path, "App.java", (
        'class App extends ResourceConfig { App() { register(RolesAllowedDynamicFeature.class); } }\n'
    ))
    result = JavaSpringAnalyzer().analyze(tmp_path)
    assert _route(result, "DELETE", "/orders/{id}").guards == ['@RolesAllowed("admin")']
    # @PermitAll alone doesn't prove the route is public (a filter may guard it).
    assert _route(result, "POST", "/orders").auth == "unknown"


def test_chain_rules_skip_micronaut_and_ktor_routes(tmp_path: Path) -> None:
    _write(tmp_path, "Ctl.java", (
        'import io.micronaut.http.annotation.*;\n'
        '@Controller("/admin")\n'
        'class Ctl {\n'
        '    @Secured(SecurityRule.IS_ANONYMOUS)\n'
        '    @Post("/x") Object x() { return null; }\n'
        '}\n'
    ))
    _write(tmp_path, "App.kt", (
        'import io.ktor.server.routing.*\n'
        'fun Application.module() { routing { post("/admin/k") { } } }\n'
    ))
    _write(tmp_path, "Sec.java", (
        'class Sec { SecurityFilterChain c(HttpSecurity http) {\n'
        '    return http.authorizeHttpRequests(a -> a.anyRequest().permitAll()).build(); } }\n'
    ))
    result = JavaSpringAnalyzer().analyze(tmp_path)
    assert set(_auth(result).values()) == {"unknown"}


def test_chain_applies_only_within_its_build_module(tmp_path: Path) -> None:
    _write(tmp_path, "pom.xml", "<project><artifactId>parent</artifactId></project>")
    for module in ("demo", "admin"):
        _write(tmp_path, f"{module}/pom.xml", f"<project><artifactId>{module}</artifactId></project>")
        _write(tmp_path, f"{module}/src/main/java/C.java", (
            '@RestController class C { @PostMapping("/brand/create") Object c() { return null; } }\n'
        ))
    _write(tmp_path, "demo/src/main/java/Sec.java", (
        'class Sec { SecurityFilterChain c(HttpSecurity http) {\n'
        '    return http.authorizeHttpRequests(r -> r.requestMatchers("/**").permitAll()).build(); } }\n'
    ))
    # A route-less shared security module applies to modules without their own chain.
    _write(tmp_path, "security/pom.xml", "<project><artifactId>security</artifactId></project>")
    _write(tmp_path, "shop/pom.xml", "<project><artifactId>shop</artifactId></project>")
    _write(tmp_path, "shop/src/main/java/S.java", (
        '@RestController class S { @PostMapping("/cart") Object c() { return null; } }\n'
    ))
    _write(tmp_path, "security/src/main/java/SharedSec.java", (
        'class SharedSec { SecurityFilterChain c(HttpSecurity http) {\n'
        '    return http.authorizeHttpRequests(r -> r.anyRequest().authenticated()).build(); } }\n'
    ))
    result = JavaSpringAnalyzer().analyze(tmp_path)
    by_file = {(r.file, r.path): r.auth for r in result.routes}
    assert by_file[("demo/src/main/java/C.java", "/brand/create")] == "anonymous"
    # admin has routes and no chain of its own; demo's chain doesn't leak into it.
    # It falls back to the shared, route-less security module.
    assert by_file[("admin/src/main/java/C.java", "/brand/create")] == "required"
    assert by_file[("shop/src/main/java/S.java", "/cart")] == "required"


def test_package_nearest_chain_wins_between_two_apps_in_one_module(tmp_path: Path) -> None:
    base = "src/main/java/org/example"
    _write(tmp_path, f"{base}/wolf/FileServer.java", (
        '@RestController class FileServer { @GetMapping("/files/{name}") Object f() { return null; } }\n'
    ))
    _write(tmp_path, f"{base}/goat/Lesson.java", (
        '@RestController class Lesson { @GetMapping("/files/{name}") Object f() { return null; } }\n'
    ))
    _write(tmp_path, f"{base}/wolf/WebSecurityConfig.java", (
        'class WebSecurityConfig { SecurityFilterChain c(HttpSecurity http) {\n'
        '    return http.authorizeHttpRequests(a -> { a.requestMatchers(HttpMethod.GET, "/files/**").permitAll();\n'
        '        a.anyRequest().authenticated(); }).build(); } }\n'
    ))
    _write(tmp_path, f"{base}/goat/WebSecurityConfig.java", (
        'class WebSecurityConfig { SecurityFilterChain c(HttpSecurity http) {\n'
        '    return http.authorizeHttpRequests(a -> a.anyRequest().authenticated()).build(); } }\n'
    ))
    result = JavaSpringAnalyzer().analyze(tmp_path)
    by_file = {r.file.rsplit("/", 2)[-2]: r.auth for r in result.routes}
    assert by_file == {"wolf": "anonymous", "goat": "required"}


def test_test_only_security_configs_are_ignored(tmp_path: Path) -> None:
    _write(tmp_path, "src/main/java/AdminController.java", _CONTROLLER)
    _write(tmp_path, "src/test/java/TestSecurityConfig.java", (
        'class TestSecurityConfig { SecurityFilterChain c(HttpSecurity http) {\n'
        '    return http.authorizeHttpRequests(a -> a.anyRequest().permitAll()).build(); } }\n'
    ))
    result = JavaSpringAnalyzer().analyze(tmp_path)
    assert set(_auth(result).values()) == {"unknown"}


def test_no_security_config_leaves_routes_unknown(tmp_path: Path) -> None:
    _write(tmp_path, "AdminController.java", _CONTROLLER)
    result = JavaSpringAnalyzer().analyze(tmp_path)
    assert set(_auth(result).values()) == {"unknown"}


def test_core_flags_permit_all_admin_route_as_declared_anonymous(tmp_path: Path) -> None:
    from attackmap.analyzer import identify_attack_surfaces
    from attackmap.route_auth_fusion import unauthenticated_routes

    _write(tmp_path, "AdminController.java", _CONTROLLER)
    _write(tmp_path, "SecurityConfig.java", (
        'class SecurityConfig { SecurityFilterChain c(HttpSecurity http) {\n'
        '    return http.authorizeHttpRequests(a -> a.requestMatchers("/admin/**").permitAll()\n'
        '        .anyRequest().authenticated()).build(); } }\n'
    ))
    result = JavaSpringAnalyzer().analyze(tmp_path)
    flagged = unauthenticated_routes(result, identify_attack_surfaces(result))
    paths = {route.path for route, _ in flagged}
    # Core's own global-auth check would have trusted `anyRequest().authenticated()`.
    assert paths == {"/admin/users", "/admin/users/{id}"}
    assert all("declared anonymous" in evidence for _, evidence in flagged)


def test_security_parser_never_raises_on_garbage(tmp_path: Path) -> None:
    rng = random.Random(4242)
    base = (
        'class S { SecurityFilterChain c(HttpSecurity http) {\n'
        '  http.securityMatcher("/api/**").authorizeHttpRequests(a -> a.requestMatchers(HttpMethod.GET, "/x/**").permitAll()\n'
        '    .requestMatchers(antMatcher("/y"), new AntPathRequestMatcher("/z", "POST")).hasRole("A")\n'
        '    .anyRequest().authenticated()).authorizeRequests().antMatchers("/q").access("hasRole(\'B\')").and();\n'
        '  http { authorizeHttpRequests { authorize("/k", permitAll) } }\n'
        '  web.ignoring().antMatchers("/i/**");\n'
        '} }\n'
    )
    tokens = [
        "authorizeHttpRequests", "authorizeRequests()", "authorizeExchange", "requestMatchers(", "antMatchers(",
        "anyRequest()", ".permitAll()", ".authenticated()", "authorize(", "ignoring()", "securityMatcher(",
        "(", ")", "{", "}", '"/a/**"', '"', ",", ".", "->", ";", "\n", "HttpMethod.GET", "regexMatchers(",
    ]
    for _ in range(300):
        cut = rng.randint(0, len(base))
        parse_security(base[:cut], "S.java")
        parse_security(base[cut:], "S.java")
        noise = "".join(rng.choice(tokens) for _ in range(rng.randint(0, 80)))
        parse_security(noise, "S.java")
        parse_security(base[:cut] + noise + base[cut:], "S.java")
    # And the analyzer end to end on a few mangled files.
    for i in range(20):
        cut = rng.randint(0, len(base))
        _write(tmp_path, f"F{i}.java", base[cut:] + base[:cut] + '\n@RestController class R { @PostMapping("/x") Object x() { return null; } }')
    JavaSpringAnalyzer().analyze(tmp_path)


def test_security_parser_handles_huge_inputs_quickly() -> None:
    import time

    rule = '.requestMatchers("/a/*/b/**", "/c/{x}").permitAll()'
    text = "class S { void c(HttpSecurity http) { http.authorizeHttpRequests(a -> a" + rule * 800 + "); } }"
    start = time.perf_counter()
    found = parse_security(mask_comments(text), "S.java")
    assert len(found.chains) == 1 and len(found.chains[0].rules) == 500  # rules per chain are capped
    # A body beyond the size cap, unbalanced brackets and a flood of calls all stay cheap.
    parse_security("void c() { http.authorizeHttpRequests(a -> a" + rule * 5000 + "); }", "S.java")
    parse_security("authorizeHttpRequests(" * 20_000, "S.java")
    parse_security("web.ignoring().requestMatchers(" * 20_000, "S.java")
    parse_security("{ http.authorizeRequests()" + ".antMatchers((" * 20_000, "S.java")
    functional_routes("RouterFunctions nest(path(" * 20_000)
    functional_routes('GET("' * 20_000 + "router { " + '"/a".nest { ' * 5_000)
    assert time.perf_counter() - start < 10


def test_bracket_index_agrees_with_match_bracket() -> None:
    rng = random.Random(77)
    for _ in range(300):
        text = "".join(rng.choice("(){}[]ab \n") for _ in range(rng.randint(0, 120)))
        index = BracketIndex(text)
        for i, c in enumerate(text):
            if c in "({[":
                assert index.close(i) == match_bracket(text, i), (text, i)


# ---------- JAX-RS pairing ----------


def test_jaxrs_multi_class_file_does_not_borrow_neighbouring_paths(tmp_path: Path) -> None:
    _write(tmp_path, "Resources.java", (
        'import javax.ws.rs.*;\n'
        '\n'
        '@Path("/users")\n'
        'public class UserResource {\n'
        '    @GET\n'
        '    public List<User> list() { return null; }\n'
        '\n'
        '    @Path("/{id}")\n'
        '    @Produces(MediaType.APPLICATION_JSON)\n'
        '    @GET\n'
        '    public User get(@PathParam("id") String id) { return null; }\n'
        '\n'
        '    @POST\n'
        '    @Consumes({MediaType.APPLICATION_JSON, MediaType.APPLICATION_XML})\n'
        '    public User create(User u) { return null; }\n'
        '\n'
        '    @Path("/{id}/avatar")\n'
        '    public AvatarResource avatar() { return null; }  // sub-resource locator\n'
        '}\n'
        '\n'
        '@Path("/orders")\n'
        'class OrderResource {\n'
        '    /** Lists orders. */\n'
        '    @GET\n'
        '    /* note */ @Path("/recent")\n'
        '    public List<Order> recent() { return null; }\n'
        '\n'
        '    @DELETE\n'
        '    public void clear() {}\n'
        '}\n'
    ))
    result = JavaSpringAnalyzer().analyze(tmp_path)
    assert _routes(result) == {
        ("GET", "/users"),
        ("GET", "/users/{id}"),
        ("POST", "/users"),
        ("GET", "/orders/recent"),
        ("DELETE", "/orders"),
    }


# ---------- Review hardening: never `required` when Spring lets a request through ----------

_BOOT3_POM = (
    "<project><parent><groupId>org.springframework.boot</groupId>"
    "<artifactId>spring-boot-starter-parent</artifactId><version>3.2.5</version></parent></project>"
)
_BOOT2_POM = _BOOT3_POM.replace("3.2.5", "2.7.18")


def _sec(rules: str, *, extra: str = "") -> str:
    return (
        f"{extra}class Sec {{ SecurityFilterChain c(HttpSecurity http) {{\n"
        f"    return http.authorizeHttpRequests(a -> a{rules}).build(); }} }}\n"
    )


def test_route_multi_segment_wildcard_is_not_covered_by_a_narrower_pattern(tmp_path: Path) -> None:
    _write(tmp_path, "pom.xml", _BOOT3_POM)
    _write(tmp_path, "Files.java", (
        '@RestController class Files {\n'
        '    @GetMapping("/files/**") Object all() { return null; }\n'
        '    @PostMapping("/blobs/{*path}") Object blob() { return null; }\n'
        '    @DeleteMapping("/docs/**") Object docs() { return null; }\n'
        '}\n'
    ))
    _write(tmp_path, "Sec.java", _sec(
        '.requestMatchers("/files/*").authenticated()'
        '.requestMatchers("/blobs/{name}").authenticated()'
        '.requestMatchers("/docs/**").authenticated()'
        '.anyRequest().permitAll()'
    ))
    auth = _auth(JavaSpringAnalyzer().analyze(tmp_path))
    # `/files/a/b` and `/blobs/a/b` fall through to permitAll.
    assert auth[("GET", "/files/**")] == "anonymous"
    assert auth[("POST", "/blobs/{*path}")] == "anonymous"
    assert auth[("DELETE", "/docs/**")] == "required"


@pytest.mark.parametrize(
    ("setup", "expected"),
    [
        ("boot2", "unknown"),  # POST /admin/ reaches the handler and is permitted
        ("none", "unknown"),  # version unknown: assume Boot 2 behaviour
        ("boot3", "required"),  # Spring 6 doesn't route /admin/ to /admin
        ("jakarta", "required"),  # jakarta.servlet means Spring 6
        ("boot3-trailing-on", "unknown"),  # trailing-slash matching switched back on
    ],
)
def test_trailing_slash_bypass_of_an_exact_ant_pattern(tmp_path: Path, setup: str, expected: str) -> None:
    if setup.startswith("boot3"):
        _write(tmp_path, "pom.xml", _BOOT3_POM)
    elif setup == "boot2":
        _write(tmp_path, "pom.xml", _BOOT2_POM)
    imports = "import jakarta.servlet.http.HttpServletRequest;\n" if setup == "jakarta" else ""
    _write(tmp_path, "Admin.java", imports + '@RestController class Admin { @PostMapping("/admin") Object a() { return null; } }\n')
    if setup == "boot3-trailing-on":
        _write(tmp_path, "Web.java", "class Web { void c(PathMatchConfigurer c) { c.setUseTrailingSlashMatch(true); } }\n")
    _write(tmp_path, "Sec.java", (
        "class Sec { protected void configure(HttpSecurity http) {\n"
        '    http.authorizeRequests().antMatchers("/admin").hasRole("A").anyRequest().permitAll(); } }\n'
    ))
    assert _route(JavaSpringAnalyzer().analyze(tmp_path), "POST", "/admin").auth == expected


def test_trailing_slash_safe_matchers_stay_required_on_boot2(tmp_path: Path) -> None:
    _write(tmp_path, "pom.xml", _BOOT2_POM)
    _write(tmp_path, "Admin.java", (
        '@RestController class Admin {\n'
        '    @PostMapping("/admin") Object a() { return null; }\n'
        '    @PostMapping("/ops") Object o() { return null; }\n'
        '    @PostMapping("/slash") Object s() { return null; }\n'
        '}\n'
    ))
    _write(tmp_path, "Sec.java", _sec(
        '.mvcMatchers("/admin").hasRole("A")'
        '.requestMatchers("/ops/**").authenticated()'
        '.requestMatchers("/slash/").authenticated()'
        '.anyRequest().permitAll()'
    ))
    auth = _auth(JavaSpringAnalyzer().analyze(tmp_path))
    assert auth[("POST", "/admin")] == "required"  # MvcRequestMatcher mirrors MVC's matching
    assert auth[("POST", "/ops")] == "required"  # `/ops/**` covers `/ops/` too
    # `/slash/` doesn't cover `/slash`, which is permitted.
    assert auth[("POST", "/slash")] == "anonymous"


def test_trailing_slash_bypass_applies_to_jaxrs_even_on_boot3(tmp_path: Path) -> None:
    _write(tmp_path, "pom.xml", _BOOT3_POM)
    _write(tmp_path, "Res.java", (
        'import jakarta.ws.rs.*;\n@Path("/admin") public class Res { @POST public void a() {} }\n'
    ))
    _write(tmp_path, "Sec.java", _sec('.requestMatchers("/admin").hasRole("A").anyRequest().permitAll()'))
    assert _route(JavaSpringAnalyzer().analyze(tmp_path), "POST", "/admin").auth == "unknown"


def test_head_reaches_a_get_handler_that_a_get_only_rule_protects(tmp_path: Path) -> None:
    _write(tmp_path, "pom.xml", _BOOT3_POM)
    _write(tmp_path, "R.java", (
        '@RestController class R {\n'
        '    @GetMapping("/report") Object r() { return null; }\n'
        '    @GetMapping("/all") Object a() { return null; }\n'
        '}\n'
    ))
    _write(tmp_path, "Sec.java", _sec(
        '.requestMatchers(HttpMethod.GET, "/report").authenticated()'
        '.requestMatchers("/all").authenticated()'
        '.anyRequest().permitAll()'
    ))
    auth = _auth(JavaSpringAnalyzer().analyze(tmp_path))
    assert auth[("GET", "/report")] == "unknown"
    assert auth[("GET", "/all")] == "required"


def test_method_security_needs_its_switch(tmp_path: Path) -> None:
    _write(tmp_path, "pom.xml", _BOOT3_POM)
    _write(tmp_path, "Api.java", (
        '@RestController class Api {\n'
        '    @PreAuthorize("hasRole(\'A\')") @PostMapping("/pre") Object pre() { return null; }\n'
        '    @Secured("ROLE_A") @PostMapping("/secured") Object secured() { return null; }\n'
        '    @RolesAllowed("A") @PostMapping("/jsr") Object jsr() { return null; }\n'
        '}\n'
    ))
    rules = '.anyRequest().permitAll()'
    _write(tmp_path, "Sec.java", _sec(rules))
    # No @EnableMethodSecurity: the annotations do nothing.
    assert set(_auth(JavaSpringAnalyzer().analyze(tmp_path)).values()) == {"anonymous"}

    _write(tmp_path, "Sec.java", _sec(rules, extra="@EnableMethodSecurity\n"))
    auth = _auth(JavaSpringAnalyzer().analyze(tmp_path))
    # prePostEnabled is on by default; securedEnabled / jsr250Enabled aren't.
    assert auth == {("POST", "/pre"): "required", ("POST", "/secured"): "anonymous", ("POST", "/jsr"): "anonymous"}

    _write(tmp_path, "Sec.java", _sec(
        rules, extra="@EnableGlobalMethodSecurity(securedEnabled = true, jsr250Enabled = true)\n"
    ))
    auth = _auth(JavaSpringAnalyzer().analyze(tmp_path))
    # EnableGlobalMethodSecurity needs prePostEnabled = true for @PreAuthorize.
    assert auth == {("POST", "/pre"): "anonymous", ("POST", "/secured"): "required", ("POST", "/jsr"): "required"}


def test_method_security_switch_in_another_app_module_does_not_apply(tmp_path: Path) -> None:
    for module in ("a", "b"):
        _write(tmp_path, f"{module}/pom.xml", _BOOT3_POM)
        _write(tmp_path, f"{module}/src/main/java/Api.java", (
            '@RestController class Api { @PreAuthorize("hasRole(\'A\')") @PostMapping("/x") Object x() { return null; } }\n'
        ))
    _write(tmp_path, "a/src/main/java/Conf.java", "@EnableMethodSecurity class Conf {}\n")
    by_module = {r.file.split("/")[0]: r.auth for r in JavaSpringAnalyzer().analyze(tmp_path).routes}
    assert by_module == {"a": "required", "b": "unknown"}


def test_annotations_that_admit_anonymous_callers_are_not_guards(tmp_path: Path) -> None:
    _write(tmp_path, "pom.xml", _BOOT3_POM)
    _write(tmp_path, "Api.java", (
        '@RestController class Api {\n'
        '    @PostAuthorize("hasRole(\'A\')") @PostMapping("/post") Object post() { return null; }\n'
        '    @Secured({"ROLE_ANONYMOUS", "ROLE_USER"}) @PostMapping("/anon") Object anon() { return null; }\n'
        '    @PreAuthorize("isAnonymous() or hasRole(\'A\')") @PostMapping("/either") Object either() { return null; }\n'
        '    @PreAuthorize("hasRole(\'A\') or hasRole(\'B\')") @PostMapping("/roles") Object roles() { return null; }\n'
        '}\n'
    ))
    _write(tmp_path, "Sec.java", _sec(
        '.anyRequest().permitAll()',
        extra="@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true)\n",
    ))
    auth = _auth(JavaSpringAnalyzer().analyze(tmp_path))
    # @PostAuthorize runs after the handler's side effects; ROLE_ANONYMOUS lets anyone in.
    assert auth[("POST", "/post")] == "anonymous"
    assert auth[("POST", "/anon")] == "anonymous"
    # An `or` with an anonymous branch is unreadable as a guard.
    assert auth[("POST", "/either")] == "unknown"
    assert auth[("POST", "/roles")] == "required"


def test_handler_variants_on_one_route_key_count_as_the_least_restrictive(tmp_path: Path) -> None:
    _write(tmp_path, "pom.xml", _BOOT3_POM)
    _write(tmp_path, "Api.java", (
        '@RestController class Api {\n'
        '    @PreAuthorize("hasRole(\'A\')")\n'
        '    @PostMapping(value = "/act", params = "admin") Object admin() { return null; }\n'
        '    @PostMapping(value = "/act", params = "public") Object pub() { return null; }\n'
        '    @PreAuthorize("hasRole(\'A\')")\n'
        '    @PostMapping(value = "/both", headers = "X-A") Object b1() { return null; }\n'
        '    @PreAuthorize("hasRole(\'B\')")\n'
        '    @PostMapping(value = "/both", headers = "X-B") Object b2() { return null; }\n'
        '}\n'
    ))
    _write(tmp_path, "Sec.java", _sec('.anyRequest().permitAll()', extra="@EnableMethodSecurity\n"))
    auth = _auth(JavaSpringAnalyzer().analyze(tmp_path))
    assert auth[("POST", "/act")] == "anonymous"
    assert auth[("POST", "/both")] == "required"


def test_resolution_budget_degrades_to_unknown() -> None:
    from attackmap_analyzer_java_spring.security_dsl import Budget, BudgetExceeded, resolve_route

    found = parse_security(_sec('.requestMatchers("/a", "/b", "/c").permitAll().anyRequest().authenticated()'), "S.java")
    assert resolve_route(found.chains, [], "/x", "POST", "", budget=Budget(1000)).decision == "required"
    with pytest.raises(BudgetExceeded):
        resolve_route(found.chains, [], "/x", "POST", "", budget=Budget(2))


def test_hostile_configs_across_files_stay_fast(tmp_path: Path) -> None:
    import time

    patterns = ", ".join(f'"/p{i}/**/x/*/{{v}}/**/y"' for i in range(200))
    rule = f".requestMatchers({patterns}).hasRole(\"A\")"
    for n in range(4):
        _write(tmp_path, f"conf{n}/Sec{n}.java", _sec(rule * 300 + ".anyRequest().authenticated()"))
    routes = "".join(f'    @PostMapping("/r{i}/a/b/c/{{id}}") Object r{i}() {{ return null; }}\n' for i in range(150))
    _write(tmp_path, "Api.java", "@RestController class Api {\n" + routes + "}\n")
    start = time.perf_counter()
    result = JavaSpringAnalyzer().analyze(tmp_path)
    elapsed = time.perf_counter() - start
    assert len(result.routes) == 150
    assert elapsed < 30, elapsed
    # The budget ran out part-way: no route got a wrong answer, most stayed unknown.
    assert set(_auth(result).values()) <= {"required", "unknown"}
    assert "unknown" in set(_auth(result).values())


# ---------- Review round 2 ----------


def test_variant_forms_pick_their_own_chain(tmp_path: Path) -> None:
    _write(tmp_path, "Api.java", (
        '@RestController class Api { @GetMapping("/api/data") Object d() { return null; } }\n'
    ))
    # The API chain only covers GET; HEAD /api/data falls to the permit-all chain.
    _write(tmp_path, "Sec.java", (
        'class Sec {\n'
        '    SecurityFilterChain api(HttpSecurity http) {\n'
        '        http.securityMatcher(antMatcher(HttpMethod.GET, "/api/**"));\n'
        '        return http.authorizeHttpRequests(a -> a.anyRequest().authenticated()).build();\n'
        '    }\n'
        '    SecurityFilterChain web(HttpSecurity http) {\n'
        '        return http.authorizeHttpRequests(a -> a.anyRequest().permitAll()).build();\n'
        '    }\n'
        '}\n'
    ))
    _write(tmp_path, "pom.xml", _BOOT3_POM)
    assert _route(JavaSpringAnalyzer().analyze(tmp_path), "GET", "/api/data").auth == "unknown"


def test_lambda_security_matchers_with_a_method_are_opaque() -> None:
    found = parse_security(
        "class S { SecurityFilterChain c(HttpSecurity http) {\n"
        '  http.securityMatchers(m -> m.requestMatchers(HttpMethod.POST, "/api/**"))\n'
        "      .authorizeHttpRequests(a -> a.anyRequest().authenticated()); } }\n",
        "S.java",
    )
    assert found.chains[0].scope is not None and found.chains[0].scope.opaque


@pytest.mark.parametrize(
    ("root_pom", "module_pom", "expected"),
    [
        ("3.2.5", "2.7.18", "unknown"),  # the module's own Boot 2 wins
        ("2.7.18", None, "unknown"),
        ("3.2.5", None, "required"),  # the module inherits the root's Boot 3
        (None, "3.2.5", "required"),
    ],
)
def test_nearest_build_file_decides_the_boot_version(
    tmp_path: Path, root_pom: str | None, module_pom: str | None, expected: str
) -> None:
    if root_pom:
        _write(tmp_path, "pom.xml", _BOOT3_POM.replace("3.2.5", root_pom))
    if module_pom:
        _write(tmp_path, "app/pom.xml", _BOOT3_POM.replace("3.2.5", module_pom))
    else:
        _write(tmp_path, "app/pom.xml", "<project><artifactId>app</artifactId></project>")
    _write(tmp_path, "app/src/main/java/Admin.java", (
        'import jakarta.servlet.http.HttpServletRequest;\n'
        '@RestController class Admin { @PostMapping("/admin") Object a() { return null; } }\n'
    ))
    _write(tmp_path, "app/src/main/java/Sec.java", _sec('.requestMatchers("/admin").hasRole("A").anyRequest().permitAll()'))
    assert _route(JavaSpringAnalyzer().analyze(tmp_path), "POST", "/admin").auth == expected


@pytest.mark.parametrize(
    "jakarta",
    [
        "// import jakarta.servlet.http.HttpServletRequest;\n",
        "/*\nimport jakarta.servlet.Filter;\n*/\n",
        'String s = "jakarta.servlet";\n',
    ],
)
def test_jakarta_mentions_that_are_not_imports_do_not_mean_spring6(tmp_path: Path, jakarta: str) -> None:
    _write(tmp_path, "Admin.java", jakarta + '@RestController class Admin { @PostMapping("/admin") Object a() { return null; } }\n')
    _write(tmp_path, "Sec.java", _sec('.requestMatchers("/admin").hasRole("A").anyRequest().permitAll()'))
    assert _route(JavaSpringAnalyzer().analyze(tmp_path), "POST", "/admin").auth == "unknown"


def test_jakarta_import_in_test_source_does_not_mean_spring6(tmp_path: Path) -> None:
    _write(tmp_path, "src/test/java/T.java", "import jakarta.servlet.Filter;\nclass T {}\n")
    _write(tmp_path, "src/main/java/Admin.java", '@RestController class Admin { @PostMapping("/admin") Object a() { return null; } }\n')
    _write(tmp_path, "src/main/java/Sec.java", _sec('.requestMatchers("/admin").hasRole("A").anyRequest().permitAll()'))
    assert _route(JavaSpringAnalyzer().analyze(tmp_path), "POST", "/admin").auth == "unknown"


def test_url_handler_filter_turns_the_trailing_slash_check_back_on(tmp_path: Path) -> None:
    _write(tmp_path, "pom.xml", _BOOT3_POM)
    _write(tmp_path, "Admin.java", '@RestController class Admin { @PostMapping("/admin") Object a() { return null; } }\n')
    _write(tmp_path, "Sec.java", _sec('.requestMatchers("/admin").hasRole("A").anyRequest().permitAll()'))
    assert _route(JavaSpringAnalyzer().analyze(tmp_path), "POST", "/admin").auth == "required"
    _write(tmp_path, "Web.java", (
        "class Web { @Bean UrlHandlerFilter f() { return UrlHandlerFilter.trailingSlashHandler(\"/**\").wrapRequest().build(); } }\n"
    ))
    assert _route(JavaSpringAnalyzer().analyze(tmp_path), "POST", "/admin").auth == "unknown"


@pytest.mark.parametrize(
    ("config_name", "config", "expected"),
    [
        ("application.properties", "spring.mvc.servlet.path=/app\n", "unknown"),
        ("application.properties", "spring.mvc.servlet.path=/\n", "required"),
        ("application.properties", "server.servlet.context-path=/ctx\n", "required"),
        ("application.yml", "spring:\n  mvc:\n    servlet:\n      path: /app\n", "unknown"),
        ("application-prod.yaml", "spring.mvc.servlet.path: /app\n", "unknown"),
        ("application.yml", "spring:\n  mvc.servlet.path: ${APP_PATH}\n", "unknown"),
        # springdoc's `path:` and unrelated `mvc:` / `servlet:` keys are not the servlet path.
        (
            "application.yml",
            "spring:\n  thymeleaf:\n    servlet:\n      content-type: text/html\n  mvc:\n    pathmatch:\n"
            "      matching-strategy: ant_path_matcher\nspringdoc:\n  swagger-ui:\n    path: /swagger-ui.html\n",
            "required",
        ),
    ],
)
def test_dispatcher_servlet_path_makes_spring_routes_unknown(
    tmp_path: Path, config_name: str, config: str, expected: str
) -> None:
    _write(tmp_path, "pom.xml", _BOOT3_POM)
    _write(tmp_path, f"src/main/resources/{config_name}", config)
    _write(tmp_path, "src/main/java/Admin.java", '@RestController class Admin { @PostMapping("/admin/x") Object a() { return null; } }\n')
    _write(tmp_path, "src/main/java/Sec.java", _sec('.requestMatchers("/admin/**").hasRole("A").anyRequest().permitAll()'))
    assert _route(JavaSpringAnalyzer().analyze(tmp_path), "POST", "/admin/x").auth == expected


@pytest.mark.parametrize(
    ("app_path", "expected"),
    [('@ApplicationPath("/api")', "unknown"), ('@ApplicationPath("/")', "required"), ("@ApplicationPath(Paths.API)", "unknown")],
)
def test_jersey_application_path_makes_jaxrs_routes_unknown(tmp_path: Path, app_path: str, expected: str) -> None:
    _write(tmp_path, "pom.xml", _BOOT3_POM)
    _write(tmp_path, "App.java", f"{app_path}\nclass App extends ResourceConfig {{}}\n")
    _write(tmp_path, "Res.java", 'import jakarta.ws.rs.*;\n@Path("/admin") public class Res { @POST @Path("/x/") public void a() {} }\n')
    _write(tmp_path, "Sec.java", _sec('.requestMatchers("/admin/**").hasRole("A").anyRequest().permitAll()'))
    assert _route(JavaSpringAnalyzer().analyze(tmp_path), "POST", "/admin/x/").auth == expected


def test_method_security_needs_literal_arguments(tmp_path: Path) -> None:
    _write(tmp_path, "pom.xml", _BOOT3_POM)
    _write(tmp_path, "Api.java", (
        '@RestController class Api {\n'
        '    @PreAuthorize("hasAuthority(\\"" + AuthoritiesConstants.ADMIN + "\\")") @PostMapping("/concat") Object a() { return null; }\n'
        '    @Secured(Roles.ADMIN) @PostMapping("/const") Object b() { return null; }\n'
        '    @PreAuthorize("hasAuthority(\\"ROLE_ADMIN\\")") @PostMapping("/escaped") Object c() { return null; }\n'
        '    @PreAuthorize(value = "hasRole(\'A\') and isAuthenticated()") @PostMapping("/named") Object d() { return null; }\n'
        '}\n'
    ))
    _write(tmp_path, "Sec.java", _sec(
        '.anyRequest().permitAll()', extra="@EnableMethodSecurity(securedEnabled = true)\n"
    ))
    auth = _auth(JavaSpringAnalyzer().analyze(tmp_path))
    assert auth[("POST", "/concat")] == "unknown"
    assert auth[("POST", "/const")] == "unknown"
    assert auth[("POST", "/escaped")] == "required"
    assert auth[("POST", "/named")] == "required"


@pytest.mark.parametrize("wildcards", [63, 8])
def test_adversarial_glob_rules_stay_fast(tmp_path: Path, wildcards: int) -> None:
    import time

    # 63 wildcards is over the per-segment cap; 8 is at it, so the cost budget does the work.
    glob = "a*" * wildcards + "a" * (127 - 2 * wildcards)
    rule = f'.requestMatchers("/**/{glob}/**/x").hasRole("A")'
    _write(tmp_path, "Sec.java", _sec(rule * 450 + ".anyRequest().permitAll()"))
    route = "/" + "/".join(["a" * 127] * 32)
    _write(tmp_path, "Api.java", (
        "@RestController class Api {\n"
        + "".join(f'    @PostMapping("{route}{i}") Object r{i}() {{ return null; }}\n' for i in range(20))
        + "}\n"
    ))
    start = time.perf_counter()
    result = JavaSpringAnalyzer().analyze(tmp_path)
    assert time.perf_counter() - start < 10
    assert set(_auth(result).values()) <= {"anonymous", "unknown"}


def test_glob_cost_is_charged_to_the_budget() -> None:
    from attackmap_analyzer_java_spring.security_dsl import Budget, BudgetExceeded

    with pytest.raises(BudgetExceeded):
        match_path("/x*y*z/**", "/" + "x" * 120 + "/a", budget=Budget(500))


def test_servlet_path_applies_only_to_its_module(tmp_path: Path) -> None:
    for module in ("a", "b"):
        _write(tmp_path, f"{module}/pom.xml", _BOOT3_POM)
        _write(tmp_path, f"{module}/src/main/java/Admin.java", '@RestController class Admin { @PostMapping("/admin/x") Object a() { return null; } }\n')
        _write(tmp_path, f"{module}/src/main/java/Sec.java", _sec('.requestMatchers("/admin/**").hasRole("A").anyRequest().permitAll()'))
    _write(tmp_path, "a/src/main/resources/application.properties", "spring.mvc.servlet.path=/app\n")
    by_module = {r.file.split("/")[0]: r.auth for r in JavaSpringAnalyzer().analyze(tmp_path).routes}
    assert by_module == {"a": "unknown", "b": "required"}


# ---------- Review round 3: path prefixes set in code ----------


@pytest.mark.parametrize(
    ("config", "expected"),
    [
        (
            "class Web implements WebMvcConfigurer { public void configurePathMatch(PathMatchConfigurer c) {\n"
            '    c.addPathPrefix("/api", HandlerTypePredicate.forAnnotation(RestController.class)); } }\n',
            "unknown",
        ),
        (
            "class Web implements WebMvcConfigurer { public void configurePathMatch(PathMatchConfigurer c) {\n"
            "    c.addPathPrefix(Paths.API, h -> true); } }\n",
            "unknown",
        ),
        (
            'class Web { @Bean DispatcherServletRegistrationBean r(DispatcherServlet s) {\n'
            '    return new DispatcherServletRegistrationBean(s, "/api/*"); } }\n',
            "unknown",
        ),
        (
            'class Web { @Bean ServletRegistrationBean<DispatcherServlet> r(DispatcherServlet dispatcherServlet) {\n'
            '    return new ServletRegistrationBean<>(dispatcherServlet, "/api/*"); } }\n',
            "unknown",
        ),
        # Another servlet on a sub-path doesn't move MVC routes.
        (
            'class Web { @Bean ServletRegistrationBean<WebServlet> h2() {\n'
            '    return new ServletRegistrationBean<>(new WebServlet(), "/h2-console/*"); } }\n',
            "required",
        ),
        (
            'class Web { @Bean DispatcherServletRegistrationBean r(DispatcherServlet s) {\n'
            '    return new DispatcherServletRegistrationBean(s, "/"); } }\n',
            "required",
        ),
        # Mentioned only in a comment.
        ('// c.addPathPrefix("/api", p);\nclass Web {}\n', "required"),
    ],
)
def test_path_prefix_set_in_code_makes_spring_routes_unknown(tmp_path: Path, config: str, expected: str) -> None:
    _write(tmp_path, "pom.xml", _BOOT3_POM)
    _write(tmp_path, "src/main/java/Web.java", config)
    _write(tmp_path, "src/main/java/Admin.java", '@RestController class Admin { @PostMapping("/admin/users") Object a() { return null; } }\n')
    _write(tmp_path, "src/main/java/Sec.java", _sec('.requestMatchers("/admin/**").hasRole("ADMIN").anyRequest().permitAll()'))
    assert _route(JavaSpringAnalyzer().analyze(tmp_path), "POST", "/admin/users").auth == expected
