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
        ("api/**", "/api/x", FULL),
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
    assert match_path("/" + "*a" * 60, "/" + "a" * 120) == FULL


def test_read_matcher_args_forms() -> None:
    m = read_matcher_args('HttpMethod.POST, "/a", "b"')
    assert m.entries == [("POST", "/a"), ("POST", "/b")] and not m.opaque
    assert read_matcher_args("HttpMethod.OPTIONS").entries == [("OPTIONS", None)]
    assert read_matcher_args('antMatcher("/h2/**"), mvc.pattern("/x")').entries == [(None, "/h2/**"), (None, "/x")]
    assert read_matcher_args('new AntPathRequestMatcher("/x", "DELETE")').entries == [("DELETE", "/x")]
    assert read_matcher_args("url").opaque
    assert read_matcher_args("PathRequest.toStaticResources().atCommonLocations()").entries[0] == (None, "/css/**")


@pytest.mark.parametrize(
    ("decision", "expected"),
    [
        ('access("hasRole(\'ADMIN\')")', "required"),
        ('access("permitAll")', "anonymous"),
        ('access("isAnonymous() or isAuthenticated()")', "unknown"),
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
    _write(tmp_path, "AdminController.java", _CONTROLLER)
    _write(tmp_path, "SecurityConfig.java", (
        'class SecurityConfig {\n'
        '    SecurityFilterChain chain(HttpSecurity http) {\n'
        '        http.authorizeHttpRequests(authz -> authz\n'
        '            .requestMatchers(HttpMethod.DELETE, "/admin/users/*").hasRole("SUPER")\n'
        '            .requestMatchers("/admin/**").hasAuthority(AuthoritiesConstants.ADMIN)\n'
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
    assert _route(result, "POST", "/admin/users").guards == ["hasAuthority(AuthoritiesConstants.ADMIN)"]
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
    assert auth[("GET", "/articles/feed")] == "required"
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
