"""Tests for the JavaSpringAnalyzer plugin.

Each test writes a realistic Java/Kotlin snippet into tmp_path and asserts
on the resulting ScanResult.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from attackmap_analyzer_java_spring import JavaSpringAnalyzer


# ---------- detect() ----------


def test_detect_picks_up_pom(tmp_path: Path) -> None:
    (tmp_path / "pom.xml").write_text(
        "<project><artifactId>demo</artifactId></project>\n", encoding="utf-8"
    )
    assert JavaSpringAnalyzer().detect(tmp_path) is True


def test_detect_picks_up_gradle(tmp_path: Path) -> None:
    (tmp_path / "build.gradle").write_text("plugins {}\n", encoding="utf-8")
    assert JavaSpringAnalyzer().detect(tmp_path) is True


def test_detect_picks_up_kotlin_file(tmp_path: Path) -> None:
    (tmp_path / "App.kt").write_text("fun main() {}\n", encoding="utf-8")
    assert JavaSpringAnalyzer().detect(tmp_path) is True


def test_detect_skips_target_dir(tmp_path: Path) -> None:
    target = tmp_path / "target" / "classes"
    target.mkdir(parents=True)
    (target / "Foo.java").write_text("class Foo {}\n", encoding="utf-8")
    assert JavaSpringAnalyzer().detect(tmp_path) is False


# ---------- Spring MVC routes (annotation-based) ----------


def test_spring_get_post_extracted_with_class_prefix(tmp_path: Path) -> None:
    src = tmp_path / "src" / "main" / "java" / "UserController.java"
    src.parent.mkdir(parents=True)
    src.write_text(
        'package com.example;\n'
        '\n'
        'import org.springframework.web.bind.annotation.*;\n'
        '\n'
        '@RestController\n'
        '@RequestMapping("/api/users")\n'
        'public class UserController {\n'
        '    @GetMapping("/{id}")\n'
        '    public Object getUser(@PathVariable Long id) { return null; }\n'
        '\n'
        '    @PostMapping\n'
        '    public Object createUser(@RequestBody Object body) { return null; }\n'
        '\n'
        '    @DeleteMapping("/{id}")\n'
        '    public void deleteUser(@PathVariable Long id) {}\n'
        '}\n',
        encoding="utf-8",
    )
    result = JavaSpringAnalyzer().analyze(tmp_path)
    pairs = sorted({(r.path, r.method) for r in result.routes})
    assert ("/api/users/{id}", "GET") in pairs
    assert ("/api/users/{id}", "DELETE") in pairs
    # Bare @PostMapping maps to the class prefix alone (#2).
    assert ("/api/users", "POST") in pairs
    assert any(r.method == "GET" and r.path == "/api/users/{id}" for r in result.routes)


def test_spring_request_mapping_with_explicit_method(tmp_path: Path) -> None:
    src = tmp_path / "Controller.java"
    src.write_text(
        'import org.springframework.web.bind.annotation.*;\n'
        'public class Controller {\n'
        '    @RequestMapping(value = "/legacy", method = RequestMethod.POST)\n'
        '    public Object legacy() { return null; }\n'
        '}\n',
        encoding="utf-8",
    )
    result = JavaSpringAnalyzer().analyze(tmp_path)
    assert any(r.path == "/legacy" and r.method == "POST" for r in result.routes)


def test_spring_class_prefix_does_not_apply_to_methods_in_a_different_class(tmp_path: Path) -> None:
    """Two classes in one file — each method must inherit only its own class's prefix."""
    src = tmp_path / "Two.java"
    src.write_text(
        'import org.springframework.web.bind.annotation.*;\n'
        '@RequestMapping("/api/a")\n'
        'class A {\n'
        '    @GetMapping("/x")\n'
        '    public Object x() { return null; }\n'
        '}\n'
        '@RequestMapping("/api/b")\n'
        'class B {\n'
        '    @GetMapping("/y")\n'
        '    public Object y() { return null; }\n'
        '}\n',
        encoding="utf-8",
    )
    result = JavaSpringAnalyzer().analyze(tmp_path)
    pairs = {(r.path, r.method) for r in result.routes}
    assert ("/api/a/x", "GET") in pairs
    assert ("/api/b/y", "GET") in pairs
    # And no cross-pollination
    assert ("/api/a/y", "GET") not in pairs
    assert ("/api/b/x", "GET") not in pairs


def test_spring_with_no_class_prefix_uses_method_path_directly(tmp_path: Path) -> None:
    src = tmp_path / "NoPrefix.java"
    src.write_text(
        'import org.springframework.web.bind.annotation.*;\n'
        '@RestController\n'
        'public class NoPrefix {\n'
        '    @GetMapping("/health")\n'
        '    public String health() { return "ok"; }\n'
        '}\n',
        encoding="utf-8",
    )
    result = JavaSpringAnalyzer().analyze(tmp_path)
    assert any(r.path == "/health" and r.method == "GET" for r in result.routes)


# ---------- JAX-RS ----------


def test_jaxrs_path_with_method_annotations(tmp_path: Path) -> None:
    src = tmp_path / "OrdersResource.java"
    src.write_text(
        'import javax.ws.rs.GET;\n'
        'import javax.ws.rs.POST;\n'
        'import javax.ws.rs.Path;\n'
        '\n'
        '@Path("/orders")\n'
        'public class OrdersResource {\n'
        '    @GET\n'
        '    @Path("/{id}")\n'
        '    public Object get() { return null; }\n'
        '\n'
        '    @POST\n'
        '    @Path("/new")\n'
        '    public Object create() { return null; }\n'
        '}\n',
        encoding="utf-8",
    )
    result = JavaSpringAnalyzer().analyze(tmp_path)
    pairs = {(r.path, r.method) for r in result.routes}
    assert ("/orders/{id}", "GET") in pairs
    assert ("/orders/new", "POST") in pairs


# ---------- Ktor ----------


def test_ktor_kotlin_routing(tmp_path: Path) -> None:
    src = tmp_path / "App.kt"
    src.write_text(
        'import io.ktor.server.application.*\n'
        'import io.ktor.server.routing.*\n'
        '\n'
        'fun Application.module() {\n'
        '    routing {\n'
        '        get("/health") { call.respondText("ok") }\n'
        '        post("/login") { call.respondText("ok") }\n'
        '        delete("/users/{id}") { call.respondText("deleted") }\n'
        '    }\n'
        '}\n',
        encoding="utf-8",
    )
    result = JavaSpringAnalyzer().analyze(tmp_path)
    pairs = {(r.path, r.method) for r in result.routes}
    assert ("/health", "GET") in pairs
    assert ("/login", "POST") in pairs
    assert ("/users/{id}", "DELETE") in pairs


# ---------- Javalin ----------


def test_javalin_routes(tmp_path: Path) -> None:
    src = tmp_path / "App.java"
    src.write_text(
        'import io.javalin.Javalin;\n'
        '\n'
        'public class App {\n'
        '    public static void main(String[] args) {\n'
        '        var app = Javalin.create();\n'
        '        app.get("/users", ctx -> ctx.result("hi"));\n'
        '        app.post("/users", ctx -> ctx.result("created"));\n'
        '    }\n'
        '}\n',
        encoding="utf-8",
    )
    result = JavaSpringAnalyzer().analyze(tmp_path)
    pairs = {(r.path, r.method) for r in result.routes}
    assert ("/users", "GET") in pairs
    assert ("/users", "POST") in pairs


# ---------- Micronaut ----------


def test_micronaut_routes_with_class_prefix(tmp_path: Path) -> None:
    src = tmp_path / "BookController.java"
    src.write_text(
        'import io.micronaut.http.annotation.*;\n'
        '\n'
        '@Controller("/books")\n'
        'public class BookController {\n'
        '    @Get("/{id}")\n'
        '    public Object get(Long id) { return null; }\n'
        '\n'
        '    @Post("/")\n'
        '    public Object create() { return null; }\n'
        '}\n',
        encoding="utf-8",
    )
    result = JavaSpringAnalyzer().analyze(tmp_path)
    pairs = {(r.path, r.method) for r in result.routes}
    assert ("/books/{id}", "GET") in pairs
    assert ("/books", "POST") in pairs


# ---------- Databases ----------


def test_jpa_repository_emits_sql_hint(tmp_path: Path) -> None:
    (tmp_path / "UserRepo.java").write_text(
        'import org.springframework.data.jpa.repository.JpaRepository;\n'
        '@Entity\n'
        'public interface UserRepo extends JpaRepository<User, Long> {}\n',
        encoding="utf-8",
    )
    result = JavaSpringAnalyzer().analyze(tmp_path)
    assert any(d.kind == "sql" for d in result.databases)


def test_mongo_redis_each_emit_distinct_kinds(tmp_path: Path) -> None:
    (tmp_path / "Mongo.java").write_text(
        'import org.springframework.data.mongodb.repository.MongoRepository;\n'
        '@Document\npublic interface M {}\n',
        encoding="utf-8",
    )
    (tmp_path / "Redis.java").write_text(
        'import org.springframework.data.redis.core.RedisTemplate;\n'
        'public class R { RedisTemplate<String, String> tmpl; }\n',
        encoding="utf-8",
    )
    result = JavaSpringAnalyzer().analyze(tmp_path)
    kinds = {d.kind for d in result.databases}
    assert "mongodb" in kinds
    assert "redis" in kinds


def test_jdbc_postgres_emits_postgresql(tmp_path: Path) -> None:
    (tmp_path / "Db.java").write_text(
        'import java.sql.DriverManager;\n'
        'public class Db {\n'
        '    void connect() throws Exception {\n'
        '        DriverManager.getConnection("jdbc:postgresql://localhost/db");\n'
        '    }\n'
        '}\n',
        encoding="utf-8",
    )
    result = JavaSpringAnalyzer().analyze(tmp_path)
    assert any(d.kind == "postgresql" for d in result.databases)


# ---------- Auth ----------


def test_spring_security_signals(tmp_path: Path) -> None:
    (tmp_path / "Sec.java").write_text(
        'import org.springframework.security.config.annotation.web.SecurityFilterChain;\n'
        'import org.springframework.security.access.prepost.PreAuthorize;\n'
        'import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;\n'
        '\n'
        '@EnableWebSecurity\n'
        'public class Sec {\n'
        '    SecurityFilterChain chain() { return null; }\n'
        '    @PreAuthorize("hasRole(\'ADMIN\')")\n'
        '    public void admin() {}\n'
        '    BCryptPasswordEncoder enc = new BCryptPasswordEncoder();\n'
        '}\n',
        encoding="utf-8",
    )
    result = JavaSpringAnalyzer().analyze(tmp_path)
    by_hint = {h.hint: h for h in result.auth_hints}
    assert "spring_security_filter_chain" in by_hint
    assert "spring_method_security" in by_hint
    assert "bcrypt" in by_hint
    assert "spring_security_enabled" in by_hint
    assert by_hint["bcrypt"].confidence == 0.9


def test_jjwt_emits_jwt_hint(tmp_path: Path) -> None:
    (tmp_path / "Jwt.java").write_text(
        'import io.jsonwebtoken.Jwts;\n'
        'public class JwtDemo { String t() { return Jwts.builder().compact(); } }\n',
        encoding="utf-8",
    )
    result = JavaSpringAnalyzer().analyze(tmp_path)
    assert any(h.hint == "jwt" for h in result.auth_hints)


# ---------- Secrets ----------


def test_system_getenv_secret(tmp_path: Path) -> None:
    (tmp_path / "Cfg.java").write_text(
        'public class Cfg {\n'
        '    String s = System.getenv("JWT_SECRET");\n'
        '    String p = System.getenv("DATABASE_PASSWORD");\n'
        '}\n',
        encoding="utf-8",
    )
    result = JavaSpringAnalyzer().analyze(tmp_path)
    names = {s.name for s in result.secret_hints}
    assert "JWT_SECRET" in names
    assert "DATABASE_PASSWORD" in names

    jwt = next(s for s in result.secret_hints if s.name == "JWT_SECRET")
    assert jwt.line == 2
    assert jwt.evidence_text and "JWT_SECRET" in jwt.evidence_text


def test_value_annotation_secret(tmp_path: Path) -> None:
    (tmp_path / "Cfg.java").write_text(
        'import org.springframework.beans.factory.annotation.Value;\n'
        'public class Cfg {\n'
        '    @Value("${stripe.secret_key}")\n'
        '    private String stripeKey;\n'
        '}\n',
        encoding="utf-8",
    )
    result = JavaSpringAnalyzer().analyze(tmp_path)
    names = {s.name.lower() for s in result.secret_hints}
    assert any("stripe.secret_key" in n for n in names)


# ---------- External calls ----------


def test_resttemplate_emits_external_call(tmp_path: Path) -> None:
    (tmp_path / "Client.java").write_text(
        'import org.springframework.web.client.RestTemplate;\n'
        'public class Client {\n'
        '    String fetch() {\n'
        '        RestTemplate restTemplate = new RestTemplate();\n'
        '        return restTemplate.getForObject("https://api.stripe.com/v1/charges", String.class);\n'
        '    }\n'
        '}\n',
        encoding="utf-8",
    )
    result = JavaSpringAnalyzer().analyze(tmp_path)
    targets = {e.target for e in result.external_calls}
    assert "https://api.stripe.com/v1/charges" in targets


def test_webclient_emits_external_call(tmp_path: Path) -> None:
    (tmp_path / "Client.java").write_text(
        'import org.springframework.web.reactive.function.client.WebClient;\n'
        'public class Client {\n'
        '    void fetch() {\n'
        '        WebClient.create().get().uri("https://api.example.com/v2/data").retrieve();\n'
        '    }\n'
        '}\n',
        encoding="utf-8",
    )
    result = JavaSpringAnalyzer().analyze(tmp_path)
    targets = {e.target for e in result.external_calls}
    assert "https://api.example.com/v2/data" in targets


# ---------- Frameworks + entrypoints ----------


def test_spring_boot_application_marker(tmp_path: Path) -> None:
    (tmp_path / "App.java").write_text(
        'import org.springframework.boot.SpringApplication;\n'
        'import org.springframework.boot.autoconfigure.SpringBootApplication;\n'
        '\n'
        '@SpringBootApplication\n'
        'public class App {\n'
        '    public static void main(String[] args) {\n'
        '        SpringApplication.run(App.class, args);\n'
        '    }\n'
        '}\n',
        encoding="utf-8",
    )
    result = JavaSpringAnalyzer().analyze(tmp_path)
    fw = {f.hint for f in result.framework_hints}
    assert "spring-boot" in fw
    ep = {e.hint for e in result.entrypoint_hints}
    assert "spring_boot_application" in ep
    assert "spring_application_run" in ep


# ---------- Build metadata → service hints ----------


def test_pom_artifact_id_picked_up(tmp_path: Path) -> None:
    (tmp_path / "pom.xml").write_text(
        "<project>\n"
        "  <groupId>com.acme</groupId>\n"
        "  <artifactId>billing-api</artifactId>\n"
        "  <version>1.0.0</version>\n"
        "</project>\n",
        encoding="utf-8",
    )
    (tmp_path / "App.java").write_text("public class App {}\n", encoding="utf-8")
    result = JavaSpringAnalyzer().analyze(tmp_path)
    assert any(h.hint == "artifact:billing-api" for h in result.service_hints)


def test_spring_application_name_from_properties(tmp_path: Path) -> None:
    res = tmp_path / "src" / "main" / "resources"
    res.mkdir(parents=True)
    (res / "application.properties").write_text(
        "spring.application.name=billing\nserver.port=8080\n", encoding="utf-8"
    )
    (tmp_path / "App.java").write_text("public class App {}\n", encoding="utf-8")
    result = JavaSpringAnalyzer().analyze(tmp_path)
    assert any(h.hint == "spring_app:billing" for h in result.service_hints)


# ---------- End-to-end sanity ----------


def test_full_spring_boot_service_signal_set(tmp_path: Path) -> None:
    (tmp_path / "pom.xml").write_text(
        "<project><artifactId>orders</artifactId></project>\n", encoding="utf-8"
    )
    src = tmp_path / "src" / "main" / "java" / "com" / "acme" / "OrdersController.java"
    src.parent.mkdir(parents=True)
    src.write_text(
        'package com.acme;\n'
        '\n'
        'import org.springframework.boot.SpringApplication;\n'
        'import org.springframework.boot.autoconfigure.SpringBootApplication;\n'
        'import org.springframework.web.bind.annotation.*;\n'
        'import org.springframework.web.client.RestTemplate;\n'
        'import org.springframework.security.access.prepost.PreAuthorize;\n'
        'import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;\n'
        'import io.jsonwebtoken.Jwts;\n'
        '\n'
        '@SpringBootApplication\n'
        '@RestController\n'
        '@RequestMapping("/api/orders")\n'
        'public class OrdersController {\n'
        '    String secret = System.getenv("JWT_SECRET");\n'
        '    String stripe = System.getenv("STRIPE_SECRET_KEY");\n'
        '    BCryptPasswordEncoder enc = new BCryptPasswordEncoder();\n'
        '\n'
        '    @GetMapping("/{id}")\n'
        '    public Object get() { return null; }\n'
        '\n'
        '    @PreAuthorize("hasRole(\'ADMIN\')")\n'
        '    @PostMapping("/admin/refund")\n'
        '    public Object refund() { return null; }\n'
        '\n'
        '    void fetch() {\n'
        '        RestTemplate restTemplate = new RestTemplate();\n'
        '        restTemplate.getForObject("https://api.stripe.com/v1/charges", String.class);\n'
        '    }\n'
        '\n'
        '    public static void main(String[] args) { SpringApplication.run(OrdersController.class, args); }\n'
        '}\n',
        encoding="utf-8",
    )

    result = JavaSpringAnalyzer().analyze(tmp_path)

    pairs = {(r.path, r.method) for r in result.routes}
    assert ("/api/orders/{id}", "GET") in pairs
    assert ("/api/orders/admin/refund", "POST") in pairs

    assert any(h.hint == "jwt" for h in result.auth_hints)
    assert any(h.hint == "bcrypt" for h in result.auth_hints)
    assert any(h.hint == "spring_method_security" for h in result.auth_hints)

    assert {s.name for s in result.secret_hints} >= {"JWT_SECRET", "STRIPE_SECRET_KEY"}

    assert any(e.target == "https://api.stripe.com/v1/charges" for e in result.external_calls)
    assert any(f.hint == "spring-boot" for f in result.framework_hints)
    assert any(e.hint == "spring_boot_application" for e in result.entrypoint_hints)
    assert any(h.hint == "artifact:orders" for h in result.service_hints)

    assert all(r.line is not None for r in result.routes)


# ---------- Repo walking (mlaify/AttackMap#253) ----------


def _write_spring_controller(src_dir: Path) -> Path:
    src_dir.mkdir(parents=True, exist_ok=True)
    src = src_dir / "UserController.java"
    src.write_text(
        'package com.example;\n'
        '\n'
        'import org.springframework.web.bind.annotation.*;\n'
        '\n'
        '@RestController\n'
        '@RequestMapping("/api/users")\n'
        'public class UserController {\n'
        '    @GetMapping("/{id}")\n'
        '    public Object getUser(@PathVariable Long id) { return null; }\n'
        '}\n',
        encoding="utf-8",
    )
    return src


@pytest.mark.parametrize("parents", [("build", "out"), ("target", "bin")])
def test_repo_under_skip_dir_names_is_still_analyzed(tmp_path: Path, parents: tuple[str, str]) -> None:
    # These are skip dirs; they must only count inside the repo.
    repo = tmp_path.joinpath(*parents, "repo")
    _write_spring_controller(repo / "src" / "main" / "java")
    analyzer = JavaSpringAnalyzer()
    assert analyzer.detect(repo) is True
    result = analyzer.analyze(repo)
    assert result.files_scanned == 1
    assert ("/api/users/{id}", "GET") in {(r.path, r.method) for r in result.routes}


@pytest.mark.skipif(sys.platform == "win32", reason="symlinks need privileges on Windows")
def test_symlinked_file_outside_repo_is_not_analyzed(tmp_path: Path) -> None:
    target = _write_spring_controller(tmp_path / "outside")
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "Linked.java").symlink_to(target)
    analyzer = JavaSpringAnalyzer()
    assert analyzer.detect(repo) is False
    result = analyzer.analyze(repo)
    assert result.files_scanned == 0
    assert result.routes == []


# ---------- Annotation argument shapes (#2) ----------


def _routes(result) -> set[tuple[str, str]]:
    return {(r.method, r.path) for r in result.routes}


def test_spring_issue_controller_produces_all_routes_with_prefix(tmp_path: Path) -> None:
    """The 5-endpoint controller from #2: path= at class and method level, bare
    @GetMapping, array @PostMapping and a plain @DeleteMapping."""
    (tmp_path / "UserController.java").write_text(
        'import org.springframework.web.bind.annotation.*;\n'
        '\n'
        '@RestController\n'
        '@RequestMapping(path = "/api/users")\n'
        'public class UserController {\n'
        '    @GetMapping\n'
        '    public List<User> list() { return null; }\n'
        '\n'
        '    @GetMapping(path = "/{id}")\n'
        '    public User get(@PathVariable Long id) { return null; }\n'
        '\n'
        '    @PostMapping({"/a", "/b"})\n'
        '    public User create(@RequestBody User u) { return null; }\n'
        '\n'
        '    @DeleteMapping("/{id}")\n'
        '    public void delete(@PathVariable Long id) {}\n'
        '}\n',
        encoding="utf-8",
    )
    result = JavaSpringAnalyzer().analyze(tmp_path)
    assert _routes(result) == {
        ("GET", "/api/users"),
        ("GET", "/api/users/{id}"),
        ("POST", "/api/users/a"),
        ("POST", "/api/users/b"),
        ("DELETE", "/api/users/{id}"),
    }
    lines = {(r.method, r.path): r.line for r in result.routes}
    assert lines[("GET", "/api/users")] == 6
    assert lines[("POST", "/api/users/b")] == 12


def test_spring_request_mapping_method_array_and_class_value_array(tmp_path: Path) -> None:
    (tmp_path / "Multi.java").write_text(
        'import org.springframework.web.bind.annotation.*;\n'
        '@RestController\n'
        '@RequestMapping(value = {"/v1/items", "/v2/items"})\n'
        '@Validated\n'
        'public class Multi {\n'
        '    @RequestMapping(path = "/{id}", method = {RequestMethod.GET, RequestMethod.HEAD})\n'
        '    public Item get() { return null; }\n'
        '    @RequestMapping("/sync")\n'
        '    public void sync() {}\n'
        '}\n',
        encoding="utf-8",
    )
    result = JavaSpringAnalyzer().analyze(tmp_path)
    assert _routes(result) == {
        ("GET", "/v1/items/{id}"),
        ("HEAD", "/v1/items/{id}"),
        ("GET", "/v2/items/{id}"),
        ("HEAD", "/v2/items/{id}"),
        ("ANY", "/v1/items/sync"),
        ("ANY", "/v2/items/sync"),
    }


def test_spring_class_without_mapping_does_not_inherit_previous_prefix(tmp_path: Path) -> None:
    (tmp_path / "Two.java").write_text(
        'import org.springframework.web.bind.annotation.*;\n'
        '@RequestMapping("/api/a")\n'
        'class A {\n'
        '    @GetMapping("/x")\n'
        '    public Object x() { return "{"; }\n'
        '}\n'
        '@RestController\n'
        'class B {\n'
        '    // @GetMapping("/commented-out")\n'
        '    @GetMapping("/y")\n'
        '    public Object y() { return null; }\n'
        '}\n',
        encoding="utf-8",
    )
    result = JavaSpringAnalyzer().analyze(tmp_path)
    assert _routes(result) == {("GET", "/api/a/x"), ("GET", "/y")}


def test_spring_mapping_with_constant_path_is_skipped_not_misattributed(tmp_path: Path) -> None:
    (tmp_path / "C.java").write_text(
        'import org.springframework.web.bind.annotation.*;\n'
        '@RequestMapping("/api")\n'
        'class C {\n'
        '    @GetMapping(Paths.STATUS)\n'
        '    public Object status() { return null; }\n'
        '    @GetMapping(value = "/ok", produces = "application/json")\n'
        '    public Object ok() { return null; }\n'
        '}\n',
        encoding="utf-8",
    )
    result = JavaSpringAnalyzer().analyze(tmp_path)
    assert _routes(result) == {("GET", "/api/ok")}


def test_spring_kotlin_array_forms(tmp_path: Path) -> None:
    (tmp_path / "UserController.kt").write_text(
        'import org.springframework.web.bind.annotation.*\n'
        '\n'
        '@RestController\n'
        '@RequestMapping(path = ["/api/users"])\n'
        'class UserController(private val repo: UserRepository) {\n'
        '    @GetMapping\n'
        '    fun list(): List<User> = repo.findAll()\n'
        '\n'
        '    @GetMapping(value = ["/{id}", "/by-id/{id}"])\n'
        '    fun get(@PathVariable id: Long): User = repo.get(id)\n'
        '\n'
        '    @PostMapping(path = arrayOf("/a", "/b"))\n'
        '    fun create(@RequestBody u: User): User = repo.save(u)\n'
        '\n'
        '    @PutMapping("/x", "/y")\n'
        '    fun put(): Unit {}\n'
        '\n'
        '    @RequestMapping(value = ["/legacy"], method = [RequestMethod.PATCH])\n'
        '    fun legacy(): Unit {}\n'
        '}\n',
        encoding="utf-8",
    )
    result = JavaSpringAnalyzer().analyze(tmp_path)
    assert _routes(result) == {
        ("GET", "/api/users"),
        ("GET", "/api/users/{id}"),
        ("GET", "/api/users/by-id/{id}"),
        ("POST", "/api/users/a"),
        ("POST", "/api/users/b"),
        ("PUT", "/api/users/x"),
        ("PUT", "/api/users/y"),
        ("PATCH", "/api/users/legacy"),
    }


def test_micronaut_bare_get_value_and_uri_forms(tmp_path: Path) -> None:
    (tmp_path / "BookController.java").write_text(
        'import io.micronaut.http.annotation.*;\n'
        '\n'
        '@Controller(value = "/books")\n'
        'public class BookController {\n'
        '    @Get\n'
        '    public List<Book> list() { return null; }\n'
        '\n'
        '    @Get(value = "/{id}")\n'
        '    public Book get(Long id) { return null; }\n'
        '\n'
        '    @Post(uri = "/import")\n'
        '    public void importBooks() {}\n'
        '\n'
        '    @Delete(uris = {"/{id}", "/remove/{id}"})\n'
        '    public void delete(Long id) {}\n'
        '}\n',
        encoding="utf-8",
    )
    result = JavaSpringAnalyzer().analyze(tmp_path)
    assert _routes(result) == {
        ("GET", "/books"),
        ("GET", "/books/{id}"),
        ("POST", "/books/import"),
        ("DELETE", "/books/{id}"),
        ("DELETE", "/books/remove/{id}"),
    }


def test_micronaut_bare_controller_mounts_at_root(tmp_path: Path) -> None:
    (tmp_path / "Health.kt").write_text(
        'import io.micronaut.http.annotation.*\n'
        '\n'
        '@Controller\n'
        'class Health {\n'
        '    @Get("/health")\n'
        '    fun health() = "ok"\n'
        '}\n',
        encoding="utf-8",
    )
    result = JavaSpringAnalyzer().analyze(tmp_path)
    assert _routes(result) == {("GET", "/health")}


def test_jaxrs_value_attribute_and_class_scoped_path(tmp_path: Path) -> None:
    (tmp_path / "Res.java").write_text(
        'import jakarta.ws.rs.*;\n'
        '\n'
        '@Path(value = "/orders")\n'
        'public class Res {\n'
        '    @GET\n'
        '    public List<Order> list() { return null; }\n'
        '\n'
        '    @DELETE\n'
        '    @Path("{id}")\n'
        '    public void delete() {}\n'
        '}\n',
        encoding="utf-8",
    )
    result = JavaSpringAnalyzer().analyze(tmp_path)
    assert _routes(result) == {("GET", "/orders"), ("DELETE", "/orders/{id}")}
