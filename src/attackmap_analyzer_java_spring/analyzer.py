"""Java/Kotlin Spring Boot ecosystem analyzer for AttackMap.

Coverage (v0.1):
- Web frameworks: Spring MVC / Spring Boot (annotation routing, with class-level
  @RequestMapping prefix joining), JAX-RS / Jersey / Quarkus (@Path + @GET/@POST),
  Ktor (Kotlin DSL routing), Javalin, Micronaut
- Databases: Spring Data JPA (@Entity, JpaRepository), Spring Data MongoDB
  (@Document, MongoRepository), Spring Data Redis (RedisTemplate), JDBC
  (DriverManager.getConnection), Hibernate, jOOQ
- Auth: Spring Security (@PreAuthorize, @Secured, SecurityFilterChain),
  jjwt / nimbus-jose-jwt, BCryptPasswordEncoder / Argon2PasswordEncoder,
  OAuth2 (oauth2Login, OAuth2AuthenticationToken)
- HTTP clients (external calls): RestTemplate, WebClient, java.net.http.HttpClient,
  OkHttpClient, @FeignClient, Apache HttpClient
- Secrets: System.getenv("X"), @Value("${X}"), Environment.getProperty("X")
- Entrypoints: @SpringBootApplication, SpringApplication.run, embedded servlet
  containers
- Service hints: artifactId/groupId from pom.xml, rootProject.name from
  build.gradle, spring.application.name from application.properties/yml

Class-level @RequestMapping (Spring), @Path (JAX-RS) and @Controller
(Micronaut) prefixes are joined with member mappings to produce the full route
path. Annotation arguments are parsed (bare, positional, `value=`/`path=`/
`uri=`, Java `{...}` and Kotlin `[...]`/`arrayOf(...)` arrays, `method =`
lists) by `annotations.py`, and a class prefix applies only inside that class's
body (found by brace matching).

Functional endpoints (`RouterFunctions`, the `route()` builder, Kotlin
`router {}` / `coRouter {}`) are read by `functional.py`. Route auth (#3):
Spring Security `authorizeHttpRequests` / `authorizeRequests` /
`authorizeExchange` rules (`security_dsl.py`) are applied to Spring, JAX-RS and
functional routes in first-match order, together with method security
(`@PreAuthorize`, `@Secured`, `@RolesAllowed`, `@DenyAll`, `@PermitAll`), and
the result is recorded on `Route.auth` / `guards` / `guard_evidence`.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from attackmap.sdk import DEFAULT_SKIP_DIRS, iter_repo_files, line_of, read_source, rel

from .annotations import (
    Annotation,
    AnnotationBlock,
    annotation_paths,
    class_scopes,
    find_annotations,
    group_blocks,
    innermost_scope,
    mask_comments,
)
from .functional import FUNCTIONAL_GATE_RE, functional_routes
from .security_dsl import (
    ANONYMOUS,
    REQUIRED,
    SECURITY_GATE_RE,
    FileSecurity,
    Resolution,
    Rule,
    SecurityChain,
    parse_security,
    resolve_route,
)

from .contracts import (
    AnalyzerMetadata,
    AuthHint,
    DatabaseHint,
    EntrypointHint,
    ExternalCall,
    FrameworkHint,
    Route,
    ScanResult,
    SecretHint,
    ServiceHint,
)

CODE_SUFFIXES = {".java", ".kt", ".kts"}
# JVM-specific directories on top of the SDK defaults (which already cover
# Maven target/, Gradle build/, out/, .git and node_modules). Matched against
# directory names inside the repo only (mlaify/AttackMap#253).
SKIP_DIRS = DEFAULT_SKIP_DIRS | {".gradle", ".mvn", ".idea", "bin"}
BUILD_FILES = {"pom.xml", "build.gradle", "build.gradle.kts"}
_SNIPPET_MAX_CHARS = 160


# ---------- Patterns ----------

# Spring MVC, JAX-RS and Micronaut routes are read with the annotation reader
# in `annotations.py` (#2): bare mappings, `value=`/`path=`/`uri=`, arrays
# (`{"/a", "/b"}`, Kotlin `["/a"]` / `arrayOf("/a")`) and
# `method = {RequestMethod.X, ...}`.
SPRING_VERB_MAPPINGS = {
    "GetMapping": "GET",
    "PostMapping": "POST",
    "PutMapping": "PUT",
    "DeleteMapping": "DELETE",
    "PatchMapping": "PATCH",
}
SPRING_PATH_KEYS = ("value", "path")
JAXRS_VERBS = frozenset({"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"})
MICRONAUT_VERBS = {
    "Get": "GET",
    "Post": "POST",
    "Put": "PUT",
    "Delete": "DELETE",
    "Patch": "PATCH",
    "Head": "HEAD",
    "Options": "OPTIONS",
}
MICRONAUT_PATH_KEYS = ("value", "uri", "uris")
ROUTE_ANNOTATIONS = frozenset(
    {*SPRING_VERB_MAPPINGS, "RequestMapping", "Path", *JAXRS_VERBS, *MICRONAUT_VERBS, "Controller"}
)

# Ktor (Kotlin): get("/x") { ... } inside `routing { ... }`.
KTOR_ROUTE_PATTERN = re.compile(
    r'\b(get|post|put|delete|patch|head|options)\s*\(\s*"([^"]+)"\s*\)\s*\{',
)

# Javalin: app.get("/x", ...), app.post("/x", ...)
JAVALIN_ROUTE_PATTERN = re.compile(
    r'\bapp\.(get|post|put|delete|patch|head|options)\s*\(\s*"([^"]+)"',
)

# Method security annotations (Spring and JSR-250) on a handler or its class.
METHOD_SECURITY_ANNOTATIONS = frozenset({"PreAuthorize", "PostAuthorize", "Secured", "RolesAllowed", "DenyAll", "PermitAll"})
_METHOD_SECURITY_PERMIT_RE = re.compile(r"\b(?:permitAll|isAnonymous|IS_AUTHENTICATED_ANONYMOUSLY)\b")
_METHOD_SECURITY_REQUIRED_RE = re.compile(
    r"\b(?:hasRole|hasAnyRole|hasAuthority|hasAnyAuthority|hasPermission|isAuthenticated|"
    r"isFullyAuthenticated|isRememberMe|denyAll|authentication|principal|ROLE_\w+|"
    r"IS_AUTHENTICATED_FULLY|IS_AUTHENTICATED_REMEMBERED)\b"
)
# Route kinds Spring Security's filter chain sits in front of. Micronaut, Ktor
# and Javalin routes have their own security and are left alone.
FILTER_CHAIN_KINDS = frozenset({"spring", "jaxrs", "functional"})
MODULE_BUILD_FILES = ("pom.xml", "build.gradle", "build.gradle.kts")
# Directory names whose security configs are test-only and never guard a route.
_TEST_DIR_NAMES = frozenset({"test", "tests", "testfixtures", "integrationtest", "it", "e2e"})
_ANNOTATION_TEXT_CHARS = 120


@dataclass
class MethodSecurity:
    decision: str  # REQUIRED or ANONYMOUS
    guard: str
    evidence: str


@dataclass
class RouteMeta:
    kind: str  # spring / jaxrs / functional / micronaut / ktor / javalin
    method_security: MethodSecurity | None = None


def _is_test_path(relative: str) -> bool:
    return any(part.lower() in _TEST_DIR_NAMES for part in relative.split("/")[:-1])


def _annotation_text(annotation: Annotation) -> str:
    text = f"@{annotation.name}" if annotation.args is None else f"@{annotation.name}({' '.join(annotation.args.split())})"
    return text if len(text) <= _ANNOTATION_TEXT_CHARS else text[: _ANNOTATION_TEXT_CHARS - 1] + "…"


def _method_security(block: AnnotationBlock | None, relative: str, content: str) -> MethodSecurity | None:
    """Auth a method-security annotation in ``block`` declares, if any.

    `@PermitAll`, `@PreAuthorize("permitAll()")` and `@Secured("IS_AUTHENTICATED_ANONYMOUSLY")`
    open the method; every other method-security annotation requires an
    authenticated caller.
    """
    if block is None:
        return None
    for annotation in block.annotations:
        if annotation.name not in METHOD_SECURITY_ANNOTATIONS:
            continue
        args = annotation.args or ""
        if annotation.name == "PermitAll" or (
            annotation.name in {"PreAuthorize", "Secured"}
            and _METHOD_SECURITY_PERMIT_RE.search(args)
            and not _METHOD_SECURITY_REQUIRED_RE.search(args)
        ):
            decision = ANONYMOUS
        else:
            decision = REQUIRED
        text = _annotation_text(annotation)
        return MethodSecurity(decision, text, f"{relative}:{line_of(content, annotation.start)} {text}")
    return None


# `RequestMethod.POST`, or a statically imported `POST`.
REQUEST_METHOD_RE = re.compile(r"(?<![\w$])(?:RequestMethod\.)?(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\b")


def _spring_methods(annotation: Annotation) -> list[str]:
    """HTTP methods of a `@RequestMapping` (`method = RequestMethod.X`, a
    statically imported `method = POST`, or an array)."""
    value = annotation.named.get("method", "")
    methods = REQUEST_METHOD_RE.findall(value)
    return list(dict.fromkeys(methods)) or ["ANY"]


# External HTTP calls
OUTBOUND_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r'\brestTemplate\.\w+(?:For\w+)?\s*\(\s*"(https?://[^"]+)"', re.IGNORECASE),
    re.compile(r'\bWebClient\.\w+\(\).*?\.uri\s*\(\s*"(https?://[^"]+)"', re.DOTALL),
    re.compile(r'\bHttpRequest\.newBuilder\(\s*URI\.create\s*\(\s*"(https?://[^"]+)"'),
    re.compile(r'\bnew\s+Request\.Builder\(\)[^.]*\.url\s*\(\s*"(https?://[^"]+)"', re.DOTALL),
    re.compile(r'\b(?:OkHttpClient|HttpClient)\(\s*\)[^.]*?\.url\s*\(\s*"(https?://[^"]+)"', re.DOTALL),
]

# Database libs
DB_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r'\borg\.springframework\.data\.jpa\b|\bJpaRepository\b|\b@Entity\b'), "sql"),
    (re.compile(r'\borg\.springframework\.data\.mongodb\b|\bMongoRepository\b|\b@Document\b'), "mongodb"),
    (re.compile(r'\borg\.springframework\.data\.redis\b|\bRedisTemplate\b'), "redis"),
    (re.compile(r'\borg\.springframework\.data\.cassandra\b|\bCassandraRepository\b'), "cassandra"),
    (re.compile(r'\borg\.hibernate\b|\bSessionFactory\b'), "sql"),
    (re.compile(r'\borg\.jooq\b|\bDSLContext\b'), "sql"),
    (re.compile(r'\bDriverManager\.getConnection\s*\(\s*"jdbc:postgresql:'), "postgresql"),
    (re.compile(r'\bDriverManager\.getConnection\s*\(\s*"jdbc:mysql:'), "mysql"),
    (re.compile(r'\bDriverManager\.getConnection\s*\(\s*"jdbc:sqlite:'), "sqlite"),
    (re.compile(r'\bDriverManager\.getConnection\s*\(\s*"jdbc:oracle:'), "oracle"),
    (re.compile(r'\bDriverManager\.getConnection\s*\('), "sql"),
    (re.compile(r'\bMongoClients\.create\s*\(|\bcom\.mongodb\.client\b'), "mongodb"),
    (re.compile(r'\bJedis\b|\blettuce\b', re.IGNORECASE), "redis"),
    (re.compile(r'\bsoftware\.amazon\.awssdk\.services\.s3\b|\bAmazonS3\b'), "object_storage"),
    (re.compile(r'\bsoftware\.amazon\.awssdk\.services\.dynamodb\b|\bAmazonDynamoDB\b'), "dynamodb"),
]

# Auth-related signals
AUTH_PATTERNS: list[tuple[re.Pattern[str], str, float]] = [
    (re.compile(r'\borg\.springframework\.security\.config\.\w+\.SecurityFilterChain\b|\bSecurityFilterChain\s+\w+\s*\('), "spring_security_filter_chain", 0.9),
    (re.compile(r'@PreAuthorize\s*\(|@PostAuthorize\s*\('), "spring_method_security", 0.9),
    (re.compile(r'@Secured\s*\(|@RolesAllowed\s*\('), "role_check", 0.85),
    (re.compile(r'\bWebSecurityConfigurerAdapter\b'), "spring_security_legacy", 0.85),
    (re.compile(r'\bio\.jsonwebtoken\b|\bJwts\.\w+\(|\bJWT\.create\(|\bnimbusds\.jwt\b', re.IGNORECASE), "jwt", 0.85),
    (re.compile(r'\bBCryptPasswordEncoder\b'), "bcrypt", 0.9),
    (re.compile(r'\bArgon2PasswordEncoder\b|\bargon2\b', re.IGNORECASE), "argon2", 0.9),
    (re.compile(r'\bSCryptPasswordEncoder\b'), "scrypt", 0.9),
    (re.compile(r'\boauth2Login\s*\(|\bOAuth2AuthenticationToken\b'), "oauth", 0.85),
    (re.compile(r'@EnableWebSecurity\b'), "spring_security_enabled", 0.85),
    (re.compile(r'@EnableGlobalMethodSecurity\b|@EnableMethodSecurity\b'), "spring_method_security_enabled", 0.85),
    (re.compile(r'\bAuthorization\b'), "authorization_header", 0.6),
    (re.compile(r'\bBearer\b'), "bearer_token", 0.6),
    (re.compile(r'\bapi[_-]?key\b', re.IGNORECASE), "api_key", 0.6),
]

FRAMEWORK_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r'\borg\.springframework\.boot\b|@SpringBootApplication\b'), "spring-boot"),
    (re.compile(r'\borg\.springframework\.web\b|@RestController\b|@Controller\b'), "spring-mvc"),
    (re.compile(r'\borg\.springframework\.webflux\b|\bWebFlux\b'), "spring-webflux"),
    (re.compile(r'\bjavax\.ws\.rs\b|\bjakarta\.ws\.rs\b'), "jax-rs"),
    (re.compile(r'\borg\.eclipse\.jersey\b|\bJersey\b'), "jersey"),
    (re.compile(r'\bio\.quarkus\b'), "quarkus"),
    (re.compile(r'\bio\.ktor\b|\bktor\.server\b'), "ktor"),
    (re.compile(r'\bio\.micronaut\b'), "micronaut"),
    (re.compile(r'\bio\.javalin\b'), "javalin"),
    (re.compile(r'\borg\.springframework\.security\b'), "spring-security"),
]

ENTRYPOINT_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r'@SpringBootApplication\b'), "spring_boot_application"),
    (re.compile(r'\bSpringApplication\.run\s*\('), "spring_application_run"),
    (re.compile(r'\bembeddedServletContainerFactory\b'), "embedded_servlet_container"),
    (re.compile(r'\bquarkusMain\b|\bQuarkusApplication\b'), "quarkus_main"),
    (re.compile(r'\bembeddedServer\s*\(\s*Netty\b|\bembeddedServer\s*\(\s*Tomcat\b|\bembeddedServer\s*\(\s*Jetty\b'), "ktor_embedded_server"),
    (re.compile(r'\bJavalin\.create\s*\(\s*\)?'), "javalin_create"),
]

# Secrets in Java are commonly two shapes:
# - System.getenv("X")
# - @Value("${X}")  (where X looks secret-like)
# - Environment.getProperty("X")
SECRET_PATTERNS: list[re.Pattern[str]] = [
    re.compile(
        r'\bSystem\.getenv\s*\(\s*"([A-Z0-9_]*(?:SECRET|TOKEN|KEY|PASSWORD|PASS|PWD)[A-Z0-9_]*)"',
    ),
    re.compile(
        r'@Value\s*\(\s*"\$\{([A-Za-z0-9_.]*(?:secret|token|key|password|pass|pwd)[A-Za-z0-9_.]*)\}?"',
        re.IGNORECASE,
    ),
    re.compile(
        r'\bgetProperty\s*\(\s*"([A-Za-z0-9_.]*(?:secret|token|key|password|pass|pwd)[A-Za-z0-9_.]*)"',
        re.IGNORECASE,
    ),
]


# Kept rather than attackmap.sdk.line_snippet: this takes a match offset and
# splits on "\n" only, so it stays consistent with line_of() on files that
# contain form feeds or other str.splitlines() separators, and it costs
# O(line) per match instead of O(file).
def _line_snippet(content: str, offset: int, *, max_chars: int = _SNIPPET_MAX_CHARS) -> str:
    line_start = content.rfind("\n", 0, offset) + 1
    line_end = content.find("\n", offset)
    if line_end == -1:
        line_end = len(content)
    line = content[line_start:line_end].strip()
    if len(line) > max_chars:
        line = line[: max_chars - 1] + "…"
    return line


def _join_paths(prefix: str, suffix: str) -> str:
    """Join a class-level prefix and a method-level path Spring-style."""
    p = prefix.strip()
    s = suffix.strip()
    if not p:
        return s or "/"
    if not s:
        return p or "/"
    if p == "/":
        return s if s.startswith("/") else "/" + s
    if s == "/":
        return p
    return p.rstrip("/") + "/" + s.lstrip("/")


def _route_path(prefix: str, suffix: str) -> str:
    """Join a class path and a member path, normalized to a leading `/`."""
    path = _join_paths(prefix, suffix)
    return path if path.startswith("/") else "/" + path


def _module_name_from_pom(pom_path: Path, root: Path | None = None) -> str | None:
    text = read_source(pom_path, root=root)
    if text is None:
        return None
    artifact = re.search(r"<artifactId>([^<]+)</artifactId>", text)
    if artifact:
        return artifact.group(1).strip()
    return None


def _module_name_from_gradle(root: Path) -> str | None:
    for candidate in ("settings.gradle", "settings.gradle.kts"):
        text = read_source(root / candidate, root=root)
        if text is None:
            continue
        match = re.search(r'rootProject\.name\s*=\s*[\'"]([^\'"]+)[\'"]', text)
        if match:
            return match.group(1).strip()
    return None


def _spring_app_name_from_properties(root: Path) -> str | None:
    for candidate in (
        "src/main/resources/application.properties",
        "src/main/resources/application.yml",
        "application.properties",
        "application.yml",
    ):
        text = read_source(root / candidate, root=root)
        if text is None:
            continue
        match = re.search(r'^\s*spring\.application\.name\s*[:=]\s*([^\s#]+)', text, re.MULTILINE)
        if match:
            return match.group(1).strip().strip("'\"")
    return None


def _class_block_paths(block: AnnotationBlock, is_jaxrs: bool, is_micronaut: bool) -> list[str] | None:
    """Path prefixes a class-level annotation block declares, or None for none."""
    for annotation in block.get("RequestMapping"):
        return annotation_paths(annotation, SPRING_PATH_KEYS)
    if is_jaxrs:
        for annotation in block.get("Path"):
            return annotation_paths(annotation, ("value",))
    if is_micronaut:
        for annotation in block.get("Controller"):
            paths = annotation_paths(annotation, MICRONAUT_PATH_KEYS)
            # A bare Micronaut @Controller is mounted at "/".
            return paths if paths != [""] else ["/"]
    return None


def _member_routes(
    block: AnnotationBlock, is_jaxrs: bool, is_micronaut: bool
) -> list[tuple[Annotation, str, list[str], str]]:
    """(anchor annotation, HTTP method, member paths, kind) for a member's block.

    A JAX-RS verb pairs only with the `@Path` in its own block, i.e. the
    annotations between the previous member and this method's signature, so a
    neighbouring method's path is never borrowed (#3).
    """
    routes: list[tuple[Annotation, str, list[str], str]] = []
    for annotation in block.annotations:
        if annotation.name in SPRING_VERB_MAPPINGS:
            paths = annotation_paths(annotation, SPRING_PATH_KEYS)
            if paths is not None:
                routes.append((annotation, SPRING_VERB_MAPPINGS[annotation.name], paths, "spring"))
        elif annotation.name == "RequestMapping":
            paths = annotation_paths(annotation, SPRING_PATH_KEYS)
            if paths is not None:
                routes.extend((annotation, method, paths, "spring") for method in _spring_methods(annotation))
        elif is_micronaut and annotation.name in MICRONAUT_VERBS:
            paths = annotation_paths(annotation, MICRONAUT_PATH_KEYS)
            if paths is not None:
                routes.append((annotation, MICRONAUT_VERBS[annotation.name], paths, "micronaut"))
    if is_jaxrs:
        verbs = [a for a in block.annotations if a.name in JAXRS_VERBS and a.args is None]
        if verbs:
            path_annotation = next(iter(block.get("Path")), None)
            paths = annotation_paths(path_annotation, ("value",)) if path_annotation else [""]
            if paths is not None:
                anchor = path_annotation or verbs[0]
                routes.extend((anchor, verb.name, paths, "jaxrs") for verb in verbs)
    return routes


class JavaSpringAnalyzer:
    metadata = AnalyzerMetadata(
        name="java-spring",
        display_name="Java/Kotlin Spring Boot Analyzer",
        version="0.1.0",
        description="Java and Kotlin analyzer with Spring Boot, JAX-RS, Ktor, and Spring Security awareness.",
        scope="Maven, Gradle, and Kotlin Spring Boot projects. Detects Spring MVC, JAX-RS, Ktor, Javalin, and Micronaut routing.",
        targets=["java", "kotlin", "spring", "spring-boot"],
        languages=["java", "kotlin"],
        # Framework band (50-149): core runs analyzers in (priority, name) order
        # across built-ins and plugins, and merge is first-seen-wins.
        priority=60,
        experimental=False,
        enabled_by_default=True,
    )

    @property
    def name(self) -> str:
        return self.metadata.name

    # ---------- Public entry points ----------

    def detect(self, repo_path: str | Path) -> bool:
        root = Path(repo_path).resolve()
        if not root.exists() or not root.is_dir():
            return False
        for marker in ("pom.xml", "build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts"):
            if (root / marker).exists():
                return True
        # Any nested source or build file; stop at the first one.
        return next(iter_repo_files(root, suffixes=CODE_SUFFIXES, names=BUILD_FILES, skip_dirs=SKIP_DIRS), None) is not None

    def analyze(self, repo_path: str | Path) -> ScanResult:
        root = Path(repo_path).resolve()
        result = ScanResult(root=str(root))
        if not root.exists() or not root.is_dir():
            return result

        # Service-name hints from build/application metadata
        artifact = _module_name_from_pom(root / "pom.xml", root)
        gradle_name = _module_name_from_gradle(root)
        spring_app = _spring_app_name_from_properties(root)
        if artifact:
            self._append_unique_service(result, f"artifact:{artifact}", "pom.xml")
        if gradle_name:
            self._append_unique_service(result, f"gradle_root:{gradle_name}", "settings.gradle")
        if spring_app:
            self._append_unique_service(result, f"spring_app:{spring_app}", "application.properties")

        route_meta: dict[tuple[str, str, str], RouteMeta] = {}
        security: dict[str, FileSecurity] = {}
        for file_path in iter_repo_files(root, suffixes=CODE_SUFFIXES, skip_dirs=SKIP_DIRS):
            content = read_source(file_path, root=root)
            if content is None:
                continue

            result.files_scanned += 1
            language = "kotlin" if file_path.suffix.lower() in {".kt", ".kts"} else "java"
            if language not in result.languages:
                result.languages.append(language)

            relative = rel(file_path, root)
            self._extract_routes(content, relative, result, route_meta)
            self._extract_security_rules(content, relative, security)
            self._extract_databases(content, relative, result)
            self._extract_auth(content, relative, result)
            self._extract_secrets(content, relative, result)
            self._extract_external_calls(content, relative, result)
            self._extract_frameworks(content, relative, result)
            self._extract_entrypoints(content, relative, result)
            self._infer_service_role(content, relative, result)

        self._apply_route_auth(root, result, route_meta, security)
        result.languages.sort()
        return result

    # ---------- Extractors ----------

    def _extract_routes(
        self,
        content: str,
        relative: str,
        result: ScanResult,
        route_meta: dict[tuple[str, str, str], RouteMeta] | None = None,
    ) -> None:
        meta = route_meta if route_meta is not None else {}
        self._extract_annotation_routes(content, relative, result, meta)

        # Ktor: routing { get("/x") { ... } }
        if "io.ktor" in content or "ktor.server.routing" in content:
            for match in KTOR_ROUTE_PATTERN.finditer(content):
                method, path = match.group(1).upper(), match.group(2)
                self._append_unique_route(result, path, method, relative, line_of(content, match.start()), meta, RouteMeta("ktor"))

        # Javalin: app.get("/x", ...)
        if "io.javalin" in content or "Javalin.create" in content:
            for match in JAVALIN_ROUTE_PATTERN.finditer(content):
                method, path = match.group(1).upper(), match.group(2)
                self._append_unique_route(result, path, method, relative, line_of(content, match.start()), meta, RouteMeta("javalin"))

        # Spring functional endpoints: RouterFunctions / route() builder /
        # Kotlin router {} and coRouter {} (#3).
        if FUNCTIONAL_GATE_RE.search(content):
            for route in functional_routes(mask_comments(content)):
                self._append_unique_route(
                    result, route.path, route.method, relative, line_of(content, route.offset), meta, RouteMeta("functional")
                )

    def _extract_security_rules(self, content: str, relative: str, security: dict[str, FileSecurity]) -> None:
        """Spring Security authorization rules in ``content`` (#3).

        Test configurations (`src/test/...`) never guard a deployed route.
        """
        if _is_test_path(relative) or not SECURITY_GATE_RE.search(content):
            return
        parsed = parse_security(mask_comments(content), relative)
        if parsed.chains or parsed.ignored:
            security[relative] = parsed

    def _apply_route_auth(
        self,
        root: Path,
        result: ScanResult,
        route_meta: dict[tuple[str, str, str], RouteMeta],
        security: dict[str, FileSecurity],
    ) -> None:
        """Set `Route.auth` from filter-chain rules and method security.

        A chain applies to routes in its own build module (nearest `pom.xml` /
        `build.gradle`); a module with routes but no chain of its own uses the
        chains of route-less modules (a shared security library). Method security
        can only narrow access: it turns an `anonymous` chain decision into
        `required`, and `@PermitAll` never opens a route the chain protects.
        """
        module_cache: dict[str, str] = {}
        chains_by_module: dict[str, list[SecurityChain]] = {}
        ignored_by_module: dict[str, list[Rule]] = {}
        for relative, parsed in security.items():
            module = _module_of(root, relative, module_cache)
            chains_by_module.setdefault(module, []).extend(parsed.chains)
            ignored_by_module.setdefault(module, []).extend(parsed.ignored)
        route_modules = {_module_of(root, r.file, module_cache) for r in result.routes}
        shared = [m for m in chains_by_module if m not in route_modules]

        for route in result.routes:
            meta = route_meta.get((route.path, route.method, route.file))
            if meta is None:
                continue
            chain_result: Resolution | None = None
            if meta.kind in FILTER_CHAIN_KINDS and chains_by_module:
                module = _module_of(root, route.file, module_cache)
                modules = [module] if module in chains_by_module else shared
                chains = [c for m in modules for c in chains_by_module[m]]
                ignored = [r for m in modules for r in ignored_by_module.get(m, [])]
                route_dir = route.file.rsplit("/", 1)[0] if "/" in route.file else ""
                chain_result = resolve_route(chains, ignored, route.path, route.method, route_dir)
            method_security = meta.method_security
            method_required = method_security is not None and method_security.decision == REQUIRED
            if chain_result is not None and chain_result.decision == REQUIRED:
                route.auth = "required"
                route.guards = [*chain_result.guards, *([method_security.guard] if method_required else [])]
                route.guard_evidence = chain_result.evidence
            elif method_required:
                route.auth = "required"
                route.guards = [method_security.guard]
                route.guard_evidence = method_security.evidence
            elif chain_result is not None and chain_result.decision == ANONYMOUS:
                route.auth = "anonymous"
                route.guards = []
                route.guard_evidence = chain_result.evidence

    def _extract_annotation_routes(
        self, content: str, relative: str, result: ScanResult, meta: dict[tuple[str, str, str], RouteMeta]
    ) -> None:
        """Spring MVC, JAX-RS and Micronaut annotation routes (#2).

        Each annotation block is attributed to a class (its paths become the
        prefix for that class body, found by brace matching) or to a member
        (a route under the innermost enclosing class's prefixes).
        """
        if "@" not in content:
            return
        is_jaxrs = "javax.ws.rs" in content or "jakarta.ws.rs" in content
        is_micronaut = "io.micronaut" in content
        masked = mask_comments(content)
        # Group every annotation (not just route ones) so `@Validated` between
        # `@RequestMapping` and `class` keeps the block on the class.
        annotations = find_annotations(masked)
        if not any(a.name in ROUTE_ANNOTATIONS for a in annotations):
            return
        blocks = group_blocks(masked, annotations)
        scopes = class_scopes(masked)

        # Class keyword offset -> that class's path prefixes / annotation block.
        class_paths: dict[int, list[str]] = {}
        class_blocks: dict[int, AnnotationBlock] = {}
        for block in blocks:
            if block.class_keyword_at is None:
                continue
            class_blocks[block.class_keyword_at] = block
            prefixes = _class_block_paths(block, is_jaxrs, is_micronaut)
            if prefixes is not None:
                class_paths[block.class_keyword_at] = prefixes

        for block in blocks:
            if block.class_keyword_at is not None:
                continue
            members = _member_routes(block, is_jaxrs, is_micronaut)
            if not members:
                continue
            scope = innermost_scope(scopes, block.annotations[0].start)
            prefixes = class_paths.get(scope.keyword_at, [""]) if scope is not None else [""]
            # Method-level security overrides class-level security.
            security = _method_security(block, relative, content) or (
                _method_security(class_blocks.get(scope.keyword_at), relative, content) if scope is not None else None
            )
            for annotation, method, paths, kind in members:
                line = line_of(content, annotation.start)
                route_meta = RouteMeta(kind, security if kind in FILTER_CHAIN_KINDS else None)
                for prefix in prefixes:
                    for suffix in paths:
                        self._append_unique_route(
                            result, _route_path(prefix, suffix), method, relative, line, meta, route_meta
                        )

    def _extract_databases(self, content: str, relative: str, result: ScanResult) -> None:
        for pattern, kind in DB_PATTERNS:
            match = pattern.search(content)
            if match is None:
                continue
            self._append_unique_database(
                result, kind, relative,
                line_of(content, match.start()),
                _line_snippet(content, match.start()),
            )

    def _extract_auth(self, content: str, relative: str, result: ScanResult) -> None:
        for pattern, hint, confidence in AUTH_PATTERNS:
            match = pattern.search(content)
            if match is None:
                continue
            self._append_unique_auth(
                result, hint, relative,
                line_of(content, match.start()),
                _line_snippet(content, match.start()),
                confidence,
            )

    def _extract_secrets(self, content: str, relative: str, result: ScanResult) -> None:
        for pattern in SECRET_PATTERNS:
            for match in pattern.finditer(content):
                groups = match.groups()
                name = groups[0] if groups and groups[0] else "unknown"
                self._append_unique_secret(
                    result, name, relative,
                    line_of(content, match.start()),
                    _line_snippet(content, match.start()),
                )

    def _extract_external_calls(self, content: str, relative: str, result: ScanResult) -> None:
        for pattern in OUTBOUND_PATTERNS:
            for match in pattern.finditer(content):
                target = match.group(1)
                if not (target.startswith("http://") or target.startswith("https://")):
                    continue
                self._append_unique_external(
                    result, target, relative,
                    line_of(content, match.start()),
                    _line_snippet(content, match.start()),
                )

    def _extract_frameworks(self, content: str, relative: str, result: ScanResult) -> None:
        for pattern, name in FRAMEWORK_PATTERNS:
            match = pattern.search(content)
            if match is None:
                continue
            self._append_unique_framework(
                result, name, relative,
                line_of(content, match.start()),
                _line_snippet(content, match.start()),
            )

    def _extract_entrypoints(self, content: str, relative: str, result: ScanResult) -> None:
        for pattern, hint in ENTRYPOINT_PATTERNS:
            match = pattern.search(content)
            if match is None:
                continue
            self._append_unique_entrypoint(
                result, hint, relative,
                line_of(content, match.start()),
                _line_snippet(content, match.start()),
            )

    def _infer_service_role(self, content: str, relative: str, result: ScanResult) -> None:
        haystack = (relative + " " + content[:500]).lower()
        role: str | None = None
        if any(token in haystack for token in ("worker", "consumer", "queue", "scheduler", "background")):
            role = "worker"
        elif any(token in haystack for token in ("controller", "rest", "resource", "api", "router")):
            role = "api"
        elif any(token in haystack for token in ("client", "sdk")):
            role = "client"
        if role:
            self._append_unique_service(result, f"service_role:{role}", relative)

    # ---------- Append helpers ----------

    @staticmethod
    def _append_unique_route(
        result: ScanResult,
        path: str,
        method: str,
        file: str,
        line: int | None,
        route_meta: dict[tuple[str, str, str], RouteMeta] | None = None,
        meta: RouteMeta | None = None,
    ) -> None:
        key = (path, method, file)
        if route_meta is not None and key in route_meta:
            return
        if any((item.path, item.method, item.file) == key for item in result.routes):
            return
        result.routes.append(Route(path=path, method=method, file=file, line=line))
        if route_meta is not None and meta is not None:
            route_meta[key] = meta

    @staticmethod
    def _append_unique_database(result: ScanResult, kind: str, file: str, line: int | None, evidence: str | None) -> None:
        key = (kind, file)
        if any((item.kind, item.file) == key for item in result.databases):
            return
        result.databases.append(DatabaseHint(kind=kind, file=file, line=line, evidence_text=evidence))

    @staticmethod
    def _append_unique_auth(result: ScanResult, hint: str, file: str, line: int | None, evidence: str | None, confidence: float) -> None:
        key = (hint, file)
        if any((item.hint, item.file) == key for item in result.auth_hints):
            return
        result.auth_hints.append(AuthHint(hint=hint, file=file, line=line, evidence_text=evidence, confidence=confidence))

    @staticmethod
    def _append_unique_secret(result: ScanResult, name: str, file: str, line: int | None, evidence: str | None) -> None:
        key = (name, file)
        if any((item.name, item.file) == key for item in result.secret_hints):
            return
        result.secret_hints.append(SecretHint(name=name, file=file, line=line, evidence_text=evidence, confidence=0.85))

    @staticmethod
    def _append_unique_external(result: ScanResult, target: str, file: str, line: int | None, evidence: str | None) -> None:
        key = (target, file)
        if any((item.target, item.file) == key for item in result.external_calls):
            return
        result.external_calls.append(ExternalCall(target=target, file=file, line=line, evidence_text=evidence))

    @staticmethod
    def _append_unique_framework(result: ScanResult, hint: str, file: str, line: int | None, evidence: str | None) -> None:
        key = (hint, file)
        if any((item.hint, item.file) == key for item in result.framework_hints):
            return
        result.framework_hints.append(FrameworkHint(hint=hint, file=file, line=line, evidence_text=evidence))

    @staticmethod
    def _append_unique_entrypoint(result: ScanResult, hint: str, file: str, line: int | None, evidence: str | None) -> None:
        key = (hint, file)
        if any((item.hint, item.file) == key for item in result.entrypoint_hints):
            return
        result.entrypoint_hints.append(EntrypointHint(hint=hint, file=file, line=line, evidence_text=evidence))

    @staticmethod
    def _append_unique_service(result: ScanResult, hint: str, file: str) -> None:
        key = (hint, file)
        if any((item.hint, item.file) == key for item in result.service_hints):
            return
        result.service_hints.append(ServiceHint(hint=hint, file=file))


def _module_of(root: Path, relative: str, cache: dict[str, str]) -> str:
    """Directory (relative to ``root``) of the nearest build file above ``relative``.

    ``cache`` maps every directory already looked at to its module.
    """
    directory = relative.rsplit("/", 1)[0] if "/" in relative else ""
    walked: list[str] = []
    found = ""
    while True:
        if directory in cache:
            found = cache[directory]
            break
        walked.append(directory)
        base = root / directory if directory else root
        if not directory or any((base / name).is_file() for name in MODULE_BUILD_FILES):
            found = directory
            break
        directory = directory.rsplit("/", 1)[0] if "/" in directory else ""
    for seen in walked:
        cache[seen] = found
    return found


__all__ = ["JavaSpringAnalyzer"]
