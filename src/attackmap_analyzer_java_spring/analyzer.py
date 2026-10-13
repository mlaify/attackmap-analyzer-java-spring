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
from dataclasses import dataclass, field
from pathlib import Path

from attackmap.sdk import (
    DEFAULT_SKIP_DIRS,
    AnalyzerMetadata,
    AuthHint,
    DatabaseHint,
    EntrypointHint,
    ExternalCall,
    FrameworkHint,
    iter_repo_files,
    line_of,
    read_source,
    rel,
    Route,
    ScanResult,
    SecretHint,
    ServiceHint,
)

from .annotations import (
    Annotation,
    AnnotationBlock,
    annotation_paths,
    bracket_end,
    class_scopes,
    find_annotations,
    group_blocks,
    innermost_scope,
    mask_comments,
    split_top_level,
    string_values,
)
from .constants import ConstantTable, resolve_expression
from .functional import FUNCTIONAL_GATE_RE, functional_routes
from .security_dsl import (
    ANONYMOUS,
    ANONYMOUS_AUTHORITY_RE,
    REQUIRED,
    SECURITY_GATE_RE,
    UNKNOWN,
    Budget,
    BudgetExceeded,
    FileSecurity,
    Resolution,
    Rule,
    SecurityChain,
    parse_security,
    resolve_route,
    spel_decision,
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

# Method security annotations (Spring and JSR-250) on a handler or its class,
# and the switch family that turns each on. `@PostAuthorize` / `@PostFilter` run
# after the handler, so they never guard against its side effects.
PREPOST, SECURED, JSR250 = "prePost", "secured", "jsr250"
METHOD_SECURITY_FAMILIES = {
    "PreAuthorize": PREPOST,
    "Secured": SECURED,
    "RolesAllowed": JSR250,
    "DenyAll": JSR250,
    "PermitAll": JSR250,
}
ENABLE_METHOD_SECURITY = frozenset({"EnableMethodSecurity", "EnableGlobalMethodSecurity", "EnableReactiveMethodSecurity"})
# JAX-RS runtimes that enforce @RolesAllowed themselves: Jersey's feature, Quarkus security.
JAXRS_ROLES_RE = re.compile(r"\bRolesAllowedDynamicFeature\b|\bio\.quarkus\.security\b")
JAXRS_JSR250 = "jaxrs-jsr250"
# Spring MVC trailing-slash matching switched on explicitly (it is off by default in Spring 6).
# Spring 6.2's `UrlHandlerFilter.trailingSlashHandler(..)` does the same by redirect or wrap.
TRAILING_SLASH_ON_RE = re.compile(
    r"\b(?:setUseTrailingSlashMatch|useTrailingSlashMatch)\s*\(\s*true\b|\bisUseTrailingSlashMatch\s*=\s*true\b"
    r"|\bUrlHandlerFilter\b"
)
# A real `import jakarta.servlet...` line (Spring 6 / Boot 3), not a mention.
JAKARTA_IMPORT_RE = re.compile(r"^[ \t]*import[ \t]+jakarta\.servlet\.", re.MULTILINE)
# The DispatcherServlet or Jersey mounted below `/`: Ant matchers then see the
# servlet path in front of the route, so the route's own path isn't what they match.
SERVLET_PATH_PROPERTY_RE = re.compile(
    r"^[ \t]*spring\.(mvc\.servlet\.path|jersey\.application-path)[ \t]*[=:][ \t]*[\"']?([^\s#\"']*)", re.MULTILINE
)
# One `key: value` YAML line (block mappings only; flow style and lists are skipped).
YAML_LINE_RE = re.compile(r"([ ]*)([A-Za-z0-9_.\-]+)[ \t]*:(?:[ \t]+[\"']?([^\s#\"']*))?[ \t]*(?:#.*)?")
SERVLET_PATH_KEYS = {"spring.mvc.servlet.path": "mvc", "spring.jersey.application-path": "jersey"}
MAX_YAML_LINES = 20_000
APPLICATION_PATH_RE = re.compile(r"@ApplicationPath\s*\(")
# The same set in code: `PathMatchConfigurer.addPathPrefix("/api", predicate)`, or
# the DispatcherServlet registered on a sub-path (`new DispatcherServletRegistrationBean(
# servlet, "/api/*")`, `new ServletRegistrationBean<>(dispatcherServlet, "/api/*")`).
SERVLET_PREFIX_CALL_RE = re.compile(
    r"\baddPathPrefix\s*\(|\b(DispatcherServletRegistrationBean|ServletRegistrationBean)\s*(?:<[^<>()]{0,100}>)?\s*\("
)
_ROOT_PATHS = frozenset({"", "/", "/*", "/**"})
CONFIG_SUFFIXES = {".properties", ".yml", ".yaml"}
# Spring Boot major version in a Maven or Gradle build file.
BOOT_VERSION_RE = re.compile(
    r"spring-boot-starter-parent</artifactId>\s*<version>\s*(\d+)\."
    r"|spring-boot-dependencies</artifactId>\s*<version>\s*(\d+)\."
    r"|<spring-boot\.version>\s*(\d+)\."
    r"|org\.springframework\.boot[\"']?\)?\s+version\s+[\"'](\d+)\."
    r"|spring-boot-gradle-plugin:(\d+)\."
    r"|springBootVersion\s*=\s*[\"'](\d+)\."
)
# Route kinds Spring Security's filter chain sits in front of. Micronaut, Ktor
# and Javalin routes have their own security and are left alone.
FILTER_CHAIN_KINDS = frozenset({"spring", "jaxrs", "functional"})
MODULE_BUILD_FILES = ("pom.xml", "build.gradle", "build.gradle.kts")
# Directory names whose security configs are test-only and never guard a route.
_TEST_DIR_NAMES = frozenset({"test", "tests", "testfixtures", "integrationtest", "it", "e2e"})
_ANNOTATION_TEXT_CHARS = 120
_DECISION_RANK = {None: 0, ANONYMOUS: 0, UNKNOWN: 1, REQUIRED: 2}


@dataclass
class MethodSecurity:
    family: str  # PREPOST / SECURED / JSR250
    name: str  # the annotation, e.g. "PreAuthorize"
    # Argument expressions; read once the repo's constants are known (#11).
    sources: list[str]
    guard: str
    evidence: str
    decision: str = UNKNOWN  # REQUIRED / ANONYMOUS / UNKNOWN, set by resolve()
    resolved: bool = False

    def resolve(self, constants: ConstantTable) -> None:
        if not self.resolved:
            self.decision = _method_decision(self.name, self.sources, constants)
            self.resolved = True


@dataclass
class RouteMeta:
    kind: str  # spring / jaxrs / functional / micronaut / ktor / javalin
    # One (method-level, class-level) annotation pair per handler mapped to this
    # route key; several when `params=` / `headers=` variants share a path+method.
    method_security: list[tuple[list[MethodSecurity], list[MethodSecurity]]] = field(default_factory=list)


@dataclass
class RepoSecurity:
    """Security facts gathered while walking the repo, applied at the end."""

    files: dict[str, FileSecurity] = field(default_factory=dict)
    # Comment-masked text of files with security rules, parsed once every
    # constant in the repo is known.
    pending: dict[str, str] = field(default_factory=dict)
    constants: ConstantTable = field(default_factory=ConstantTable)
    # File -> method-security switches it turns on (PREPOST / SECURED / JSR250 / JAXRS_JSR250).
    switches: dict[str, set[str]] = field(default_factory=dict)
    # Main-source files importing `jakarta.servlet` (Spring 6: no trailing-slash
    # matching by default), used when no build file declares a Boot version.
    jakarta_files: set[str] = field(default_factory=set)
    trailing_slash_on: bool = False
    # Files that mount the DispatcherServlet / Jersey below `/` (or set it to
    # something unreadable); applied to routes in the same build module.
    mvc_path_files: set[str] = field(default_factory=set)
    jersey_path_files: set[str] = field(default_factory=set)


def _is_test_path(relative: str) -> bool:
    return any(part.lower() in _TEST_DIR_NAMES for part in relative.split("/")[:-1])


def _annotation_text(annotation: Annotation) -> str:
    text = f"@{annotation.name}" if annotation.args is None else f"@{annotation.name}({' '.join(annotation.args.split())})"
    return text if len(text) <= _ANNOTATION_TEXT_CHARS else text[: _ANNOTATION_TEXT_CHARS - 1] + "…"


def _method_security(block: AnnotationBlock | None, relative: str, content: str) -> list[MethodSecurity]:
    """Method-security annotations in ``block``; their access is decided later
    by `_method_decision`, once the repo's constants are known."""
    found: list[MethodSecurity] = []
    if block is None:
        return found
    for annotation in block.annotations:
        family = METHOD_SECURITY_FAMILIES.get(annotation.name)
        if family is None:
            continue
        sources = [*annotation.positional, *([annotation.named["value"]] if "value" in annotation.named else [])]
        text = _annotation_text(annotation)
        evidence = f"{relative}:{line_of(content, annotation.start)} {text}"
        found.append(MethodSecurity(family, annotation.name, sources, text, evidence))
    return found


def _array_elements(source: str) -> list[str]:
    """Elements of `{a, b}`, Kotlin `[a, b]` / `arrayOf(a, b)`, or the value itself."""
    v = source.strip()
    if (v.startswith("{") and v.endswith("}")) or (v.startswith("[") and v.endswith("]")):
        return split_top_level(v[1:-1])
    if v.startswith("arrayOf(") and v.endswith(")"):
        return split_top_level(v[len("arrayOf(") : -1])
    return [v]


def _method_decision(name: str, sources: list[str], constants: ConstantTable) -> str:
    """The access one method-security annotation declares.

    `@PreAuthorize` SpEL is read like `access(...)`, from one string literal or
    literals and same-repo constants joined by `+`. `@Secured` / `@RolesAllowed`
    naming an ANONYMOUS authority, and `@PermitAll`, open the method; `@DenyAll`
    and other roles require an authenticated caller. Any argument that can't be
    resolved makes the annotation UNKNOWN.
    """
    if name == "PreAuthorize":
        expression = resolve_expression(sources[0], constants) if len(sources) == 1 else None
        return spel_decision(expression) if expression is not None else UNKNOWN
    if name in ("Secured", "RolesAllowed"):
        roles: list[str] = []
        for source in sources:
            for element in _array_elements(source):
                value = resolve_expression(element, constants)
                if value is None:
                    return UNKNOWN
                roles.append(value)
        if not roles:
            return UNKNOWN
        return ANONYMOUS if any(ANONYMOUS_AUTHORITY_RE.search(r) for r in roles) else REQUIRED
    if name == "DenyAll":
        return REQUIRED
    return ANONYMOUS


def _method_security_switches(content: str) -> set[str]:
    """Method-security families a file switches on (`@EnableMethodSecurity` & co.)."""
    switches: set[str] = set()
    if "MethodSecurity" not in content and "RolesAllowedDynamicFeature" not in content and "io.quarkus" not in content:
        return switches
    masked = mask_comments(content)
    for annotation in find_annotations(masked, ENABLE_METHOD_SECURITY):
        named = {k: v.strip() for k, v in annotation.named.items()}
        if annotation.name == "EnableMethodSecurity":
            if named.get("prePostEnabled") != "false":
                switches.add(PREPOST)
        elif annotation.name == "EnableReactiveMethodSecurity":
            switches.add(PREPOST)
        elif named.get("prePostEnabled") == "true":
            switches.add(PREPOST)
        if named.get("securedEnabled") == "true":
            switches.add(SECURED)
        if named.get("jsr250Enabled") == "true":
            switches.add(JSR250)
    if JAXRS_ROLES_RE.search(masked):
        switches.add(JAXRS_JSR250)
    return switches


def _effective_method_security(
    levels: tuple[list[MethodSecurity], list[MethodSecurity]], switches: set[str], kind: str
) -> MethodSecurity | None:
    """What the method security that is switched on does for one handler.

    Each enabled family looks at the method first, then the class. Every
    enabled interceptor runs, so one that requires authentication guards the
    handler; annotations whose family isn't switched on do nothing.
    """
    method_level, class_level = levels
    picks: list[MethodSecurity] = []
    for family in (PREPOST, SECURED, JSR250):
        enabled = family in switches or (family == JSR250 and kind == "jaxrs" and JAXRS_JSR250 in switches)
        if not enabled:
            continue
        pick = next((m for m in method_level if m.family == family), None) or next(
            (m for m in class_level if m.family == family), None
        )
        if pick is not None:
            picks.append(pick)
    for decision in (REQUIRED, UNKNOWN, ANONYMOUS):
        for pick in picks:
            if pick.decision == decision:
                return pick
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
        security = RepoSecurity()
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

        _read_servlet_paths(root, security)
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

    def _extract_security_rules(self, content: str, relative: str, security: RepoSecurity) -> None:
        """Spring Security authorization rules and switches in ``content`` (#3).

        Test configurations (`src/test/...`) never guard a deployed route.
        """
        if _is_test_path(relative):
            return
        if JAKARTA_IMPORT_RE.search(content) and JAKARTA_IMPORT_RE.search(mask_comments(content)):
            security.jakarta_files.add(relative)
        if APPLICATION_PATH_RE.search(content) and _application_path_not_root(content):
            security.jersey_path_files.add(relative)
        if SERVLET_PREFIX_CALL_RE.search(content) and _code_mounts_mvc_below_root(content):
            security.mvc_path_files.add(relative)
        if not security.trailing_slash_on and TRAILING_SLASH_ON_RE.search(content):
            security.trailing_slash_on = True
        switches = _method_security_switches(content)
        if switches:
            security.switches[relative] = switches
        gated = SECURITY_GATE_RE.search(content) is not None
        declares_constants = ("final" in content and "String" in content) or "const val" in content
        if not gated and not declares_constants:
            return
        masked = mask_comments(content)
        if declares_constants:
            security.constants.collect(masked, kotlin=relative.endswith((".kt", ".kts")))
        if gated:
            security.pending[relative] = masked

    def _apply_route_auth(
        self,
        root: Path,
        result: ScanResult,
        route_meta: dict[tuple[str, str, str], RouteMeta],
        security: RepoSecurity,
    ) -> None:
        """Set `Route.auth` from filter-chain rules and method security.

        A chain applies to routes in its own build module (nearest `pom.xml` /
        `build.gradle`); a module with routes but no chain of its own uses the
        chains of route-less modules (a shared security library). The same goes
        for `@EnableMethodSecurity`-style switches: an annotation whose family
        isn't switched on is ignored. The filter chain runs first, so method
        security can turn a chain's `anonymous` into `required` but never opens
        a route the chain protects. Several handlers on one route key (`params=`
        variants) count only as much as the least restrictive of them.

        Applying rules costs routes x chains x rules x entries, so it shares one
        `Budget`; once that runs out the remaining routes keep the chain's answer
        unknown.
        """
        for relative, masked in security.pending.items():
            parsed = parse_security(masked, relative, security.constants)
            if parsed.chains or parsed.ignored:
                security.files[relative] = parsed
        security.pending.clear()
        module_cache: dict[str, str] = {}
        chains_by_module: dict[str, list[SecurityChain]] = {}
        ignored_by_module: dict[str, list[Rule]] = {}
        for relative, parsed in security.files.items():
            module = _module_of(root, relative, module_cache)
            chains_by_module.setdefault(module, []).extend(parsed.chains)
            ignored_by_module.setdefault(module, []).extend(parsed.ignored)
        switches_by_module: dict[str, set[str]] = {}
        for relative, switches in security.switches.items():
            switches_by_module.setdefault(_module_of(root, relative, module_cache), set()).update(switches)
        jakarta_modules = {_module_of(root, relative, module_cache) for relative in security.jakarta_files}
        mvc_path_modules = {_module_of(root, relative, module_cache) for relative in security.mvc_path_files}
        jersey_path_modules = {_module_of(root, relative, module_cache) for relative in security.jersey_path_files}
        route_modules = {_module_of(root, r.file, module_cache) for r in result.routes}
        shared = [m for m in chains_by_module if m not in route_modules]
        shared_switches: set[str] = set()
        for module, switches in switches_by_module.items():
            if module not in route_modules:
                shared_switches |= switches
        spring6_cache: dict[str, bool] = {}
        budget = Budget()

        for route in result.routes:
            meta = route_meta.get((route.path, route.method, route.file))
            if meta is None:
                continue
            module = _module_of(root, route.file, module_cache)
            chain_result: Resolution | None = None
            if meta.kind in FILTER_CHAIN_KINDS and chains_by_module and not budget.exhausted:
                modules = [module] if module in chains_by_module else shared
                chains = [c for m in modules for c in chains_by_module[m]]
                ignored = [r for m in modules for r in ignored_by_module.get(m, [])]
                route_dir = route.file.rsplit("/", 1)[0] if "/" in route.file else ""
                # Spring 6 / Boot 3 no longer routes `/x/` to `/x`; JAX-RS runtimes do.
                trailing = (
                    meta.kind == "jaxrs"
                    or security.trailing_slash_on
                    or not _is_spring6_module(root, module, module in jakarta_modules, spring6_cache)
                )
                # Under a servlet path the matchers see a different path than the route.
                mounted_elsewhere = module in (jersey_path_modules if meta.kind == "jaxrs" else mvc_path_modules)
                if not mounted_elsewhere:
                    try:
                        chain_result = resolve_route(
                            chains, ignored, route.path, route.method, route_dir,
                            trailing_slash_reaches_handler=trailing, budget=budget,
                        )
                    except BudgetExceeded:
                        chain_result = None
            switches = switches_by_module.get(module, set()) | shared_switches
            method_security: MethodSecurity | None = None
            if meta.kind in FILTER_CHAIN_KINDS and meta.method_security:
                for method_level, class_level in meta.method_security:
                    for annotation in (*method_level, *class_level):
                        annotation.resolve(security.constants)
                effective = [_effective_method_security(levels, switches, meta.kind) for levels in meta.method_security]
                # The least restrictive handler decides.
                method_security = min(effective, key=lambda m: _DECISION_RANK[m.decision if m else None])
            method_decision = method_security.decision if method_security is not None else None
            if chain_result is not None and chain_result.decision == REQUIRED:
                route.auth = "required"
                extra = [method_security.guard] if method_security is not None and method_decision == REQUIRED else []
                route.guards = [*chain_result.guards, *extra]
                route.guard_evidence = chain_result.evidence
            elif method_security is not None and method_decision == REQUIRED:
                route.auth = "required"
                route.guards = [method_security.guard]
                route.guard_evidence = method_security.evidence
            elif chain_result is not None and chain_result.decision == ANONYMOUS and method_decision in (None, ANONYMOUS):
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
            # Method-level annotations, then the class's (each family looks at both).
            levels = (
                _method_security(block, relative, content),
                _method_security(class_blocks.get(scope.keyword_at), relative, content) if scope is not None else [],
            )
            for annotation, method, paths, kind in members:
                line = line_of(content, annotation.start)
                route_meta = RouteMeta(kind, [levels])
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
            # Another handler on the same path+method (`params=` / `headers=`
            # variants): keep its method security too, so the least restrictive wins.
            if meta is not None:
                route_meta[key].method_security.extend(meta.method_security)
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


def _declared_boot_major(text: str) -> int | None:
    for match in BOOT_VERSION_RE.finditer(text):
        version = next((g for g in match.groups() if g), None)
        if version is not None:
            return int(version)
    return None


def _is_spring6_module(root: Path, module: str, imports_jakarta: bool, cache: dict[str, bool]) -> bool:
    """True when the module runs Spring Boot 3+ (Spring 6).

    The nearest build file that declares a Boot version decides (a module's own
    Boot 2 wins over the root's Boot 3). Only when none does, a main-source
    `import jakarta.servlet...` in the module stands in for it.
    """
    if module in cache:
        return cache[module]
    major: int | None = None
    directory = module
    for _ in range(64):
        base = root / directory if directory else root
        for name in MODULE_BUILD_FILES:
            text = read_source(base / name, root=root) if (base / name).is_file() else None
            if text is not None:
                major = _declared_boot_major(text)
                if major is not None:
                    break
        if major is not None or not directory:
            break
        directory = directory.rsplit("/", 1)[0] if "/" in directory else ""
    found = major >= 3 if major is not None else imports_jakarta
    cache[module] = found
    return found


def _application_path_not_root(content: str) -> bool:
    """A JAX-RS `@ApplicationPath` that isn't `/` (or isn't a literal)."""
    masked = mask_comments(content)
    for annotation in find_annotations(masked, frozenset({"ApplicationPath"})):
        paths = annotation_paths(annotation, ("value",))
        if paths is None or any(p not in _ROOT_PATHS for p in paths):
            return True
    return False


def _code_mounts_mvc_below_root(content: str) -> bool:
    """`addPathPrefix(..)` or a DispatcherServlet registration on a non-root (or
    unreadable) path in Java/Kotlin code. A prefix applies to the controllers its
    predicate selects; we don't read predicates, so the whole module counts."""
    masked = mask_comments(content)
    for count, m in enumerate(SERVLET_PREFIX_CALL_RE.finditer(masked)):
        if count >= 64:
            return True  # too many to read: assume the worst
        close = bracket_end(masked, m.end() - 1, 5_000)
        if close is None:
            return True
        parts = split_top_level(masked[m.end() : close - 1])
        bean = m.group(1)
        if bean is None:  # addPathPrefix(prefix, predicate)
            mappings = parts[:1]
        elif bean == "ServletRegistrationBean" and not (parts and "ispatcher" in parts[0]):
            continue  # some other servlet (an H2 console, ...): MVC routes don't move
        else:
            mappings = parts[1:]
        if not mappings:
            if bean is None:
                return True
            continue  # a registration without mappings keeps the default "/"
        for mapping in mappings:
            values = string_values(mapping)
            if values is None or any(v not in _ROOT_PATHS for v in values):
                return True
    return False


def _read_servlet_paths(root: Path, security: RepoSecurity) -> None:
    """`spring.mvc.servlet.path` / `spring.jersey.application-path` below `/`
    (or an unreadable value such as `${PATH}`) in application properties or YAML."""
    for path in iter_repo_files(root, suffixes=CONFIG_SUFFIXES, skip_dirs=SKIP_DIRS):
        name = path.name.lower()
        if not (name.startswith("application") or name.startswith("bootstrap")):
            continue
        relative = rel(path, root)
        if _is_test_path(relative):
            continue
        text = read_source(path, root=root)
        if text is None:
            continue
        found = [(m.group(1), m.group(2)) for m in SERVLET_PATH_PROPERTY_RE.finditer(text)]
        if path.suffix.lower() in (".yml", ".yaml"):
            found += _yaml_servlet_paths(text)
        for key, value in found:
            if value not in _ROOT_PATHS:
                (security.mvc_path_files if key.startswith("mvc") else security.jersey_path_files).add(relative)


def _yaml_servlet_paths(text: str) -> list[tuple[str, str]]:
    """`(kind, value)` for `spring.mvc.servlet.path` / `spring.jersey.application-path`
    in a YAML file, following block-mapping indentation (`spring:` / `  mvc:` /
    `    servlet:` / `      path: /app`) and dotted keys (`spring.mvc.servlet.path: /app`)."""
    found: list[tuple[str, str]] = []
    stack: list[tuple[int, str]] = []
    for count, line in enumerate(text.splitlines()):
        if count >= MAX_YAML_LINES:
            break
        if line.startswith("---"):
            stack = []
            continue
        m = YAML_LINE_RE.fullmatch(line)
        if m is None:
            continue
        indent = len(m.group(1))
        while stack and stack[-1][0] >= indent:
            stack.pop()
        key = ".".join([k for _, k in stack] + [m.group(2)])
        if m.group(3) is None or m.group(3) == "":
            stack.append((indent, m.group(2)))
        kind = SERVLET_PATH_KEYS.get(key)
        if kind is not None:
            found.append((kind, m.group(3) or ""))
    return found


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
