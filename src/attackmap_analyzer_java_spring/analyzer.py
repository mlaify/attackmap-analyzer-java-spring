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

Class-level @RequestMapping prefixes are joined with method-level
@GetMapping / @PostMapping etc. to produce the full route path. Multiple
classes per file are tracked correctly (each class's prefix only applies
to methods that follow it).
"""

from __future__ import annotations

import re
from pathlib import Path

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
SKIP_DIRS = {
    "target",       # Maven build output
    "build",        # Gradle build output
    ".gradle",
    ".mvn",
    ".idea",
    ".git",
    "out",
    "bin",
    "node_modules",
}
_SNIPPET_MAX_CHARS = 160


# ---------- Patterns ----------

# Spring MVC method-level mappings: @GetMapping("/x"), @PostMapping(value = "/x"), etc.
SPRING_METHOD_MAPPING_PATTERN = re.compile(
    r'@(Get|Post|Put|Delete|Patch)Mapping\s*\(\s*(?:value\s*=\s*)?"([^"]+)"',
)
# @RequestMapping("/x", method = RequestMethod.GET)  — method-level, with explicit method.
SPRING_REQUEST_MAPPING_PATTERN = re.compile(
    r'@RequestMapping\s*\(\s*'
    r'(?:value\s*=\s*)?"([^"]+)"'
    r'(?P<rest>[^)]*)\)',
    re.DOTALL,
)
# @RequestMapping("/x") — class-level form; we recognize class-level by lookahead for `class `.
SPRING_CLASS_REQUEST_MAPPING_PATTERN = re.compile(
    r'@RequestMapping\s*\(\s*(?:value\s*=\s*)?"([^"]+)"[^)]*\)\s*'
    r'(?:@\w+(?:\([^)]*\))?\s*)*'
    r'(?:public\s+|abstract\s+|final\s+|@\w+\s+)*class\s+\w+',
    re.DOTALL,
)
# JAX-RS / Jersey / Quarkus
JAXRS_PATH_PATTERN = re.compile(r'@Path\s*\(\s*"([^"]+)"\s*\)')
JAXRS_METHOD_PATTERN = re.compile(r'@(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\b')

# Ktor (Kotlin): get("/x") { ... } inside `routing { ... }`.
KTOR_ROUTE_PATTERN = re.compile(
    r'\b(get|post|put|delete|patch|head|options)\s*\(\s*"([^"]+)"\s*\)\s*\{',
)

# Javalin: app.get("/x", ...), app.post("/x", ...)
JAVALIN_ROUTE_PATTERN = re.compile(
    r'\bapp\.(get|post|put|delete|patch|head|options)\s*\(\s*"([^"]+)"',
)

# Micronaut: @Controller("/x") + @Get / @Post / ...
MICRONAUT_CLASS_PATTERN = re.compile(r'@Controller\s*\(\s*(?:value\s*=\s*)?"([^"]+)"')
MICRONAUT_METHOD_PATTERN = re.compile(
    r'@(Get|Post|Put|Delete|Patch)\s*\(\s*(?:value\s*=\s*)?"([^"]+)"',
)


def _spring_method_from_request_mapping(rest: str) -> list[str]:
    methods: list[str] = []
    for match in re.finditer(r'RequestMethod\.(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)', rest):
        methods.append(match.group(1).upper())
    return methods or ["ANY"]


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


def _line_of(content: str, offset: int) -> int:
    if offset <= 0:
        return 1
    return content.count("\n", 0, offset) + 1


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


def _class_prefixes_in_file(content: str) -> list[tuple[int, str]]:
    """Return [(start_offset, prefix), ...] for every class-level @RequestMapping in the file.

    A class-level mapping is one whose annotation precedes a `class Foo` declaration
    (with at most other annotations/modifiers in between). Order matters — when a
    method-level mapping is at offset N, we use the *latest* class prefix at offset < N.
    """
    prefixes: list[tuple[int, str]] = []
    for match in SPRING_CLASS_REQUEST_MAPPING_PATTERN.finditer(content):
        prefixes.append((match.start(), match.group(1)))
    return prefixes


def _active_class_prefix(prefixes: list[tuple[int, str]], offset: int) -> str:
    """Find the most recent class prefix preceding the given offset."""
    active = ""
    for start, prefix in prefixes:
        if start < offset:
            active = prefix
        else:
            break
    return active


def _module_name_from_pom(pom_path: Path) -> str | None:
    if not pom_path.exists():
        return None
    try:
        text = pom_path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return None
    artifact = re.search(r"<artifactId>([^<]+)</artifactId>", text)
    if artifact:
        return artifact.group(1).strip()
    return None


def _module_name_from_gradle(root: Path) -> str | None:
    for candidate in ("settings.gradle", "settings.gradle.kts"):
        path = root / candidate
        if not path.exists():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
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
        path = root / candidate
        if not path.exists():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        match = re.search(r'^\s*spring\.application\.name\s*[:=]\s*([^\s#]+)', text, re.MULTILINE)
        if match:
            return match.group(1).strip().strip("'\"")
    return None


class JavaSpringAnalyzer:
    metadata = AnalyzerMetadata(
        name="java-spring",
        display_name="Java/Kotlin Spring Boot Analyzer",
        version="0.1.0",
        description="Java and Kotlin analyzer with Spring Boot, JAX-RS, Ktor, and Spring Security awareness.",
        scope="Maven, Gradle, and Kotlin Spring Boot projects. Detects Spring MVC, JAX-RS, Ktor, Javalin, and Micronaut routing.",
        targets=["java", "kotlin", "spring", "spring-boot"],
        languages=["java", "kotlin"],
        priority=20,
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
        for path in root.rglob("*"):
            if any(part in SKIP_DIRS for part in path.parts):
                continue
            if path.is_file() and path.suffix in CODE_SUFFIXES:
                return True
            if path.is_file() and path.name in {"pom.xml", "build.gradle", "build.gradle.kts"}:
                return True
        return False

    def analyze(self, repo_path: str | Path) -> ScanResult:
        root = Path(repo_path).resolve()
        result = ScanResult(root=str(root))
        if not root.exists() or not root.is_dir():
            return result

        # Service-name hints from build/application metadata
        artifact = _module_name_from_pom(root / "pom.xml")
        gradle_name = _module_name_from_gradle(root)
        spring_app = _spring_app_name_from_properties(root)
        if artifact:
            self._append_unique_service(result, f"artifact:{artifact}", "pom.xml")
        if gradle_name:
            self._append_unique_service(result, f"gradle_root:{gradle_name}", "settings.gradle")
        if spring_app:
            self._append_unique_service(result, f"spring_app:{spring_app}", "application.properties")

        for file_path in root.rglob("*"):
            if not file_path.is_file():
                continue
            if any(part in SKIP_DIRS for part in file_path.parts):
                continue
            if file_path.suffix not in CODE_SUFFIXES:
                continue

            result.files_scanned += 1
            language = "kotlin" if file_path.suffix in {".kt", ".kts"} else "java"
            if language not in result.languages:
                result.languages.append(language)

            try:
                content = file_path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue

            relative = str(file_path.relative_to(root))
            self._extract_routes(content, relative, result)
            self._extract_databases(content, relative, result)
            self._extract_auth(content, relative, result)
            self._extract_secrets(content, relative, result)
            self._extract_external_calls(content, relative, result)
            self._extract_frameworks(content, relative, result)
            self._extract_entrypoints(content, relative, result)
            self._infer_service_role(content, relative, result)

        result.languages.sort()
        return result

    # ---------- Extractors ----------

    def _extract_routes(self, content: str, relative: str, result: ScanResult) -> None:
        # Spring: class-level @RequestMapping prefix + method-level @GetMapping etc.
        class_prefixes = _class_prefixes_in_file(content)

        for match in SPRING_METHOD_MAPPING_PATTERN.finditer(content):
            verb, suffix = match.group(1), match.group(2)
            method = verb.upper()
            prefix = _active_class_prefix(class_prefixes, match.start())
            full_path = _join_paths(prefix, suffix)
            self._append_unique_route(result, full_path, method, relative, _line_of(content, match.start()))

        # Method-level @RequestMapping with explicit method = RequestMethod.X
        for match in SPRING_REQUEST_MAPPING_PATTERN.finditer(content):
            # Skip class-level mappings — they're handled as prefixes, not routes themselves.
            if (match.start(), match.group(1)) in [(p[0], p[1]) for p in class_prefixes]:
                continue
            suffix = match.group(1)
            rest = match.group("rest") or ""
            methods = _spring_method_from_request_mapping(rest)
            prefix = _active_class_prefix(class_prefixes, match.start())
            full_path = _join_paths(prefix, suffix)
            line = _line_of(content, match.start())
            for method in methods:
                self._append_unique_route(result, full_path, method, relative, line)

        # JAX-RS: class-level @Path("/x") + method-level @Path("/y") + @GET/@POST/...
        # In typical JAX-RS code, the verb annotation can come *before* or *after* the
        # method-level @Path (`@GET\n@Path("/{id}")` is just as common as the inverse).
        # We pair each verb annotation with the @Path it sits closest to within a window.
        if "javax.ws.rs" in content or "jakarta.ws.rs" in content:
            path_matches = list(JAXRS_PATH_PATTERN.finditer(content))
            verb_matches = list(JAXRS_METHOD_PATTERN.finditer(content))
            class_path = path_matches[0].group(1) if path_matches else ""
            class_path_offset = path_matches[0].start() if path_matches else -1
            for verb_match in verb_matches:
                # Find the @Path annotation closest to this verb (excluding the class-level
                # one) within a 400-char proximity window — that's "the same method block".
                best_path: re.Match | None = None
                best_distance = 401
                for path_match in path_matches:
                    if path_match.start() == class_path_offset:
                        continue
                    distance = abs(path_match.start() - verb_match.start())
                    if distance < best_distance:
                        best_distance = distance
                        best_path = path_match
                method = verb_match.group(1)
                if best_path is not None:
                    method_path = best_path.group(1)
                    line = _line_of(content, best_path.start())
                else:
                    # No method-level @Path — the verb applies to the class-level path.
                    method_path = ""
                    line = _line_of(content, verb_match.start())
                full_path = _join_paths(class_path, method_path)
                self._append_unique_route(result, full_path, method, relative, line)

        # Ktor: routing { get("/x") { ... } }
        if "io.ktor" in content or "ktor.server.routing" in content:
            for match in KTOR_ROUTE_PATTERN.finditer(content):
                method, path = match.group(1).upper(), match.group(2)
                self._append_unique_route(result, path, method, relative, _line_of(content, match.start()))

        # Javalin: app.get("/x", ...)
        if "io.javalin" in content or "Javalin.create" in content:
            for match in JAVALIN_ROUTE_PATTERN.finditer(content):
                method, path = match.group(1).upper(), match.group(2)
                self._append_unique_route(result, path, method, relative, _line_of(content, match.start()))

        # Micronaut: @Controller("/x") + method @Get/@Post
        if "io.micronaut" in content:
            class_match = MICRONAUT_CLASS_PATTERN.search(content)
            class_path = class_match.group(1) if class_match else ""
            for match in MICRONAUT_METHOD_PATTERN.finditer(content):
                method, suffix = match.group(1).upper(), match.group(2)
                full_path = _join_paths(class_path, suffix)
                self._append_unique_route(result, full_path, method, relative, _line_of(content, match.start()))

    def _extract_databases(self, content: str, relative: str, result: ScanResult) -> None:
        for pattern, kind in DB_PATTERNS:
            match = pattern.search(content)
            if match is None:
                continue
            self._append_unique_database(
                result, kind, relative,
                _line_of(content, match.start()),
                _line_snippet(content, match.start()),
            )

    def _extract_auth(self, content: str, relative: str, result: ScanResult) -> None:
        for pattern, hint, confidence in AUTH_PATTERNS:
            match = pattern.search(content)
            if match is None:
                continue
            self._append_unique_auth(
                result, hint, relative,
                _line_of(content, match.start()),
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
                    _line_of(content, match.start()),
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
                    _line_of(content, match.start()),
                    _line_snippet(content, match.start()),
                )

    def _extract_frameworks(self, content: str, relative: str, result: ScanResult) -> None:
        for pattern, name in FRAMEWORK_PATTERNS:
            match = pattern.search(content)
            if match is None:
                continue
            self._append_unique_framework(
                result, name, relative,
                _line_of(content, match.start()),
                _line_snippet(content, match.start()),
            )

    def _extract_entrypoints(self, content: str, relative: str, result: ScanResult) -> None:
        for pattern, hint in ENTRYPOINT_PATTERNS:
            match = pattern.search(content)
            if match is None:
                continue
            self._append_unique_entrypoint(
                result, hint, relative,
                _line_of(content, match.start()),
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
    def _append_unique_route(result: ScanResult, path: str, method: str, file: str, line: int | None) -> None:
        key = (path, method, file)
        if any((item.path, item.method, item.file) == key for item in result.routes):
            return
        result.routes.append(Route(path=path, method=method, file=file, line=line))

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


__all__ = ["JavaSpringAnalyzer"]
