# attackmap-analyzer-java-spring

> [!IMPORTANT]
> **Active development, slow pace.** AttackMap is under active development, but
> progress may be slow until more contributors or co-maintainers join. Help is
> very welcome with the core engine, an analyzer, the macOS app, or the docs —
> see [CONTRIBUTING.md](CONTRIBUTING.md) or open an issue on
> [mlaify/AttackMap](https://github.com/mlaify/AttackMap/issues) to say hello.
> Security reports are still welcome at [security@mlaify.io](mailto:security@mlaify.io).

Java and Kotlin Spring Boot ecosystem analyzer for [AttackMap](https://github.com/mlaify/AttackMap).

This analyzer extracts structured signals from Maven and Gradle projects:

- **Web frameworks** — Spring MVC / Spring Boot (annotation routing with class-level `@RequestMapping` prefix joining), Spring WebFlux / WebMvc.fn functional endpoints (`RouterFunctions`, the `route()` builder, Kotlin `router {}` / `coRouter {}`), JAX-RS / Jersey / Quarkus (`@Path` + `@GET`/`@POST`), Ktor (Kotlin DSL), Javalin, Micronaut
- **Route auth** — Spring Security `authorizeHttpRequests` / `authorizeRequests` / `authorizeExchange` rules and method security (`@PreAuthorize`, `@Secured`, `@RolesAllowed`) resolved per route into `Route.auth` / `guards` / `guard_evidence`
- **Databases** — Spring Data JPA (`@Entity`, `JpaRepository`), Spring Data MongoDB (`@Document`, `MongoRepository`), Spring Data Redis (`RedisTemplate`), JDBC (`DriverManager.getConnection` with driver-aware kind inference), Hibernate, jOOQ, AWS SDK (S3, DynamoDB)
- **Auth packages** — Spring Security (`@PreAuthorize`, `@Secured`, `SecurityFilterChain`, `@EnableWebSecurity`), jjwt / nimbus-jose-jwt, BCrypt / Argon2 / SCrypt password encoders, OAuth2 (`oauth2Login`, `OAuth2AuthenticationToken`)
- **HTTP clients (external calls)** — RestTemplate, WebClient, java.net.http.HttpClient, OkHttpClient, `@FeignClient`, Apache HttpClient
- **Secrets** — `System.getenv`, `@Value("${...}")`, `Environment.getProperty(...)`
- **Service hints** — `<artifactId>` from `pom.xml`, `rootProject.name` from Gradle settings, `spring.application.name` from `application.properties`/`application.yml`

All emissions populate AttackMap's Signal v2 fields (line numbers, evidence snippets, confidence scores) so downstream insights can cite `path/to/file.java:NN`.

## Install

```bash
pip install git+https://github.com/mlaify/attackmap-analyzer-java-spring.git
```

The analyzer is auto-discovered by AttackMap via the `attackmap.analyzers` entry-point group.

## Usage with AttackMap

```bash
# Auto-discovered when installed:
attackmap analyze /path/to/spring/repo

# Or invoke explicitly:
attackmap analyze /path/to/spring/repo --module java-spring
```

## Detection

`detect()` returns true when any of the following are present, ignoring `target/`, `build/`, `.gradle/`, `.mvn/`, `.idea/`, `.git/`, `out/`, `bin/`, and `node_modules/`:

- `pom.xml`, `build.gradle`, `build.gradle.kts`, `settings.gradle`, or `settings.gradle.kts` at the root
- `.java`, `.kt`, or `.kts` files anywhere in the tree

## Coverage notes

- **Class-level `@RequestMapping` prefix joining**: a class annotated with `@RequestMapping("/api/users")` causes its method-level `@GetMapping("/{id}")` to emit as `/api/users/{id}`. Multiple classes in one file are tracked correctly — the prefix in effect is whichever class declaration most recently preceded the method annotation.
- **`@PostMapping` with no value** (e.g. `@PostMapping public Object create()`) is **not currently extracted** — the regex requires a string argument. Workaround: write `@PostMapping("")` or `@PostMapping("/")`. Roadmap.
- **JAX-RS class + method `@Path` joining**: each class's own `@Path` is the prefix for the methods in its body, and a verb (`@GET`, `@POST`, etc.) pairs only with the `@Path` among the annotations on the same method, so a neighbouring method's path is never borrowed.
- **Functional endpoints**: `GET("/x")`-style predicates and builder calls are read only in files that use `org.springframework.web.reactive.function.server`, `org.springframework.web.servlet.function`, `RouterFunctions` or `RequestPredicates`. `nest(path("/api"), ...)`, `.andNest(...)`, builder `.path("/api", b -> ...)` / `.nest(path(...), b -> ...)` and Kotlin `"/api".nest {}` / `path("/api").nest {}` add their prefix. A path that isn't a string literal (a constant, a Kotlin `$template`), and every route inside a nest whose prefix can't be read, is skipped rather than reported under a wrong path. `GET(handler)` with no path and `route(path("/x").and(method(...)), h)` are not read.
- **Spring Security rules → route auth**: the matchers of `authorizeHttpRequests` / `authorizeRequests` / `authorizeExchange` (lambda, pre-lambda `.and()` chain and Kotlin `authorize(...)` DSL; `requestMatchers` / `antMatchers` / `mvcMatchers` / `pathMatchers` with an optional `HttpMethod`, `anyRequest()` / `anyExchange()`, `web.ignoring()`) are applied to Spring, JAX-RS and functional routes in first-match order with Ant/PathPattern matching (`/**`, `/*`, `?`, `{var}`, `{*var}`). `permitAll()` / `anonymous()` give `auth = "anonymous"`; `authenticated()`, `hasRole(..)`, `hasAuthority(..)`, `denyAll()` and readable `access(..)` give `"required"` with the rule as the guard. A matcher that can't be read (a constant, `regexMatchers`, a loop over configured URLs) before the deciding rule leaves the route `"unknown"` unless it agrees. Several chains must agree unless a `securityMatcher` or the config's package picks one; a chain applies only to routes in its own Maven/Gradle module (or, for a module without its own chain, a route-less shared security module); configs under `test/` directories are ignored. Method security can only narrow access: `@PreAuthorize("hasRole(...)")` makes a `permitAll()` route `"required"`, and `@PermitAll` never opens a route the chain protects. `csrf().disable()` is reported by AttackMap core's web-hardening pass, not by this plugin.
- **Kotlin Ktor**: `routing { get("/x") { ... } }` extraction only fires when the file contains an `io.ktor` import or `ktor.server.routing` reference, to avoid mis-attributing `get(...)` calls on Maps and other types.
- **Javalin** and **Micronaut** are similarly framework-gated.
- **OkHttp / java.net.http.HttpClient**: literal-URL builder patterns (`new Request.Builder().url("https://...")`, `HttpRequest.newBuilder(URI.create("https://..."))`) are picked up. Calls where the URL is built by string concatenation are not.

## License

MIT
