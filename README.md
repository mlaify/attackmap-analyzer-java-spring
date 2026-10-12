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
- **Spring Security rules → route auth**: the matchers of `authorizeHttpRequests` / `authorizeRequests` / `authorizeExchange` (lambda, pre-lambda `.and()` chain and Kotlin `authorize(...)` DSL; `requestMatchers` / `antMatchers` / `mvcMatchers` / `pathMatchers` with an optional `HttpMethod`, `anyRequest()` / `anyExchange()`, `web.ignoring()`) are applied to Spring, JAX-RS and functional routes in first-match order with Ant/PathPattern matching (`/**`, `/*`, `?`, `{var}`, `{*var}`). `permitAll()` / `anonymous()` give `auth = "anonymous"`; `authenticated()`, `hasRole(..)`, `hasAuthority(..)`, `denyAll()` and readable `access(..)` give `"required"` with the rule as the guard. A matcher that can't be read (a constant, `regexMatchers`, a loop over configured URLs) before the deciding rule leaves the route `"unknown"` unless it agrees. Several chains must agree unless a `securityMatcher` or the config's package picks one; a chain applies only to routes in its own Maven/Gradle module (or, for a module without its own chain, a route-less shared security module); configs under `test/` directories are ignored. The filter chain runs first, so method security can turn a `permitAll()` route into `"required"` but never opens a route the chain protects. `csrf().disable()` is reported by AttackMap core's web-hardening pass, not by this plugin.
- **When a route is never `required`** (the dangerous direction, since core then skips it):
  - a multi-segment route wildcard (`/files/**`, `{*rest}`) is only fully covered by a pattern `**`;
  - a pattern without a leading `/` is unreadable (Ant never matches it), and `/admin/` doesn't cover `/admin`;
  - **trailing slash**: Spring MVC 5 / Boot 2 routes `POST /admin/` to `/admin`, and an exact Ant pattern (`antMatchers`, `requestMatchers`, the Kotlin DSL, `antMatcher(..)`) doesn't match it. A `required` route must stay `required` for that form too, or it becomes `unknown`. This is skipped only when the module is on Spring Boot 3+ (build file) or imports `jakarta.servlet`, and `setUseTrailingSlashMatch(true)` isn't set. `mvcMatchers`, `mvc.pattern(..)` and WebFlux `pathMatchers` cover the trailing slash. JAX-RS routes always get the check;
  - **HEAD**: a `GET` route must also be `required` for `HEAD`, because Spring MVC runs the GET handler for HEAD and a `HttpMethod.GET` rule doesn't cover it;
  - the guiding rule: when an input the decision depends on can't be read with confidence, the answer is `unknown`;
  - `hasRole` / `hasAnyRole` / `hasAuthority` need string-literal arguments. Same-repo string constants resolve (#11): `static final String NAME = "...";` and Kotlin `const val`, referenced as `Class.NAME` (or fully qualified), also inside `+` concatenations such as `"hasAuthority(\"" + AuthoritiesConstants.ADMIN + "\")"`. Every member declaration of every class, interface (fields implicitly static final), enum, record and Kotlin object or companion object is recorded. A key resolves only when all its declarations in the repo are String constants with the same plain-literal value. Any other declaration poisons it: non-final or non-String, no literal initializer, a text block or raw string, an enum constant, a `val`/`var`, or a same-named class elsewhere declaring it differently. Hitting a size cap makes every lookup fail. Unqualified names and constants declared only under `test/` stay unresolved. All of these give `unknown`. An `ANONYMOUS` authority gives `anonymous`. SpEL is read only as plain terms (`hasRole('A')`, `isAuthenticated()`, `permitAll`) joined by `and` / `or`, and `or` gives `required` only if every branch does. `==`, `eq`, `!`, `not`, ternaries, `#param`, `@bean` and grouping give `unknown`. The same applies to `@PreAuthorize` (one string literal, not a concatenation), `@Secured` and `@RolesAllowed`;
  - a `securityMatchers(m -> ...)` lambda that names a method is an unreadable scope. Each request form (plain, trailing slash, HEAD) re-selects its chain by `securityMatcher`;
  - the nearest build file that declares a Spring Boot version decides Boot 2 vs 3, so a module's own Boot 2 wins over the root's Boot 3. Without one, a main-source `import jakarta.servlet...` line counts as Spring 6. Spring 6.2's `UrlHandlerFilter` re-enables the trailing-slash check, like `setUseTrailingSlashMatch(true)`;
  - `spring.mvc.servlet.path` below `/`, in application properties or YAML (nested keys followed by indentation) or as an unreadable `${..}` value, makes the module's Spring and functional routes `unknown`: Ant matchers then see the servlet path in front of the route. The same applies in code: `addPathPrefix(..)` with a non-root or unreadable prefix (predicates aren't read, so it covers the whole module), or the DispatcherServlet registered on a sub-path (`DispatcherServletRegistrationBean`, or a `ServletRegistrationBean` of the dispatcher servlet; other servlets such as an H2 console don't count). A non-root Jersey `@ApplicationPath` or `spring.jersey.application-path` does the same for JAX-RS routes. `server.servlet.context-path` is harmless, because matchers and routes both exclude it;
  - method security counts only when switched on in the route's module or a shared route-less module. `@PreAuthorize` needs `@EnableMethodSecurity` / `@EnableReactiveMethodSecurity` / `@EnableGlobalMethodSecurity(prePostEnabled = true)`. `@Secured` needs `securedEnabled = true`. `@RolesAllowed` / `@DenyAll` / `@PermitAll` need `jsr250Enabled = true`, or, for JAX-RS, Jersey's `RolesAllowedDynamicFeature` / Quarkus security. `@PostAuthorize` runs after the handler and is never a guard, and `@Secured("ROLE_ANONYMOUS")` / `@PreAuthorize("isAnonymous() or ...")` aren't guards either;
  - several handlers on one route key (`params=` / `headers=` variants) count as the least restrictive of them.
- **Cost**: per-file parsing is linear and capped (rules, chains, calls, pattern size). Applying rules to routes costs routes × chains × rules × entries, so it shares a per-repo budget of 5,000,000 cost units. Each matcher entry costs 20, each path match the size of its segment table, and each glob comparison pattern × text characters. A pattern segment with more than 8 wildcards is unreadable. Routes left when it runs out keep their chain answer `unknown`. Not covered: Spring < 5.3 suffix-pattern matching (`/admin.json`) and `@Order` between chains.
- **Kotlin Ktor**: `routing { get("/x") { ... } }` extraction only fires when the file contains an `io.ktor` import or `ktor.server.routing` reference, to avoid mis-attributing `get(...)` calls on Maps and other types.
- **Javalin** and **Micronaut** are similarly framework-gated.
- **OkHttp / java.net.http.HttpClient**: literal-URL builder patterns (`new Request.Builder().url("https://...")`, `HttpRequest.newBuilder(URI.create("https://..."))`) are picked up. Calls where the URL is built by string concatenation are not.

## License

MIT
