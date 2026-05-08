# attackmap-analyzer-java-spring

Java and Kotlin Spring Boot ecosystem analyzer for [AttackMap](https://github.com/mlaify/AttackMap).

This analyzer extracts structured signals from Maven and Gradle projects:

- **Web frameworks** — Spring MVC / Spring Boot (annotation routing with class-level `@RequestMapping` prefix joining), JAX-RS / Jersey / Quarkus (`@Path` + `@GET`/`@POST`), Ktor (Kotlin DSL), Javalin, Micronaut
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
- **JAX-RS class + method `@Path` joining**: the first `@Path` in a JAX-RS file is treated as the class-level prefix and joined to subsequent method-level `@Path` annotations. HTTP verb (`@GET`, `@POST`, etc.) is captured by looking ahead from the `@Path` for the next verb annotation within ~800 chars.
- **Kotlin Ktor**: `routing { get("/x") { ... } }` extraction only fires when the file contains an `io.ktor` import or `ktor.server.routing` reference, to avoid mis-attributing `get(...)` calls on Maps and other types.
- **Javalin** and **Micronaut** are similarly framework-gated.
- **OkHttp / java.net.http.HttpClient**: literal-URL builder patterns (`new Request.Builder().url("https://...")`, `HttpRequest.newBuilder(URI.create("https://..."))`) are picked up. Calls where the URL is built by string concatenation are not.

## License

MIT
