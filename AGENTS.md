# AGENTS.md

## Project
This repository contains an AttackMap analyzer.

AttackMap analyzers live under:
- `github.com/mlaify`

This repo should implement one analyzer cleanly against the AttackMap core contract.

## Analyzer responsibilities
This analyzer should:
- detect whether it applies to a target repository
- emit structured signals
- remain heuristic but explainable

## Scope
Java/Kotlin Spring Boot ecosystem coverage:

- **Web frameworks**: Spring MVC / Spring Boot (annotation routing with class-level `@RequestMapping` prefix joining), JAX-RS / Jersey / Quarkus, Ktor, Javalin, Micronaut
- **Databases**: Spring Data JPA / MongoDB / Redis / Cassandra, JDBC (driver-aware), Hibernate, jOOQ, AWS SDK (S3 + DynamoDB)
- **Auth**: Spring Security (`@PreAuthorize`, `@Secured`, `SecurityFilterChain`, `@EnableWebSecurity`), jjwt / nimbus-jose-jwt, BCrypt / Argon2 / SCrypt password encoders, OAuth2
- **HTTP clients**: RestTemplate, WebClient, java.net.http.HttpClient, OkHttp, Apache HttpClient
- **Secrets**: `System.getenv`, `@Value("${...}")`, `Environment.getProperty`
- **Service hints**: `<artifactId>` from `pom.xml`, `rootProject.name` from Gradle settings, `spring.application.name` from properties/yml

## Out of scope (for now)
- `@PostMapping` (and friends) with no value argument (`@PostMapping public Object create()`) — pattern requires a string arg.
- chained URL construction in HTTP clients (e.g. `RestTemplate.getForObject(baseUrl + "/orders", ...)`) — only literal-URL calls are picked up.
- Spring AOP / aspect-based authorization checks.
- WebSocket routing (`@MessageMapping`, `@SubscribeMapping`).

## Confidence policy
- Spring Security configuration (`SecurityFilterChain`, `@PreAuthorize`) → 0.9 (very strong signal)
- Hash-based password encoders (BCrypt, Argon2, SCrypt) → 0.9
- Canonical JWT/OAuth library imports → 0.85
- Keyword-only matches (`Authorization`, `Bearer`, `api_key`) → 0.6
- Secret extractions (env vars, `@Value`) → 0.85

## Class-prefix tracking
Class-level `@RequestMapping("/api/users")` is detected via a regex that requires a `class Foo` declaration to follow within the lookahead window. The list of (offset, prefix) pairs is built once per file; for any method-level mapping at offset N, the *active* prefix is the last class-level prefix whose offset is < N. This handles multiple classes per file correctly.

## Testing
Tests write realistic Java/Kotlin snippets to `tmp_path` and assert on the resulting `ScanResult`. Each new framework or extractor needs both:
- A positive test (signal fires on representative code).
- A negative test (signal does **not** fire on a look-alike — e.g., `@RequestMapping` on a class is a prefix, not a route).
