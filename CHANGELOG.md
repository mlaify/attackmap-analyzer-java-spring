# Changelog

All notable changes to `attackmap-analyzer-java-spring` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-10-31

### Changed — packaging

- Released to the mlaify package index (https://pkg.mlaify.io/pypi/simple/). A `v*` tag now builds the wheel and sdist and attaches them to a GitHub release (`.github/workflows/release.yml`); the index picks them up within six hours.
- The `core` and `dev` extras require `attackmap>=0.6.0` from the index instead of AttackMap's git main.

### Fixed — JWT auth hints need verification (#9, AttackMap#325)

- The `jwt` auth hint used to match the `io.jsonwebtoken` / `nimbusds.jwt` package names (so any import), `Jwts.*(` (including `Jwts.builder()`), and `JWT.create(` (signing). It now needs verification:
  - jjwt `parseClaimsJws` / `parseSignedClaims` / `parseSignedContent` / `parseContentJws` (not `parseClaimsJwt`, which is unsigned);
  - auth0 `JWT.require(`;
  - Hutool `JWTUtil.verify(` / `JWTValidator.of(`;
  - Nimbus `new MAC|RSASSA|ECDSA|Ed25519Verifier(`;
  - Spring `NimbusJwtDecoder.with*(` / `JwtDecoders.from*(`, and `oauth2ResourceServer(… jwt …)`, Java or Kotlin DSL.
- Core credits any auth hint near a route as that route's auth.
- Real repos, before → after:
  - eladmin@55fbf70: the hint moved from the import to `parseClaimsJws`.
  - mall@dcaa93b: Hutool's `JWTUtil.verify` is now found; nothing was found before.
  - jhipster-sample-app@6b000b5: `oauth2ResourceServer(oauth2 -> oauth2.jwt(...))` and `NimbusJwtDecoder.withSecretKey` are now found.
  - Routes and surface risk are unchanged. Core's repo-wide `unauth-outbound-integration` gate now sees a `jwt` hint in mall and jhipster, so those findings are gone (265 and 28 locations; tracked in AttackMap#395).

### Added

- Same-repo `static final String` / Kotlin `const val` constants resolve in
  matcher patterns, authority arguments, `access(..)`, `@PreAuthorize` (including
  `+` concatenation of literals and constants), `@Secured` and `@RolesAllowed`
  ([#11](https://github.com/mlaify/attackmap-analyzer-java-spring/issues/11)).
  Unresolved or ambiguous references stay `unknown`.
- Spring WebFlux / WebMvc.fn functional endpoints become routes
  ([#3](https://github.com/mlaify/attackmap-analyzer-java-spring/issues/3)):
  `RouterFunctions.route(GET("/x"), h).andRoute(...)`, `nest(path("/api"), ...)` /
  `.andNest(...)`, the `route().GET("/x", h).path("/api", b -> ...)` builder and
  Kotlin `router {}` / `coRouter {}` with `"/api".nest {}`. Unreadable paths and
  prefixes are skipped, never guessed.
- Spring Security `authorizeHttpRequests` / `authorizeRequests` /
  `authorizeExchange` rules (lambda, pre-lambda and Kotlin DSL forms,
  `web.ignoring()`, `securityMatcher` scopes) are applied to each Spring, JAX-RS
  and functional route in first-match order with Ant-style matching, together
  with method security (`@PreAuthorize`, `@Secured`, `@RolesAllowed`,
  `@DenyAll`, `@PermitAll`). The result is set on `Route.auth` / `guards` /
  `guard_evidence` (mlaify/AttackMap#256), so `requestMatchers("/admin/**").permitAll()`
  now makes those routes explicitly anonymous with the rule as evidence.
  A route is never marked `required` when Spring would let some request to
  it through anonymously. That covers route `**` wildcards, the Boot 2
  trailing-slash form of exact Ant patterns, `HEAD` on `GET` handlers,
  ANONYMOUS authorities and SpEL `or`, method security that isn't switched on,
  `@PostAuthorize`, and `params=` handler variants. Applying rules to routes
  shares a per-repo cost budget (segment and glob work included). Anything
  that can't be read with confidence is `unknown`: non-literal roles, SpEL
  beyond plain `and` / `or` terms, a non-root `spring.mvc.servlet.path` or
  Jersey `@ApplicationPath`, a code-level `addPathPrefix(..)` or
  DispatcherServlet registration on a sub-path, and `UrlHandlerFilter`
  trailing-slash handling.

### Changed

- **License metadata uses an SPDX expression (PEP 639).** `license = "MIT"` and `license-files = ["LICENSE"]` replace the deprecated `license = {text = "MIT"}` table, and the `License ::` classifier (which setuptools ≥ 77 rejects next to an expression) is gone. The build backend floor is now `setuptools>=77` (mlaify/AttackMap#259).
- **Import the analyzer contract from `attackmap.sdk` directly; `contracts.py` is gone.** It only re-exported SDK types (and aliased `AnalyzerProtocol` as `AttackMapAnalyzerProtocol`), and its four copy-pasted variants drifted across the plugins (mlaify/AttackMap#259).
- Walk and read the repo with the shared `attackmap.sdk.fs` helpers
  (`iter_repo_files`, `read_source`, `rel`, `line_of`) instead of a private
  `rglob` + `SKIP_DIRS` walk ([mlaify/AttackMap#253](https://github.com/mlaify/AttackMap/issues/253)).
  Skip dirs are now `DEFAULT_SKIP_DIRS` plus `.gradle`, `.mvn`, `.idea` and `bin` (a superset of the old list; it also skips `dist/`, `vendor/`, `.venv/` and AttackMap output dirs). `pom.xml`, `settings.gradle` and `application.properties/yml` are read with `read_source` too.
- `priority` 20 → 60, into the framework band (50–149), now that core orders
  analyzers by `(priority, name)` across built-ins and plugins
  ([mlaify/AttackMap#221](https://github.com/mlaify/AttackMap/issues/221)).

### Fixed

- `@RequestMapping(method = POST)` with a statically imported `RequestMethod`
  gives a `POST` route instead of `ANY`.
- JAX-RS: a regression test pins that a verb pairs only with its own method's
  `@Path` and each resource class uses its own class `@Path` (#3; the pairing
  itself was scoped to the method's annotation block in #2).

- Spring MVC mappings are read with an annotation-argument parser instead of
  single-string regexes, so these shapes now produce routes with the right
  path ([#2](https://github.com/mlaify/attackmap-analyzer-java-spring/issues/2)):
  bare `@GetMapping` (the class prefix alone), `path = "/x"`, arrays
  (`@PostMapping({"/a", "/b"})`, Kotlin `["/a"]`, `arrayOf("/a")` and vararg
  `@PutMapping("/a", "/b")`), `method = {RequestMethod.GET, ...}`, and a
  class-level `@RequestMapping(path = ...)` prefix. A `@Validated` (or any
  other annotation) between `@RequestMapping` and `class` no longer hides the
  prefix.
- A class prefix applies only inside its own class body; a second class in
  the file without a mapping no longer inherits the first class's prefix.
- Micronaut: bare `@Get`, `value =`, `uri =` and `uris = {...}` are read, and a
  bare `@Controller` mounts at `/`. JAX-RS `@Path(value = ...)` is read and the
  class path comes from the class's own `@Path`.
- Mappings inside comments are ignored, and a mapping whose path is a constant
  (`@GetMapping(Paths.X)`) is skipped rather than reported under the
  class prefix. Annotation-derived paths always start with `/`.
- A repo checked out under a directory named like a skip dir (e.g. `/build/...`,
  `.../out/...`) was silently skipped entirely; skip dirs are now matched only
  inside the repo.
- Symlinked files pointing outside the repo are no longer analyzed.
- An unreadable file no longer raises out of `analyze()`, and cp1252/latin-1
  sources are analyzed instead of dropped. `files_scanned` counts only files
  that were actually read.
- `detect()` stops at the first source or build file and prunes skipped directories instead of walking all of them.

## [0.1.0] - 2026-06-04

### Added

- Initial public release. Java/Kotlin Spring Boot ecosystem analyzer plugin for AttackMap (Spring MVC routing, JAX-RS, Ktor; Spring Data JPA / Mongo / Redis; Spring Security; jjwt; RestTemplate / WebClient / OkHttp).
- Registered under the `attackmap.analyzers` entry-point group so the core
  AttackMap CLI auto-discovers this analyzer once installed.
- Emits Signal-v2 records (`file:line` citation, evidence text, and confidence
  score) for every signal.

[Unreleased]: https://github.com/mlaify/attackmap-analyzer-java-spring/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/mlaify/attackmap-analyzer-java-spring/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/mlaify/attackmap-analyzer-java-spring/releases/tag/v0.1.0
