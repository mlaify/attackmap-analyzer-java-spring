# Changelog

All notable changes to `attackmap-analyzer-java-spring` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- Walk and read the repo with the shared `attackmap.sdk.fs` helpers
  (`iter_repo_files`, `read_source`, `rel`, `line_of`) instead of a private
  `rglob` + `SKIP_DIRS` walk ([mlaify/AttackMap#253](https://github.com/mlaify/AttackMap/issues/253)).
  Skip dirs are now `DEFAULT_SKIP_DIRS` plus `.gradle`, `.mvn`, `.idea` and `bin` (a superset of the old list; it also skips `dist/`, `vendor/`, `.venv/` and AttackMap output dirs). `pom.xml`, `settings.gradle` and `application.properties/yml` are read with `read_source` too.
- `priority` 20 → 60, into the framework band (50–149), now that core orders
  analyzers by `(priority, name)` across built-ins and plugins
  ([mlaify/AttackMap#221](https://github.com/mlaify/AttackMap/issues/221)).

### Fixed

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

[Unreleased]: https://github.com/mlaify/attackmap-analyzer-java-spring/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/mlaify/attackmap-analyzer-java-spring/releases/tag/v0.1.0
