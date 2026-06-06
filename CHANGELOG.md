# Changelog

All notable changes to `attackmap-analyzer-java-spring` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-06-04

### Added

- Initial public release. Java/Kotlin Spring Boot ecosystem analyzer plugin for AttackMap (Spring MVC routing, JAX-RS, Ktor; Spring Data JPA / Mongo / Redis; Spring Security; jjwt; RestTemplate / WebClient / OkHttp).
- Registered under the `attackmap.analyzers` entry-point group so the core
  AttackMap CLI auto-discovers this analyzer once installed.
- Emits Signal-v2 records (`file:line` citation, evidence text, and confidence
  score) for every signal.

[Unreleased]: https://github.com/mlaify/attackmap-analyzer-java-spring/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/mlaify/attackmap-analyzer-java-spring/releases/tag/v0.1.0
