# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [v0.2.0] - 2026-07-30

### Changed
- **Refined** AWS guardian whitelist posture to "read-only by default" matching true blast-radius analysis.
- **Added** explicit Threat Model (`docs/THREAT-MODEL.md`) detailing known failure modes and mitigations.
- **Implemented** CI integrity testing (Shellcheck + fail-closed logic verification).

### Added
- `VERSION` file to track release numbering.
- Automated bash syntax and ShellCheck for all guardian scripts.

## [v0.1.2] - 2025-06-01

### Added
- Initial public release of three guardian hooks (`aws-prod-guardian.sh`, `db-prod-guardian.sh`, `sf-prod-guardian.sh`).
- SHA-256 passkey gate implementation to prevent bypass by agent caching.
- Automatic installer script for `.claude/hooks` directory registration and settings configuration.

[v0.1.2]: https://github.com/farjad-hasan/claude-safety-hooks/releases/tag/v0.1.2
[Unreleased]: https://github.com/farjad-hasan/claude-safety-hooks/compare/v0.1.2...HEAD
