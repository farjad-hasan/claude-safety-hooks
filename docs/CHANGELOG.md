# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-07-31

### Added

- CI integrity checks for every push and pull request.
- Bash syntax validation for all guardian scripts.
- ShellCheck validation for shell scripts.
- Fail-closed regression tests in the GitHub Actions workflow.
- Threat model and known failure-mode documentation in `docs/THREAT-MODEL.md`.
- `VERSION` file for release tracking.

### Changed

- README now exposes integrity, version, testing, and threat-model documentation.
- Hook, installer, and test scripts are marked executable in Git.

[Unreleased]: https://github.com/farjad-hasan/claude-safety-hooks/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/farjad-hasan/claude-safety-hooks/releases/tag/v0.2.0
