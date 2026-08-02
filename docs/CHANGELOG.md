# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.0] - 2026-08-02

### Added

- `memory-invariants-guardian.sh` — the first **PostToolUse** guardian: fires
  after Edit/Write on memory index files (`MEMORY.md`, `INDEX.md`) and
  surfaces violations to Claude for self-correction.
- `scripts/check_memory_invariants.py` — generic validator: dead relative
  markdown links, dead `[[wikilinks]]`, and opt-in stale-count checks via
  `<!-- invariant-count: <glob> -->` annotations.
- `tests/test-memory-guardian.sh` — 10 test cases covering validator checks
  and the hook's fail-closed stdin contract; wired into CI.

### Changed

- `install.sh` now installs the validator to `.claude/scripts/` and registers
  the PostToolUse hook block (idempotent re-runs preserved).
- README documents the new guardian class.

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

[Unreleased]: https://github.com/farjad-hasan/claude-safety-hooks/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/farjad-hasan/claude-safety-hooks/releases/tag/v0.3.0
[0.2.0]: https://github.com/farjad-hasan/claude-safety-hooks/releases/tag/v0.2.0
