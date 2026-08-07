# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.4.1] - 2026-08-07

### Fixed

- **An unconfigured guardian blocked every Bash command.** The
  misconfiguration check ran *before* command detection, so on an install with
  no env vars set, `ls`, `git status`, `echo` — everything — exited 2. With the
  manual installer users at least saw the "configure now" output; with
  one-command plugin install this would brick Claude Code's Bash tool on
  install. The check now runs *after* command detection in all three prod
  guardians: unrelated commands pass, and the commands each guardian actually
  governs still fail closed until configured.
- Added 9 regression cases to `tests/test-allow-path.sh` covering exactly this:
  each unconfigured guardian must allow `ls -la` and `git status`, and must
  still block its own domain.

## [0.4.0] - 2026-08-07

### Added

- **Claude Code plugin packaging.** `.claude-plugin/plugin.json` and
  `hooks/hooks.json` register all four guardians automatically on install;
  `.claude-plugin/marketplace.json` makes the repo installable with
  `/plugin marketplace add farjad-hasan/claude-safety-hooks`.

### Fixed

- **`memory-invariants-guardian.sh` was committed non-executable** (mode
  `100644`). `install.sh` masked this by running `chmod +x`, but a plugin
  install has no installer — the hook would never have run. `tests/test-memory-guardian.sh`
  had the same problem.
- **`install.sh` printed the Linux-only hash recipe.** Its NEXT STEPS told every
  user to run `echo -n … | sha256sum`, which on macOS yields an empty hash and a
  passkey gate that cannot open — the same class of bug v0.3.1 fixed elsewhere,
  missed here because the installer is not covered by CI.

### Changed

- The memory guardian resolves its validator via `${CLAUDE_PLUGIN_ROOT}` when
  running as a plugin, falling back to the `install.sh` relative path
  otherwise — removing a fragile path assumption. Both branches are verified.
- README documents plugin install alongside the manual installer, including an
  explicit note that plugins execute arbitrary code and are trusted wholesale.

## [0.3.1] - 2026-08-07

### Fixed

- **macOS: whitelisted AWS reads were blocked.** The subcommand parser used
  GNU-only `\s` and `\b`, so on BSD `sed` the `aws` prefix was never stripped
  and the service parsed as the literal string `aws` — matching no whitelist
  entry. Every read, including `aws s3 ls`, was blocked. Replaced with `awk`
  token walking, which has no regex-dialect surface.
- **macOS: the passkey gate could not be opened.** All three prod guardians
  called `sha256sum`, which stock macOS does not ship, so the computed hash
  was empty and never matched. Added a `shasum -a 256` fallback that fails
  closed when neither tool is available.
- Replaced non-portable `echo -n` with `printf '%s'` in hash computation.

### Added

- `tests/test-allow-path.sh` — asserts that safe commands are **allowed** and
  that the passkey gate opens. The previous suite only proved dangerous
  commands were blocked, so a hook that blocked everything passed it; that is
  precisely how the macOS breakage reached a release.
- CI now runs on `macos-latest` as well as `ubuntu-latest`, and runs the
  memory-guardian suite, which CI had never executed.

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

[Unreleased]: https://github.com/farjad-hasan/claude-safety-hooks/compare/v0.4.1...HEAD
[0.4.1]: https://github.com/farjad-hasan/claude-safety-hooks/releases/tag/v0.4.1
[0.4.0]: https://github.com/farjad-hasan/claude-safety-hooks/releases/tag/v0.4.0
[0.3.1]: https://github.com/farjad-hasan/claude-safety-hooks/releases/tag/v0.3.1
[0.3.0]: https://github.com/farjad-hasan/claude-safety-hooks/releases/tag/v0.3.0
[0.2.0]: https://github.com/farjad-hasan/claude-safety-hooks/releases/tag/v0.2.0
