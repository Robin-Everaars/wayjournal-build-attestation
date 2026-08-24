# Changelog

All notable user-visible changes to Wayjournal are recorded here. Wayjournal follows Semantic Versioning. Before 1.0, an incompatible public API or wire-contract change requires a new minor version; patch releases preserve the documented minor-series contracts.

## Unreleased

### Added

- `Store::open_strict_retained_root` opens a strict store from an already retained directory descriptor. Before creating the layout, it rejects descriptors that cannot be synchronized or cannot yield an independent read-only root-lock descriptor. The retained descriptor stays the root-lock authority, every reserved child is derived descriptor-relatively, and the diagnostic path is never an authority.
- `GitCommandError` carries a stable `GitCommandFailureKind` (`Spawn`, `Io`, `Timeout`, `NonZeroExit`, `StdoutLimit`, `StderrLimit`, `ProcessControl`) behind a `kind()` accessor, so consumers can classify a failed Git invocation without matching its message text.

### Changed

- Bounded output capture tracks stdout and stderr overflow separately, so a stderr budget breach is reported as `StderrLimit` instead of sharing one flag with stdout.

## 0.1.0 - 2026-08-15

Wayjournal v0.1.0 is a source-only release distributed through its locked Nix flake.

### Added

- Strict canonical JSON record and atomic batch envelopes with deterministic logical-store revisions.
- Sealed built-in identity, profile, and multi-target catalog domains with deterministic causal folds.
- Descriptor-confined Linux filesystem publication, durability barriers, startup recovery, and bounded semantic replay.
- Advancing Git union/CAS admission with retained pending and quarantine authority, hostile-history checks, linked-worktree support, and exact snapshot convergence.
- Additive S5 federation projections: exact revision and proof vectors, locally verified presence proofs, capability negotiation, bounded disposable proof caching, and all-target preflighted multi-store synchronization.
- Checked schemas, canonical positive fixtures, hostile boundary fixtures, source-compatibility gates, and exact-capacity resource tests.

### Security

- Git and filesystem authority is retained descriptor-relatively and fails closed on hostile framing, namespace mutation, rollback, ambiguous ownership, or stale checkpoints.
- Proofs and caches are integrity projections only. They are not signatures, remote attestations, claims, or independent freshness authority.

### Known limitations

- Distribution is source-only through the locked Nix flake; the crates are not published to crates.io.
- Native package/check outputs are configured for `x86_64-linux`, `aarch64-linux`, and `aarch64-darwin`, but advancing Git admission and retained publication require Linux procfs at `/proc/self/fd`.
- Git cannot portably cap incoming pack bytes before a fetch writes received objects. Cooperative locking and expected-old replacement are not kernel compare-and-swap.
