# Wayjournal

Wayjournal is a generic, federated substrate for immutable journals stored in
ordinary Git repositories. It is intended to provide domain-neutral journal
primitives that independent applications can build on.

The wire slice and an experimental Linux filesystem-store slice are implemented.
They provide strict canonical JSON, closed generic record and batch envelopes,
typed identifiers, canonical path classification, deterministic revisions, and
checked protocol artifacts. The local store uses descriptor-relative publication
and explicit durability barriers; recovery is tested at those modeled barriers,
not against arbitrary device, kernel, or filesystem failures. Git federation is
not yet implemented.

## Product boundaries

- The substrate is generic: it does not define task, workflow, issue-tracking,
  or project-management semantics.
- Immutable journal records in ordinary Git repositories are the intended
  durable data model.
- Federation is repository-based; no hosted service is required by the core
  design.
- Domain-specific policy and user experiences belong in consumers, not in this
  repository.
- On Linux, cooperative store processes lock the retained root-directory inode;
  the ambient root binding must be supplied by a trusted caller. Store-relative
  scans and publication reject symlinks/cross-device descendants and apply count/byte
  bounds, no-clobber staging, fsync barriers, and startup recovery. Publication
  currently requires Linux procfs at `/proc/self/fd` to link retained file inodes.
- Git sync, profiles, catalogs, trust, proofs, projections, and consumer
  semantics remain outside this milestone.

## Repository layout

- `crates/wayjournal-core`: domain-neutral wire and layout primitives
- `schemas` and `fixtures`: checked schemas and canonical wire goldens
- `crates/wayjournal-cli`: the `wayjournal` executable
- `.forgejo/workflows/check.yml`: the reproducible Codeberg check
- `flake.nix`: packages, applications, checks, formatter, and development shell

## Development

Install Nix with flakes enabled, then allow direnv:

```console
direnv allow
```

Format the source with:

```console
nix fmt
```

Run the complete local gate with:

```console
nix flake check --print-build-logs
```

Run the bootstrap executable with:

```console
nix run . -- --version
```

The Forgejo workflow invokes the same Nix gate on a self-hosted runner labelled
`nix`; there is no separate CI-only build script.

The license and public release policy will be decided before publication.
