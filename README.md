# Wayjournal

Wayjournal is a generic, federated substrate for immutable journals stored in
ordinary Git repositories. It is intended to provide domain-neutral journal
primitives that independent applications can build on.

The wire slice, the Linux filesystem store, identity/profile/catalog domains, and
read-only Git admission bootstrap are implemented. They provide strict canonical JSON,
closed generic record and batch envelopes, typed immutable logical store identity,
deterministic causal folds for advisory profiles and catalogs, canonical path
classification, deterministic revisions, and checked protocol artifacts. The local
store uses descriptor-relative publication and explicit durability barriers; recovery
is tested at those modeled barriers, not against arbitrary device, kernel, or filesystem
failures. S4b adds retained pending/quarantine roots, closed bounded pending and
quarantine codecs, full-capacity chunk metadata, pending-aware Store access, complete
monotonic history validation, immutable exact union, descriptor-safe bulk recovery,
expected-old local-ref/checkpoint transitions, one-ref lease push with observation,
and two-slot stale-successor recovery.

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
  Git admission is likewise Linux/procfs-dependent: it executes the retained Git
  inode and addresses retained store, `.git`, and attempt directories through procfs.
  Non-Linux systems can evaluate/package the crate but Git admission returns an I/O
  failure where those procfs bindings are unavailable. Git script executables are
  not supported reliably; callers should supply an ordinary native Git binary.
- `Store::bootstrap_git_admission` can establish or revalidate a durable local
  checkpoint only when local HEAD, the fetched approved tip, the filesystem, identity,
  and revision already match. Differing tips return `AdvanceRequired` without mutation.
  If any durable S4b pending operation exists, `read`, `append`, `exclusive_snapshot`,
  and `admission_checkpoint` fail before scanning in every phase, including stale and
  confirmed phases. Bootstrap alone may use its retained Git executable to verify the
  candidate filesystem, approved local ref, and checkpoint read-only; it cannot recover,
  advance, retire, or clean durable pending state. Shared profile data is advisory and
  never supplies approval or credentials.
- Quarantine incidents are closed canonical private files and block automatic Git retry.
  There is no S4b acknowledgement or clearing API. Ordinary local Store APIs are not
  blocked by quarantine when no pending operation exists.
- Advancing synchronization validates every new commit and parent boundary, detects
  delete/modify-and-restore edges, and converges by exact canonical path-byte set and
  revision. It reuses a tip only with the required ancestry; otherwise it constructs a
  bounded two-parent merge and verifies both parents are ancestors. Remote publication
  updates exactly the existing approved ref with an expected-OID lease; missing refs are
  quarantined and are never created.
- Fetched repositories are disposable until their metadata, physical count/byte/depth,
  object graph, commit graph, canonical trees, and snapshots validate. Git CLI still
  cannot impose a portable byte cap before receiving an incoming pack. Checkpoint
  expected-old replacement is cooperative serialization, not a kernel compare-and-swap.
- The Git executable, one credential-free canonical `file://` or `https://` locator,
  one `refs/heads/...` ref, and a local trust binding are explicit checked inputs. The
  runner clears ambient environment/configuration and rejects unsafe repository-local
  Git settings before transfer.
- Git CLI fetch cannot portably impose a hard pack-byte cap before Git writes received
  objects. Concurrent hostile rewriting of Git metadata is outside the cooperative
  locking boundary. Proofs, projections, and consumer semantics remain out of scope.
- `Store::open` is the secure S3 default and requires a sealed built-in registry from
  `wayjournal_domain_registry[_with]`. Existing S1/S2 callers must migrate explicitly
  to `Store::open_legacy_s1_s2`; that compatibility API refuses S3 built-in records.

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
