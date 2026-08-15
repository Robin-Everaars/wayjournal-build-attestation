# Wayjournal

Wayjournal is a generic, federated substrate for immutable journals stored in
ordinary Git repositories. It is intended to provide domain-neutral journal
primitives that independent applications can build on.

The wire slice, Linux filesystem store, identity/profile/catalog domains, Git union
admission, and S5 federation projections are implemented. They provide strict canonical
JSON, closed generic record and batch envelopes, typed immutable logical store identity,
deterministic causal folds for advisory profiles and multi-target catalogs, canonical
path classification, deterministic revisions, checked protocol artifacts, locally
verified presence proofs, capability negotiation, disposable proof caching, and
preflighted multi-store synchronization. The local store uses descriptor-relative
publication and explicit durability barriers; recovery is tested at those modeled
barriers, not against arbitrary device, kernel, or filesystem failures. S4b supplies the
retained pending/quarantine roots and exact union/CAS authority on which S5 relies.

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
  Non-Linux systems are package and check-compilation targets only. Secure unnamed
  staging returns an `Unsupported` I/O failure, and Git admission fails where the
  required procfs bindings are unavailable. Git script executables are
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
  locking boundary. S5 proofs are exact local presence projections created only from a
  current durable checkpoint and matching canonical snapshot under one retained lock.
  They are integrity identifiers, not signatures, remote attestations, claims, or
  independent freshness authority.
- `Store::open` is the secure S3 default and requires a sealed built-in registry from
  `wayjournal_domain_registry[_with]`. Existing S1/S2 callers must migrate explicitly
  to `Store::open_legacy_s1_s2`; that compatibility API refuses S3 built-in records.

## Three authority planes

Wayjournal keeps three planes separate:

1. **Canonical Git journal state.** Immutable records, batches, identity, advisory
   profile/catalog operations, and their deterministic store revision are the portable
   journal. Catalog remotes, aliases, groups, defaults, enabled flags, and capability
   hints remain advisory and cannot authorize synchronization or proof freshness.
1. **Durable local authority state.** Admission checkpoints bind the logical identity,
   accepted Git commit/revision, local trust, approved remote, and approved ref. Pending
   recovery and quarantine are local durable safety state. This plane alone authorizes
   Git admission and supplies the current revision used by S5 projections.
1. **Disposable local proofs, projections, and cache.** A `VerifiedProof` records that an
   exact record was present in the canonical snapshot matching the current checkpoint
   when observed. Its BLAKE3 identifier is not a signature. Revision/proof vectors are
   bounded serialized data, never statements that their revisions are current. The
   proof cache has no fsync promise and no journal, checkpoint, trust, quarantine, or Git
   authority; deleting it changes no durable meaning.

Cache lookup and insertion resolve every dependency only from current durable admission
checkpoints while retaining all dependency-store locks in logical-store order. A
serialized or caller-retained revision vector can never enter that freshness-authority
path. Missing, malformed, pending-blocked, identity-confused, changed, or reset authority
returns no hit, and cache-root replacement permanently latches the opened cache handle as
reset.

`sync_stores` first performs a complete ordered, duplicate-free, at-most-256-target
preflight. It checks every current checkpoint, store identity, request authority, sealed
handshake checkpoint, and negotiated Git union/CAS capability before any transfer-capable
operation. After preflight, each target must repeat the complete checkpoint/handshake,
identity, trust, approved remote/ref, and sync-capability checks while continuously
holding that target's exact transfer lock through Git, pending, and CAS work. Stores then
complete independently in input order; one runtime error never rolls back another store.
Per-target authorization and legacy synchronization failures use the additive
`AuthorizedGitSyncError`; the finalized S4 `GitSyncError` surface remains unchanged.

Consumers own publication and folding of invalidation records, the meaning of
contradictions, TTL/expiry policy, and every task, workflow, readiness, claim, routing,
recipient, and scheduler semantic. S5 exposes no such consumer policy.

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
