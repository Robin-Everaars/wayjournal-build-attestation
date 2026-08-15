# Releasing Wayjournal

Wayjournal releases are source-only. Cargo packages remain `publish = false`; Forgejo publishes the signed source tag and its generated archives. A release is valid only when every gate below binds the same exact commit.

## 1. Prepare the candidate

1. Start from protected `main` after all intended pull requests are merged.

1. Confirm `## Unreleased` remains in `CHANGELOG.md`, promote `## 0.1.0 - Unreleased` to the UTC release date, and use release commit subject `chore(release): 0.1.0`.

1. Confirm the version agrees everywhere:

   ```console
   version=$(nix develop -c cargo metadata --locked --no-deps --format-version 1 | jq -r '.packages[0].version')
   test "$version" = 0.1.0
   test "$(nix eval --raw .#packages."$(nix eval --impure --raw --expr builtins.currentSystem)".default.version)" = "$version"
   nix run . -- --version | grep -Fx "wayjournal $version"
   ```

1. Confirm the candidate has only reviewed release metadata on top of the exact reviewed S5 implementation commit. Record both commit and tree IDs.

## 2. Run source and contract gates

Resolve the native Git executable once and retain it for every Git-executing test:

```console
export WAYJOURNAL_TEST_GIT="$(readlink -f "$(command -v git)")"
test -x "$WAYJOURNAL_TEST_GIT"
```

Run the complete cheap and normal gates:

```console
nix fmt
nix develop -c cargo fmt --all -- --check
nix develop -c cargo clippy --locked --workspace --all-targets --all-features -- --deny warnings
nix develop -c cargo test --locked --release --workspace --all-targets --all-features --no-fail-fast
nix develop -c cargo run --locked --package wayjournal-core --example generate-artifacts -- --check
nix develop -c cargo deny check bans licenses sources
nix develop -c cargo audit --deny warnings
nix develop -c reuse lint
python3 nix/check-release-policy.py
nix flake check --all-systems --no-build
nix flake check --print-build-logs
```

Inspect `git diff` after the artifact generator and require zero schema, fixture, proof-preimage, capability-manifest, or lockfile drift.

Run every explicit capacity/RSS gate serially; the normal Nix gate skips these tests:

```console
nix develop -c cargo test --locked --release --workspace --all-targets --all-features \
  -- --ignored --test-threads=1
```

The exact-capacity record must include the 1 GiB Git tip, 1 GiB journal/proof/cache, one-million-entry/maximum-path, hostile-parent/history/fold, recovery inventory, and S5-specific projection/cache/multi-target maxima plus their maximum-plus-one rejections. Keep command output and SHA-256 hashes as release evidence.

## 3. Qualify every configured native system

Evaluation is not a native build. On a trusted clean runner whose native Nix system equals each of the following:

- `aarch64-darwin`
- `aarch64-linux`
- `x86_64-linux`

check out the exact candidate commit by full object ID, disable credential persistence, verify `git rev-parse HEAD`, and run:

```console
nix flake check --print-build-logs
system=$(nix eval --impure --raw --expr builtins.currentSystem)
nix build ".#packages.$system.default" --no-link --print-build-logs
```

Retain the immutable run URL or signed runner record, native system, candidate commit/tree, outcome, and logs. Foreign evaluation from another architecture does not qualify the system. A failure on a system blocks the release; do not silently narrow the configured matrix.

## 4. Review and merge

1. Obtain independent commit-bound correctness and security/resource reviews. Each review must verify the exact candidate commit/tree, clean worktree and index, artifact drift, public S4 compatibility, descriptor/authority/resource invariants, and report no blocker or high-severity finding.
1. Verify the pull request contains only approved release files and that required Forgejo checks pass.
1. Merge through protected `main`, fetch it into a clean worktree, and repeat version, release-policy, REUSE, artifact, signature, and clean-tree checks.
1. Require `git status --porcelain=v1 --untracked-files=all` to be empty and `git write-tree` to equal `HEAD^{tree}`.

## 5. Sign and publish

Create the annotated SSH-signed tag locally; do not ask Forgejo to invent it:

```console
git tag -s -a v0.1.0 -m 'Wayjournal v0.1.0' HEAD
git verify-tag v0.1.0
test "$(git rev-list -n1 v0.1.0)" = "$(git rev-parse HEAD)"
git push origin refs/tags/v0.1.0
```

Prepare release notes from the dated `0.1.0` changelog section. Publish a non-draft, non-prerelease Forgejo release against the pre-existing tag:

```console
fj release create --tag v0.1.0 --body "$(cat /tmp/wayjournal-v0.1.0-release.md)" 'Wayjournal v0.1.0'
```

Do not attach binaries unless that exact target artifact has a separately reviewed reproducibility, checksum, and provenance contract. Forgejo-generated source archives are source, not supported binaries.

## 6. Postflight

1. Fetch the tag from a new clone, run `git verify-tag v0.1.0`, and verify its commit/tree equal the recorded release candidate.
1. Build the locked flake and run `wayjournal --version` from the fetched tag.
1. Download the Forgejo source archive, record its SHA-256, and verify it contains both canonical license texts, `CHANGELOG.md`, `SECURITY.md`, schemas, fixtures, Cargo lock, and Nix lock.
1. Verify the release is public, non-draft, non-prerelease, titled `Wayjournal v0.1.0`, and links the changelog and security policy.
1. Confirm protected `main`, protected `v*` tags, required checks, runner isolation, least-privilege workflow permissions, and private vulnerability-reporting route remain configured.
1. Record release commit/tree, tag object/signature fingerprint, all three native attestations, review receipts, gate-log hashes, archive hash, and postflight result in durable release notes.

Any mismatch, missing evidence, blocker/high review finding, signature failure, artifact drift, or configured-system failure stops publication. Never delete or replace an already published tag.
