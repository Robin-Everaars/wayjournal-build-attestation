# Contributing to Wayjournal

Wayjournal is a security-sensitive immutable-journal substrate. Keep changes narrow, preserve closed wire contracts, and include the positive, negative, boundary, and failure evidence appropriate to the changed authority path.

## Development environment

Install Nix with flakes enabled and enter the locked development shell:

```console
nix develop
```

Tests that execute Git must receive the resolved native executable, not an alias, script, or ambient `PATH` lookup:

```console
export WAYJOURNAL_TEST_GIT="$(readlink -f "$(command -v git)")"
```

Use disposable repositories and state. Tests must not contact production remotes, reuse credentials, or mutate an operator's journal.

## Required gates

Run the focused regression first, including an observed failing test before production code for behavior changes. Before submitting any change, run:

```console
nix develop -c cargo fmt --all -- --check
nix develop -c cargo clippy --locked --workspace --all-targets --all-features -- --deny warnings
WAYJOURNAL_TEST_GIT="$(readlink -f "$(command -v git)")" \
  nix develop -c cargo test --locked --release --workspace --all-targets --all-features --no-fail-fast
nix develop -c cargo run --locked --package wayjournal-core --example generate-artifacts -- --check
nix develop -c reuse lint
python3 nix/check-release-policy.py
nix flake check --all-systems --no-build
nix flake check --print-build-logs
```

The normal Nix gate deliberately skips explicit capacity/RSS tests. Security-sensitive or release work must also run every ignored test serially with the resolved Git executable:

```console
WAYJOURNAL_TEST_GIT="$(readlink -f "$(command -v git)")" \
  nix develop -c cargo test --locked --release --workspace --all-targets --all-features \
  -- --ignored --test-threads=1
```

`nix flake check --all-systems --no-build` is evaluation evidence only. Release qualification additionally requires `nix flake check --print-build-logs` and a native package build on each configured system as specified in [the release procedure](docs/releasing.md).

## Contract and artifact changes

Public schema identifiers, canonical fixture bytes, proof preimages, capability identifiers, projection identifiers, error variants, revision algorithms, and framing rules are contracts. A change must:

1. state whether it is additive or incompatible;
1. add a failing positive/negative or maximum/+1 test first;
1. update the generator rather than hand-edit generated artifacts;
1. run the generator in write mode and then `--check` mode;
1. review every schema and fixture byte in the diff;
1. obtain independent correctness and security review for authority or resource-bound changes.

Do not add aliases, implicit revision conversion, wildcard decoding, ambient executable discovery, private validity caps, or a fallback that weakens a closed contract.

## Documentation and licensing

Documentation is part of the release contract. Keep local links valid and let `nix fmt` normalize Markdown. New files are licensed under `MIT OR Apache-2.0`; update `REUSE.toml` when a new path is not covered by its aggregate annotation. Do not insert headers into canonical JSON, preimage, or fixture bytes.

## Submissions

Use focused imperative commits and explicit pathspecs. A change description must name its safety impact, tests, exact commit reviewed, and residual assumptions. Never sweep unrelated concurrent work into a commit. Report vulnerabilities privately according to [the security policy](SECURITY.md).
