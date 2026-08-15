# Security policy

## Supported versions

Only the latest tagged release receives security fixes. Before 1.0, a fix may require upgrading to a newer minor release. The `main` branch and untagged release candidates are development code and receive no release support.

## Report a vulnerability

Send private reports to [robineveraars@pm.me](mailto:robineveraars@pm.me) with `Wayjournal security` in the subject. Do not open a public issue before coordinating disclosure.

Include:

- the affected release or exact commit;
- the operating system, filesystem, Git version, and repository shape;
- the security impact and required attacker capabilities;
- minimal reproduction steps using disposable state and credential-free remotes;
- any suggested mitigation.

A report does not authorize access to repositories, hosts, credentials, or data that you do not own or have explicit permission to test. Do not test against a production journal or remote without the owner's authorization. There is no bug bounty program.

After confirming an issue, the maintainer will coordinate a fix, release, and disclosure with the reporter. Response and disclosure timing depend on severity and the affected dependency or platform; no fixed service-level agreement is promised.

## Relevant trust boundaries

Reports are especially useful when they concern:

- canonical JSON, record, batch, revision, proof, capability, or projection ambiguity;
- descriptor confinement, symlink or mount crossing, namespace mutation, publication durability, or recovery;
- logical-store identity, built-in domain sealing, ownership, duplicate IDs, or causal-fold divergence;
- Git executable retention, configuration/environment isolation, hostile history/object framing, remote/ref authority, rollback, quarantine, or expected-old replacement;
- checkpoint freshness, proof creation, cache authority, lock ordering, cache-root reset, or cross-store confusion;
- resource bounds at exact accepted maxima or maximum-plus-one rejection;
- accidental credential disclosure or unexpected network contact in tests and tooling;
- release source, schema/fixture drift, dependency provenance, signed-tag, or native-build attestation.

Wayjournal assumes a trusted caller supplies the intended ambient store root and approved Git/remote/ref bindings. Cooperative store locking does not stop an attacker with independent write access to retained metadata, and Git cannot impose a portable pre-write incoming-pack byte cap. S5 proofs are local integrity projections, not signatures, claims, remote attestations, or freshness authority. See the [product boundaries and authority planes](README.md#product-boundaries) for the complete public model.
