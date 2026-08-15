#!/usr/bin/env python3
"""Check the source-only Wayjournal release metadata contract."""

from __future__ import annotations

import hashlib
import pathlib
import re
import sys
import tomllib

ROOT = pathlib.Path(__file__).resolve().parent.parent
EXPECTED_LICENSE_DIGESTS = {
    "LICENSES/MIT.txt": "b05785f9f18e6716bab63424b11454513b9943a222595b70411009202fc592b5",
    "LICENSES/Apache-2.0.txt": "074e6e32c86a4c0ef8b3ed25b721ca23aca83df277cd88106ef7177c354615ff",
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def text(path: str) -> str:
    candidate = ROOT / path
    require(candidate.is_file(), f"missing required file: {path}")
    return candidate.read_text(encoding="utf-8")


def main() -> int:
    cargo = tomllib.loads(text("Cargo.toml"))
    package = cargo["workspace"]["package"]
    version = package.get("version", "")
    require(re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version) is not None, "workspace version must be SemVer")
    require(package.get("license") == "MIT OR Apache-2.0", "workspace license drift")
    require(package.get("readme") == "README.md", "workspace readme drift")

    for member in ("crates/wayjournal-core/Cargo.toml", "crates/wayjournal-cli/Cargo.toml"):
        manifest = tomllib.loads(text(member))["package"]
        require(manifest.get("publish") is False, f"{member} must remain publish=false")
        for field in ("license", "readme", "homepage", "documentation", "keywords", "categories"):
            require(manifest.get(field, {}).get("workspace") is True, f"{member} must inherit {field}")

    readme = text("README.md")
    require("license and public release policy will be decided" not in readme.lower(), "README still defers licensing")
    require(
        re.search(
            r"without\s+opening a Wayjournal store, contacting a Wayjournal or Git remote",
            readme,
        )
        is not None,
        "README must scope its no-remote claim to Wayjournal and Git",
    )
    for link in ("CHANGELOG.md", "CONTRIBUTING.md", "SECURITY.md", "docs/releasing.md", "LICENSES/MIT.txt", "LICENSES/Apache-2.0.txt"):
        require(link in readme, f"README must link {link}")

    changelog = text("CHANGELOG.md")
    require("## Unreleased" in changelog, "CHANGELOG must retain Unreleased")
    release_heading = rf"^## {re.escape(version)} - (?:Unreleased|[0-9]{{4}}-[0-9]{{2}}-[0-9]{{2}})$"
    require(re.search(release_heading, changelog, re.MULTILINE) is not None, "CHANGELOG must contain the current candidate or dated release")

    contributing = text("CONTRIBUTING.md")
    releasing = text("docs/releasing.md")
    require("readlink -f" not in contributing + releasing, "release documentation must not require GNU readlink")
    for token in (
        "aarch64-darwin",
        "aarch64-linux",
        "x86_64-linux",
        "git verify-tag",
        'git verify-commit "$candidate"',
        "WAYJOURNAL_TEST_GIT",
        "os.path.realpath",
        "Linux runners execute the full runtime test suite",
        "Darwin compiles every target and feature",
        "SHA256:lY3cNt8mrdV5ueO4FqErIN1SotpFVBdLw2ER7DSdRkU",
        "robineveraars@pm.me",
    ):
        require(token in releasing, f"release procedure omits {token}")

    workflow = text(".forgejo/workflows/check.yml")
    for token in ("contents: read", "cancel-in-progress: true", "timeout-minutes:"):
        require(token in workflow, f"Forgejo workflow omits {token}")
    require(
        "actions/checkout@11d5960a326750d5838078e36cf38b85af677262" in workflow,
        "Forgejo checkout action must remain immutable",
    )
    require("persist-credentials: false" in workflow, "Forgejo checkout must not persist credentials")

    flake = text("flake.nix")
    require('version = cargoManifest.workspace.package.version;' in flake, "Nix version must derive from Cargo.toml")
    require('version = "0.1.0";' not in flake, "Nix version must not duplicate Cargo version")
    for token in (
        "check-release-policy",
        "reuse lint",
        "licenses.mit",
        "cargo check --locked --release --workspace --all-targets --all-features",
        "store::non_linux_tests::secure_unnamed_temporary_staging_fails_closed",
    ):
        require(token in flake, f"flake release gate omits {token}")

    reuse = tomllib.loads(text("REUSE.toml"))
    require(reuse["SPDX-PackageName"] == "wayjournal", "REUSE package name drift")
    for path, expected_digest in EXPECTED_LICENSE_DIGESTS.items():
        candidate = ROOT / path
        require(candidate.is_file(), f"missing canonical license text: {path}")
        actual_digest = hashlib.sha256(candidate.read_bytes()).hexdigest()
        require(actual_digest == expected_digest, f"canonical license digest drift: {path}")

    print("release metadata contract: ok")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except AssertionError as error:
        print(f"release metadata contract: {error}", file=sys.stderr)
        raise SystemExit(1) from error
