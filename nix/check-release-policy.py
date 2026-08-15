#!/usr/bin/env python3
"""Check the source-only Wayjournal release metadata contract."""

from __future__ import annotations

import pathlib
import re
import sys
import tomllib

ROOT = pathlib.Path(__file__).resolve().parent.parent


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
    for link in ("CHANGELOG.md", "CONTRIBUTING.md", "SECURITY.md", "docs/releasing.md", "LICENSES/MIT.txt", "LICENSES/Apache-2.0.txt"):
        require(link in readme, f"README must link {link}")

    changelog = text("CHANGELOG.md")
    require("## Unreleased" in changelog, "CHANGELOG must retain Unreleased")
    release_heading = rf"^## {re.escape(version)} - (?:Unreleased|[0-9]{{4}}-[0-9]{{2}}-[0-9]{{2}})$"
    require(re.search(release_heading, changelog, re.MULTILINE) is not None, "CHANGELOG must contain the current candidate or dated release")

    releasing = text("docs/releasing.md")
    for token in ("aarch64-darwin", "aarch64-linux", "x86_64-linux", "git verify-tag", "WAYJOURNAL_TEST_GIT"):
        require(token in releasing, f"release procedure omits {token}")

    workflow = text(".forgejo/workflows/check.yml")
    for token in ("contents: read", "cancel-in-progress: true", "timeout-minutes:"):
        require(token in workflow, f"Forgejo workflow omits {token}")
    require(
        "actions/checkout@11d5960a326750d5838078e36cf38b85af677262" in workflow,
        "Forgejo checkout action must remain immutable",
    )

    flake = text("flake.nix")
    require('version = cargoManifest.workspace.package.version;' in flake, "Nix version must derive from Cargo.toml")
    require('version = "0.1.0";' not in flake, "Nix version must not duplicate Cargo version")
    for token in ("check-release-policy", "reuse lint", "licenses.mit"):
        require(token in flake, f"flake release gate omits {token}")

    reuse = tomllib.loads(text("REUSE.toml"))
    require(reuse["SPDX-PackageName"] == "wayjournal", "REUSE package name drift")
    require((ROOT / "LICENSES/MIT.txt").is_file(), "missing canonical MIT text")
    require((ROOT / "LICENSES/Apache-2.0.txt").is_file(), "missing canonical Apache text")

    print("release metadata contract: ok")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except AssertionError as error:
        print(f"release metadata contract: {error}", file=sys.stderr)
        raise SystemExit(1) from error
