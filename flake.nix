{
  description = "Federated immutable Git journal substrate";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";

    advisory-db = {
      url = "github:rustsec/advisory-db";
      flake = false;
    };

    flake-parts = {
      url = "github:hercules-ci/flake-parts";
      inputs.nixpkgs-lib.follows = "nixpkgs";
    };

    crane.url = "github:ipetkov/crane";

    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    treefmt-nix = {
      url = "github:numtide/treefmt-nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    inputs@{
      advisory-db,
      crane,
      flake-parts,
      nixpkgs,
      rust-overlay,
      self,
      treefmt-nix,
      ...
    }:
    let
      supportedSystems = [
        "aarch64-darwin"
        "aarch64-linux"
        "x86_64-linux"
      ];
    in
    flake-parts.lib.mkFlake { inherit inputs; } {
      imports = [ treefmt-nix.flakeModule ];

      systems = supportedSystems;

      perSystem =
        { system, ... }:
        let
          pkgs = import nixpkgs {
            inherit system;
            overlays = [ (import rust-overlay) ];
          };
          rustToolchain = pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;
          craneLib = (crane.mkLib pkgs).overrideToolchain rustToolchain;
          cargoManifest = builtins.fromTOML (builtins.readFile ./Cargo.toml);
          src = pkgs.lib.cleanSourceWith {
            src = ./.;
            filter =
              path: type:
              (craneLib.filterCargoSources path type)
              || pkgs.lib.hasInfix "/schemas/" (toString path)
              || pkgs.lib.hasInfix "/fixtures/" (toString path);
          };
          commonArgs = {
            pname = "wayjournal";
            version = cargoManifest.workspace.package.version;
            inherit src;
            strictDeps = true;
            nativeBuildInputs = [ pkgs.git ];
            WAYJOURNAL_TEST_GIT = "${pkgs.git}/bin/git";
          };
          cargoArtifacts = craneLib.buildDepsOnly commonArgs;
          wayjournal = craneLib.buildPackage (
            commonArgs
            // {
              inherit cargoArtifacts;
              doCheck = false;
              meta = {
                description = "Federated immutable Git journal substrate";
                homepage = "https://codeberg.org/Robinio94/wayjournal";
                license = [
                  pkgs.lib.licenses.mit
                  pkgs.lib.licenses.asl20
                ];
                mainProgram = "wayjournal";
                platforms = supportedSystems;
              };
            }
          );
        in
        {
          apps =
            let
              app = {
                type = "app";
                program = "${wayjournal}/bin/wayjournal";
                meta.description = "Federated immutable Git journal substrate";
              };
            in
            {
              default = app;
              wayjournal = app;
            };

          packages = {
            default = wayjournal;
            inherit wayjournal;
          };

          checks = {
            package = wayjournal;
            audit = craneLib.cargoAudit {
              inherit advisory-db src;
              cargoAuditExtraArgs = "--no-yanked";
            };
            clippy = craneLib.cargoClippy (
              commonArgs
              // {
                inherit cargoArtifacts;
                cargoClippyExtraArgs = "--all-targets --all-features -- --deny warnings";
              }
            );
            nextest =
              if pkgs.stdenv.isLinux then
                craneLib.cargoNextest (
                  commonArgs
                  // {
                    inherit cargoArtifacts;
                  }
                )
              else
                # The secure store is Linux-only and fails closed elsewhere; compile every target
                # without claiming that its filesystem and Git behavior is available.
                craneLib.mkCargoDerivation (
                  commonArgs
                  // {
                    inherit cargoArtifacts;
                    pname = "wayjournal-non-linux-check";
                    buildPhaseCargoCommand = ''
                      cargo check --locked --release --workspace --all-targets --all-features
                      cargo test --locked --release --package wayjournal-core --lib --all-features store::non_linux_tests::secure_unnamed_temporary_staging_fails_closed -- --exact
                    '';
                    installPhaseCommand = ''
                      mkdir -p "$out"
                      touch "$out/passed"
                    '';
                  }
                );
            wire-artifacts = craneLib.mkCargoDerivation (
              commonArgs
              // {
                inherit cargoArtifacts;
                pname = "wayjournal-wire-artifacts";
                buildPhaseCargoCommand = "cargo run --package wayjournal-core --example generate-artifacts -- --check";
                installPhaseCommand = ''
                  mkdir -p "$out"
                  touch "$out/passed"
                '';
              }
            );
            deny = craneLib.cargoDeny (
              commonArgs
              // {
                cargoDenyChecks = "bans licenses sources";
              }
            );
            actionlint = pkgs.runCommand "wayjournal-actionlint" { nativeBuildInputs = [ pkgs.actionlint ]; } ''
              cd ${self}
              actionlint -config-file actionlint.yaml .forgejo/workflows/check.yml
              touch "$out"
            '';
            docs-links =
              pkgs.runCommand "wayjournal-docs-links"
                {
                  nativeBuildInputs = [ pkgs.lychee ];
                  SSL_CERT_FILE = "${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt";
                }
                ''
                  cd ${self}
                  lychee --offline --no-progress README.md CHANGELOG.md CONTRIBUTING.md SECURITY.md docs
                  touch "$out"
                '';
            release-policy =
              pkgs.runCommand "wayjournal-release-policy" { nativeBuildInputs = [ pkgs.python3 ]; }
                ''
                  cd ${self}
                  python3 nix/check-release-policy.py
                  touch "$out"
                '';
            reuse = pkgs.runCommand "wayjournal-reuse" { nativeBuildInputs = [ pkgs.reuse ]; } ''
              cd ${self}
              reuse lint
              touch "$out"
            '';
          };

          devShells.default = pkgs.mkShell {
            packages = [
              rustToolchain
              pkgs.actionlint
              pkgs.cargo-audit
              pkgs.cargo-deny
              pkgs.cargo-nextest
              pkgs.git
              pkgs.jq
              pkgs.lychee
              pkgs.python3
              pkgs.reuse
              pkgs.rust-analyzer
            ];

            RUST_SRC_PATH = "${rustToolchain}/lib/rustlib/src/rust/library";
          };

          treefmt = {
            projectRootFile = "flake.nix";
            programs = {
              deadnix.enable = true;
              mdformat.enable = true;
              nixfmt.enable = true;
              rustfmt = {
                enable = true;
                edition = "2024";
                package = rustToolchain;
              };
              statix.enable = true;
              taplo.enable = true;
              yamlfmt.enable = true;
            };
            settings.excludes = [
              ".direnv/**"
              "target/**"
            ];
          };
        };
    };
}
