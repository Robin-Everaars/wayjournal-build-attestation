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
    flake-parts.lib.mkFlake { inherit inputs; } {
      imports = [ treefmt-nix.flakeModule ];

      systems = [
        "aarch64-darwin"
        "aarch64-linux"
        "x86_64-linux"
      ];

      perSystem =
        { system, ... }:
        let
          pkgs = import nixpkgs {
            inherit system;
            overlays = [ (import rust-overlay) ];
          };
          rustToolchain = pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;
          craneLib = (crane.mkLib pkgs).overrideToolchain rustToolchain;
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
            version = "0.1.0";
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
                mainProgram = "wayjournal";
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
                    pname = "wayjournal-test-compile";
                    buildPhaseCargoCommand = "cargo check --locked --release --workspace --all-targets --all-features";
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
          };

          devShells.default = pkgs.mkShell {
            packages = [
              rustToolchain
              pkgs.actionlint
              pkgs.cargo-deny
              pkgs.cargo-nextest
              pkgs.git
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
