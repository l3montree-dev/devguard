{
  description = "DevGuard";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";
    nixpkgs-unstable.url = "github:NixOS/nixpkgs/nixpkgs-unstable";

    # uv2nix + pyproject-nix: build the scanner Python env from uv.lock,
    # replacing manual overridePythonAttrs for semgrep + checkov.
    pyproject-nix.url = "github:pyproject-nix/pyproject.nix";
    pyproject-nix.inputs.nixpkgs.follows = "nixpkgs";
    uv2nix.url = "github:pyproject-nix/uv2nix";
    uv2nix.inputs.pyproject-nix.follows = "pyproject-nix";
    uv2nix.inputs.nixpkgs.follows = "nixpkgs";
    pyproject-build-systems.url = "github:pyproject-nix/build-system-pkgs";
    pyproject-build-systems.inputs.pyproject-nix.follows = "pyproject-nix";
    pyproject-build-systems.inputs.uv2nix.follows = "uv2nix";
    pyproject-build-systems.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs =
    {
      self,
      nixpkgs,
      nixpkgs-unstable,
      uv2nix,
      pyproject-nix,
      pyproject-build-systems,
    }:

    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "aarch64-darwin"
      ];

      eachSystem =
        systems: f:
        builtins.foldl' (
          a: s: a // builtins.mapAttrs (k: v: (a.${k} or { }) // { ${s} = v; }) (f s)
        ) { } systems;

      inherit (nixpkgs) lib;
    in
    eachSystem systems (
      system:
      let
        unstablePkgs = nixpkgs-unstable.legacyPackages.${system};
        hostPkgs = nixpkgs.legacyPackages.${system} // {
          inherit (unstablePkgs) buildGoModule;
        };

        targetPkgsAmd64 = nixpkgs.legacyPackages.x86_64-linux // {
          buildGoModule = nixpkgs-unstable.legacyPackages.x86_64-linux.buildGoModule;
        };
        targetPkgsArm64 = nixpkgs.legacyPackages.aarch64-linux // {
          buildGoModule = nixpkgs-unstable.legacyPackages.aarch64-linux.buildGoModule;
        };
        # this is only done to satisfy the expected structure in the container hardening work
        binaries = import ./nix/devguard.nix {
          inherit (hostPkgs)
            buildGoModule
            lib
            ;
          inherit self;
        };
        ociImagesAmd64 = import ./nix/oci.nix {
          pkgs = targetPkgsAmd64;
          inherit
            self
            pyproject-nix
            uv2nix
            pyproject-build-systems
            ;
        };
        ociImagesArm64 = import ./nix/oci.nix {
          pkgs = targetPkgsArm64;
          inherit
            self
            pyproject-nix
            uv2nix
            pyproject-build-systems
            ;
        };

        amd64Dependencies = [
          ociImagesAmd64.craneFromSource.package
          ociImagesAmd64.gitleaksFromSource.package
          ociImagesAmd64.trivyFromSource.package
        ];

        arm64Dependencies = [
          ociImagesArm64.craneFromSource.package
          ociImagesArm64.gitleaksFromSource.package
          ociImagesArm64.trivyFromSource.package
        ];

        # Built for the evaluating system, so these are the only outputs that
        # mean anything on a non-Linux host.
        hostBinaries = {
          inherit (binaries)
            devguardScanner
            devguard
            devguardCLI
            ;
        };

        # supplementary SBOMs, exposed directly so they can be inspected
        # (`nix build .#devguard-scanner-sbom && cat result/sboms/*.json`)
        # without rebuilding and untarring a whole OCI image just to check
        # one file.
        sbomOutputs = {
          devguard-scanner-sbom = ociImagesArm64.devguardBinaries.devguardScannerSBOM;
          devguard-sbom = ociImagesArm64.devguardBinaries.devguardSBOM;
          devguard-cli-sbom = ociImagesArm64.devguardBinaries.devguardCLISBOM;
          crane-sbom = ociImagesArm64.craneFromSource.sbom;
          gitleaks-sbom = ociImagesArm64.gitleaksFromSource.sbom;
          trivy-sbom = ociImagesArm64.trivyFromSource.sbom;
          kratos-sbom = ociImagesArm64.kratosFromSource.kratosSBOM;
        };

        arm64Packages = {
          devguard-arm64 = ociImagesArm64.devguardOCI { debug = false; };
          devguard-scanner-arm64 = ociImagesArm64.devguardScannerOCI;
          postgresql-arm64 = ociImagesArm64.postgresqlOCI { debug = false; };
          devguard-debug-arm64 = ociImagesArm64.devguardOCI { debug = true; };
          postgresql-debug-arm64 = ociImagesArm64.postgresqlOCI { debug = true; };
          kratos-arm64 = ociImagesArm64.kratosOCI { debug = false; };
          kratos-debug-arm64 = ociImagesArm64.kratosOCI { debug = true; };

          deps-arm64 = hostPkgs.symlinkJoin {
            name = "devguard-deps-arm64";
            paths = arm64Dependencies ++ [ ociImagesArm64.pythonTools.venv ];
          };
        };

        amd64Packages = {
          # those are binaries compiled for the host platform
          devguard-amd64 = ociImagesAmd64.devguardOCI { debug = false; };
          devguard-scanner-amd64 = ociImagesAmd64.devguardScannerOCI;
          postgresql-amd64 = ociImagesAmd64.postgresqlOCI { debug = false; };
          devguard-debug-amd64 = ociImagesAmd64.devguardOCI { debug = true; };
          postgresql-debug-amd64 = ociImagesAmd64.postgresqlOCI { debug = true; };
          kratos-amd64 = ociImagesAmd64.kratosOCI { debug = false; };
          kratos-debug-amd64 = ociImagesAmd64.kratosOCI { debug = true; };

          deps-amd64 = hostPkgs.symlinkJoin {
            name = "devguard-deps-amd64";
            paths = amd64Dependencies ++ [ ociImagesAmd64.pythonTools.venv ];
          };
        };

      in
      {
        # The OCI images, their SBOMs and the deps bundles are all pinned to a
        # Linux target arch regardless of the evaluating system - the exact same
        # derivations on every system. Exposing them under a darwin `packages`
        # set would just be 18 attributes that need a remote builder to realise.
        # Both Linux arches keep both target arches: `make nix-cache-push`
        # builds deps-amd64 and deps-arm64 from a single machine, and CI splits
        # the image builds across an amd64 and an arm64 runner.
        packages = {
          default = hostBinaries.devguard;
        }
        // hostBinaries
        // sbomOutputs
        // arm64Packages
        // amd64Packages;
        devShells.default = hostPkgs.mkShell {
          buildInputs = [
            unstablePkgs.go
            unstablePkgs.gotools
            unstablePkgs.gopls
            unstablePkgs.golangci-lint
            unstablePkgs.go-mockery
            self.formatter.${system}
          ];
        };

        formatter = unstablePkgs.treefmt.withConfig {
          settings = {
            tree-root-file = "flake.nix";
            on-unmatched = "info";
            formatter = {
              nixfmt = {
                command = lib.getExe unstablePkgs.nixfmt;
                includes = [ "*.nix" ];
              };
              statix = {
                command = lib.getExe unstablePkgs.statix;
                options = [ "fix" ];
                no-positional-arg-support = true;
                includes = [ "*.nix" ];
              };
              deadnix = {
                command = lib.getExe unstablePkgs.deadnix;
                options = [ "--edit" ];
                includes = [ "*.nix" ];
              };
            };
          };
        };

        checks.formatting = self.formatter.${system}.check self;
      }
    );
}
