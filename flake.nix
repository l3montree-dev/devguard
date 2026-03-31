{
  description = "DevGuard";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";
    flake-utils.url = "github:numtide/flake-utils";
    # sbomnix walks the full Nix derivation graph (build + runtime closure)
    # and emits CycloneDX / SPDX SBOMs — including the Go compiler, stdlib,
    # every build tool, and all Go module dependencies.
    sbomnix.url = "github:tiiuae/sbomnix";
    sbomnix.inputs.nixpkgs.follows = "nixpkgs"; # share the same nixpkgs pin
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

  outputs = { self, nixpkgs, flake-utils, sbomnix, uv2nix, pyproject-nix, pyproject-build-systems }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        hostPkgs = nixpkgs.legacyPackages.${system};
        sbomnixPkgs = sbomnix.packages.${system};

        targetPkgsAmd64 = nixpkgs.legacyPackages.x86_64-linux;
        targetPkgsArm64 = nixpkgs.legacyPackages.aarch64-linux;
        # this is only done to satisfy the expected structure in the container hardening work
        binaries = import ./nix/devguard.nix { buildGoModule = hostPkgs.buildGoModule; inherit self; };
        ociImagesAmd64 = import ./nix/oci.nix { pkgs = targetPkgsAmd64; inherit self pyproject-nix uv2nix pyproject-build-systems; };
        ociImagesArm64 = import ./nix/oci.nix { pkgs = targetPkgsArm64; inherit self pyproject-nix uv2nix pyproject-build-systems; };

        amd64Dependencies = [
          ociImagesAmd64.craneFromSource
          ociImagesAmd64.gitleaksFromSource
          ociImagesAmd64.trivyFromSource
        ];

        arm64Dependencies = [
          ociImagesArm64.craneFromSource
          ociImagesArm64.gitleaksFromSource
          ociImagesArm64.trivyFromSource
        ];

        commonBuildOutputs = {
          devguardScanner = binaries.devguardScanner;
          devguard = binaries.devguard;
          devguardCLI = binaries.devguardCLI;
        };

        arm64Packages = {
          devguard-0-arm64 = ociImagesArm64.devguardOCI;
          devguard-scanner-0-arm64 = ociImagesArm64.devguardScannerOCI;
          postgresql-0-arm64 = ociImagesArm64.postgresqlOCI;
          deps = hostPkgs.symlinkJoin {
            name = "devguard-deps-arm64";
            paths = arm64Dependencies ++ [ ociImagesArm64.pythonTools.venv ];
          };
        } // commonBuildOutputs;

        amd64Packages =  {
          # those are binaries compiled for the host platform         
          devguard-0-amd64 = ociImagesAmd64.devguardOCI;
          devguard-scanner-0-amd64 = ociImagesAmd64.devguardScannerOCI;
          postgresql-0-amd64 = ociImagesAmd64.postgresqlOCI;

          deps = hostPkgs.symlinkJoin {
            name = "devguard-deps-amd64";
            paths = amd64Dependencies ++ [ ociImagesAmd64.pythonTools.venv ];
          };
        } // commonBuildOutputs;

      in {
        packages = if system == "aarch64-linux" then arm64Packages else if system == "x86_64-linux" then amd64Packages else if system == "aarch64-darwin" then arm64Packages else if system == "x86_64-darwin" then amd64Packages else commonBuildOutputs;

        devShells.default =
          hostPkgs.mkShell { buildInputs = [ hostPkgs.go hostPkgs.gotools hostPkgs.gopls binaries.devguardScanner binaries.devguardCli ]; };
      });
}
