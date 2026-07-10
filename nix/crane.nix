# Upstream nixpkgs definition:
# https://github.com/NixOS/nixpkgs/blob/nixos-25.11/pkgs/by-name/go/go-containerregistry/package.nix
{ lib, buildGoModule, fetchFromGitHub, installShellFiles, runCommand, jq, trivy }:

let
  pname = "crane";
  version = "0.21.5";
  modulePurl = "pkg:golang/github.com/google/go-containerregistry";

  src = fetchFromGitHub {
    owner = "google";
    repo = "go-containerregistry";
    rev = "v${version}";
    hash = "sha256-2cC2fZe22K8mPIXa8YI1MgUlEn6p1z7RBEQhFjYNsxA=";
  };

  package = buildGoModule {
    inherit pname version src;

    # Source tree includes a vendor/ directory.
    vendorHash = null;

    subPackages = [ "cmd/crane" ];

    ldflags = [
      "-s"
      "-w"
      "-X github.com/google/go-containerregistry/cmd/crane/cmd.Version=v${version}"
      "-X github.com/google/go-containerregistry/internal/version.Version=${version}"
    ];
    env = { CGO_ENABLED = 0; };
    nativeBuildInputs = [ installShellFiles ];

    postInstall = "";

    doCheck = false;

    meta = with lib; {
      description = "A tool for interacting with remote images and registries";
      homepage = "https://github.com/google/go-containerregistry";
      license = licenses.asl20;
      mainProgram = "crane";
    };
  };

  mkToolSBOM = import ./sbom-lib.nix { inherit lib runCommand jq; } { inherit trivy; };
in
{
  inherit package;

  sbom = mkToolSBOM {
    toolName = "crane";
    inherit src version modulePurl;
    binaries = [{ name = "crane"; binPath = "${package}/bin/crane"; }];
  };
}
