# Upstream nixpkgs definition:
# https://github.com/NixOS/nixpkgs/blob/nixos-25.11/pkgs/by-name/gi/gitleaks/package.nix
{ lib, buildGoModule, fetchFromGitHub, installShellFiles, runCommand, jq, trivy }:

let
  pname = "gitleaks";
  version = "8.30.1";
  modulePurl = "pkg:golang/github.com/zricethezav/gitleaks/v8";

  src = fetchFromGitHub {
    owner = "gitleaks";
    repo = "gitleaks";
    rev = "v${version}";
    hash = "sha256-PpMquYyXNN6KFwN/efY5+gr+4IhSKPoAy2M/rcqfW5k=";
  };

  package = buildGoModule {
    inherit pname version src;

    proxyVendor = true;
    vendorHash = "sha256-FlXL2gyYdAe+n2fxePJu2zogIULIpmsdbikew0Lqx0U=";
    subPackages = [ "." ];

    ldflags = [
      "-s"
      "-w"
      "-X github.com/gitleaks/gitleaks/v8/cmd.Version=v${version}"
    ];

    nativeBuildInputs = [ installShellFiles ];

    postInstall = "";
    env = {
      CGO_ENABLED = 0;
    };

    doCheck = false;

    meta = with lib; {
      description = "Scan git repos (or files) for secrets";
      homepage = "https://github.com/gitleaks/gitleaks";
      license = licenses.mit;
      mainProgram = "gitleaks";
    };
  };

  mkToolSBOM = import ./sbom-lib.nix { inherit lib runCommand jq; } { inherit trivy; };
in
{
  inherit package;

  sbom = mkToolSBOM {
    toolName = "gitleaks";
    inherit src version modulePurl;
    goModules = package.goModules;
    binaries = [{ name = "gitleaks"; binPath = "${package}/bin/gitleaks"; }];
  };
}
