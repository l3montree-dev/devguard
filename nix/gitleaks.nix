# Upstream nixpkgs definition:
# https://github.com/NixOS/nixpkgs/blob/nixos-25.11/pkgs/by-name/gi/gitleaks/package.nix
{ lib, buildGoModule, fetchFromGitHub, installShellFiles }:

buildGoModule rec {
  pname = "gitleaks";
  version = "8.30.1";

  src = fetchFromGitHub {
    owner = "gitleaks";
    repo = "gitleaks";
    rev = "v${version}";
    hash = "sha256-PpMquYyXNN6KFwN/efY5+gr+4IhSKPoAy2M/rcqfW5k=";
  };

  vendorHash = "sha256-whJtl34dNltH/dk9qWSThcCYXC0x9PzbAUOO97Int+k=";

  ldflags = [
    "-s"
    "-w"
    "-X github.com/gitleaks/gitleaks/v8/cmd.Version=v${version}"
  ];

  nativeBuildInputs = [ installShellFiles ];

  postInstall = "";

  doCheck = false;

  meta = with lib; {
    description = "Scan git repos (or files) for secrets";
    homepage = "https://github.com/gitleaks/gitleaks";
    license = licenses.mit;
    mainProgram = "gitleaks";
  };
}
