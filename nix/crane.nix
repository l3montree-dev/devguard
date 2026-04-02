# Upstream nixpkgs definition:
# https://github.com/NixOS/nixpkgs/blob/nixos-25.11/pkgs/by-name/go/go-containerregistry/package.nix
{ lib, buildGoModule, fetchFromGitHub, installShellFiles }:

buildGoModule rec {
  pname = "crane";
  version = "0.21.3";

  src = fetchFromGitHub {
    owner = "google";
    repo = "go-containerregistry";
    rev = "v${version}";
    hash = "sha256-BfKiBjfL5th1TPpw6hpno04MffLnXmOVq7BsGUCkPT0=";
  };

  # Source tree includes a vendor/ directory.
  vendorHash = null;

  subPackages = [
    "cmd/crane"
    "cmd/gcrane"
  ];

  ldflags = [
    "-s"
    "-w"
    "-X github.com/google/go-containerregistry/cmd/crane/cmd.Version=v${version}"
    "-X github.com/google/go-containerregistry/internal/version.Version=${version}"
  ];

  nativeBuildInputs = [ installShellFiles ];

  postInstall = "";

  doCheck = false;

  meta = with lib; {
    description = "A tool for interacting with remote images and registries";
    homepage = "https://github.com/google/go-containerregistry";
    license = licenses.asl20;
    mainProgram = "crane";
  };
}
