# Upstream nixpkgs definition:
# https://github.com/NixOS/nixpkgs/blob/nixos-25.11/pkgs/by-name/tr/trivy/package.nix
{ lib, buildGoModule, fetchFromGitHub, installShellFiles, runCommand, jq }:

let
  pname = "trivy";
  version = "0.72.0";
  modulePurl = "pkg:golang/github.com/aquasecurity/trivy";

  src = fetchFromGitHub {
    owner = "aquasecurity";
    repo = "trivy";
    rev = "v${version}";
    hash = "sha256-wlvG8iGPBbHV66SOT0zek2VN1QawksVQwM9LSEItzh4=";
  };

  package = buildGoModule {
    inherit pname version src;

    # vendor hash differs across Linux and Darwin builds — bypass the source
    # vendor dir entirely and fetch modules via the Go module proxy.
    proxyVendor = true;
    vendorHash = "sha256-n5eWyKpG47LuXPzMO+/tzhFs4F+grWQAThCoGEMQ2S8=";

    subPackages = [ "cmd/trivy" ];

    env = {
      GOEXPERIMENT = "jsonv2";
      # aws-sdk-go-v2/service/ec2 is extremely large; compiling it with full
      # parallelism OOM-kills the builder.  Cap to 1 parallel codegen unit.
      GOMAXPROCS = "1";
      CGO_ENABLED = 0;
    };

    ldflags = [
      "-s"
      "-w"
      "-X=github.com/aquasecurity/trivy/pkg/version/app.ver=${version}"
    ];

    nativeBuildInputs = [ installShellFiles ];

    postInstall = "";

    doCheck = false;

    meta = {
      description = "A comprehensive and versatile security scanner";
      homepage = "https://github.com/aquasecurity/trivy";
      license = lib.licenses.asl20;
      mainProgram = "trivy";
    };
  };

  # Uses its own freshly-built binary to scan its own source - no external
  # trivy dependency needed, unlike gitleaks.nix/crane.nix.
  mkToolSBOM = import ./sbom-lib.nix { inherit lib runCommand jq; } { trivy = package; };
in
{
  inherit package;

  sbom = mkToolSBOM {
    toolName = "trivy";
    inherit src version modulePurl;
    goModules = package.goModules;
    binaries = [{ name = "trivy"; binPath = "${package}/bin/trivy"; }];
  };
}
