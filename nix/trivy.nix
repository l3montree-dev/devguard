# Upstream nixpkgs definition:
# https://github.com/NixOS/nixpkgs/blob/nixos-25.11/pkgs/by-name/tr/trivy/package.nix
{ lib, buildGoModule, fetchFromGitHub, installShellFiles }:

buildGoModule rec {
  pname = "trivy";
  version = "0.70.0";

  src = fetchFromGitHub {
    owner = "aquasecurity";
    repo = "trivy";
    rev = "v${version}";
    hash = "sha256-xMj5xA/q3ekMW8k1aHCKa5hsYZSFShghOO5K6MnDCBo=";
  };

  # vendor hash differs across Linux and Darwin builds — bypass the source
  # vendor dir entirely and fetch modules via the Go module proxy.
  proxyVendor = true;
  vendorHash = "sha256-VbkCDzSF8gHxXpzzNxtPVRqUn/4l0AVHNzlsOKmXNG8=";

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
}
