# Upstream nixpkgs definition:
# https://github.com/NixOS/nixpkgs/blob/nixos-25.11/pkgs/by-name/tr/trivy/package.nix
{
  pkgs,
  buildGo127Module ? pkgs.buildGo127Module,
}:

let
  pname = "trivy";
  version = "0.75.0";
  modulePurl = "pkg:golang/github.com/aquasecurity/trivy";

  src = pkgs.fetchFromGitHub {
    owner = "aquasecurity";
    repo = "trivy";
    rev = "v${version}";
    hash = "sha256-z0QMnaHSoHR2eHFFWOFHn7EJV0QfQYSSTQ4Q7Q31QbQ=";
  };

  package = buildGo127Module {
    inherit pname version src;

    # vendor hash differs across Linux and Darwin builds — bypass the source
    # vendor dir entirely and fetch modules via the Go module proxy.
    proxyVendor = true;
    vendorHash = "sha256-idc2wjjPVTRW9cImD/o40I+xdSzDwO7vEv2SB03FYl0=";

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

    nativeBuildInputs = [ pkgs.installShellFiles ];

    postInstall = "";

    doCheck = false;

    meta = {
      description = "A comprehensive and versatile security scanner";
      homepage = "https://github.com/aquasecurity/trivy";
      license = pkgs.lib.licenses.asl20;
      mainProgram = "trivy";
    };
  };

  # Uses its own freshly-built binary to scan its own source - no external
  # trivy dependency needed, unlike gitleaks.nix/crane.nix.
  mkToolSBOM = (import ./sbom-lib.nix { inherit (pkgs) lib runCommand jq; }).mkToolSBOM {
    trivy = package;
  };

  # Trivy's own repo is full of testdata fixtures for its analyzer tests
  # (poetry.lock, package-lock.json, go.mod, ...) pinned to arbitrary,
  # sometimes vulnerable versions. Left in, `trivy fs` reports them as real
  # dependencies of the trivy binary itself. Excluded from the SBOM scan
  # source only - the actual build still uses the unfiltered `src`.
  # Another issue is that since we are not having sbom merkle trees implemented in devguard, this will override any patches we are doing to python packages (https://github.com/l3montree-dev/devguard/issues/2780)
  sbomSrc = pkgs.lib.cleanSourceWith {
    inherit src;
    filter = path: _type: builtins.match ".*/testdata(/.*)?" path == null;
  };
in
{
  inherit package;

  sbom = mkToolSBOM {
    toolName = "trivy";
    src = sbomSrc;
    inherit version modulePurl;
    inherit (package) goModules;
    binaries = [
      {
        name = "trivy";
        binPath = "${package}/bin/trivy";
      }
    ];
  };
}
