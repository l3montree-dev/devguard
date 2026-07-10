{
  buildGoModule, lib, self, system,
  # optional: only needed to build devguardScannerSBOM (passed explicitly
  # from oci.nix). The plain "binaries" call site in flake.nix never
  # references that attribute, so it's fine for these to stay null there.
  runCommand ? null, jq ? null, trivy ? null,
}: rec {
  common = import ./common.nix { inherit self; };
  ldflags = [
    "-s"
    "-w"
    "-X github.com/l3montree-dev/devguard/config.Version=${common.version}"
    "-X github.com/l3montree-dev/devguard/config.Commit=${common.commit}"
    "-X github.com/l3montree-dev/devguard/config.Branch=main"
    "-X github.com/l3montree-dev/devguard/config.BuildDate=${common.buildDate}"
  ];

  # Only include files that affect the Go build output — Go sources, modules,
  # vendored deps, and directories used by //go:embed directives.
  # Excludes nix/, flake.nix, docs, etc. so those changes don't bust the cache.
  src = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      ../go.mod
      ../go.sum
      (lib.fileset.fileFilter (f: f.hasExt "go") ../.)
      # go:embed assets
      ../database/migrations
      ../licenses
      ../compliance/attestation-compliance-policies
      ../normalize/package_mappings.json
      ../integrations/commonint/templates
      ../controllers/report-templates
      ../vulndb/cosign.pub
    ];
  };

  # Shared build arguments for all three binaries.
  commonArgs = {
    inherit src;
    # vendorHash differs per OS because `go mod vendor` applies build constraints.
    vendorHash = if lib.hasSuffix "-darwin" system
      then "sha256-2cJvRo6sFUDI+MBDIBTyIcHmg8XN4e6jL7JqkYcWMu8="
      else "sha256-7B3fHKAqeIAulMiJWzD62gTNu6O7+5BdyHc+aYOsgPY=";
    inherit ldflags;
    buildFlags =
      [ "-trimpath" ]; # compiler-level flag, mirrors Makefile FLAGS
    doCheck = false;
    env = {
      CGO_ENABLED = 0; # static binary, no cgo
    };
  };

  devguardScanner = buildGoModule (commonArgs // {
    pname = "devguard-scanner";
    version = common.version;
    subPackages = [ "cmd/devguard-scanner" ];
  });

  devguard = buildGoModule (commonArgs // {
    pname = "devguard";
    version = common.version;
    subPackages = [ "cmd/devguard" ];
  });

  devguardCLI = buildGoModule (commonArgs // {
    pname = "devguard-cli";
    version = common.version;
    subPackages = [ "cmd/devguard-cli" ];
  });

  # devguard-scanner ends up scanning devguard's own images, and trivy
  # detects each of these compiled binaries the same way it detects
  # gitleaks/trivy/crane's - an unresolved "application" stub plus a
  # versionless main-module reference (same root cause as gitleaks.nix
  # documents: no VCS stamping for a locally-built binary). One supplementary
  # SBOM per binary fixes both, the same way.
  #
  # Two separate derivations, not one bundling all three: devguardScanner
  # ships alone in the scanner image, devguard+devguardCLI ship together in
  # the api-server image - the two images don't share binaries, so bundling
  # all three together would ship each image SBOM data describing a binary
  # that isn't even present in it.
  mkToolSBOM = import ./sbom-lib.nix { inherit lib runCommand jq; } { inherit trivy; };

  devguardScannerSBOM = mkToolSBOM {
    toolName = "devguard-scanner";
    inherit src;
    version = common.version;
    modulePurl = "pkg:golang/github.com/l3montree-dev/devguard";
    binaries = [{ name = "devguard-scanner"; binPath = "${devguardScanner}/bin/devguard-scanner"; }];
  };

  devguardSBOM = mkToolSBOM {
    toolName = "devguard-api";
    inherit src;
    version = common.version;
    modulePurl = "pkg:golang/github.com/l3montree-dev/devguard";
    binaries = [
      { name = "devguard"; binPath = "${devguard}/bin/devguard"; }
    ];
  };

  devguardCLISBOM = mkToolSBOM {
    toolName = "devguard-cli";
    inherit src;
    version = common.version;
    modulePurl = "pkg:golang/github.com/l3montree-dev/devguard";
    binaries = [{ name = "devguard-cli"; binPath = "${devguardCLI}/bin/devguard-cli"; }];
  };
}
