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
      ../compliance
      ../normalize/package_mappings.json
      ../integrations/commonint/templates
      ../controllers/report-templates
      ../vulndb/cosign.pub
    ];
  };

  # Shared build arguments for all three binaries.
  commonArgs = {
    inherit src;
    # Fetch modules via the Go module proxy instead of vendoring: a plain
    # `go mod vendor` tree only records resolved versions (vendor/modules.txt),
    # not which module requires which, so it can't give the supplementary
    # SBOMs below (see sbom-lib.nix) a real transitive dependency tree -
    # a `go mod download`-style module cache has each dependency's own
    # go.mod, which is what's actually needed.
    proxyVendor = true;
    vendorHash = "sha256-SkOEUxAtoVYUFUyWzwpAWCS0yEvtQGFGEA/83R1VN5o=";
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
    goModules = devguardScanner.goModules;
    binaries = [{ name = "devguard-scanner"; binPath = "${devguardScanner}/bin/devguard-scanner"; }];
    externalReferences = [
      {
        type = "exploitability-statement";
        url = "https://api.main.devguard.org/api/v1/public/e1f24270-6e68-4571-9168-9c151c639c97/refs/${common.version}/artifacts/pkg%3Agolang%2Fgithub.com%2Fl3montree-dev%2Fdevguard/csaf.json/";
      }
    ];
  };

  devguardSBOM = mkToolSBOM {
    toolName = "devguard-api";
    inherit src;
    version = common.version;
    modulePurl = "pkg:golang/github.com/l3montree-dev/devguard";
    goModules = devguard.goModules;
    binaries = [
      { name = "devguard"; binPath = "${devguard}/bin/devguard"; }
    ];
  };

  devguardCLISBOM = mkToolSBOM {
    toolName = "devguard-cli";
    inherit src;
    version = common.version;
    modulePurl = "pkg:golang/github.com/l3montree-dev/devguard";
    goModules = devguardCLI.goModules;
    binaries = [{ name = "devguard-cli"; binPath = "${devguardCLI}/bin/devguard-cli"; }];
  };
}
