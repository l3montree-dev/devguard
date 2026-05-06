{ buildGoModule, lib, self, system }: rec {
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
    ];
  };

  # Shared build arguments for all three binaries.
  commonArgs = {
    inherit src;
    # vendorHash differs per OS because `go mod vendor` applies build constraints.
    vendorHash = if lib.hasSuffix "-darwin" system
      then "sha256-Z36CfY7CqDwnGaeT/3kr8+LL7Uu7Sg0E3nvvnUg8bcM="
      else "sha256-hxKsFo9eeLWcJQxrKGgzMpfzqQxZxk4dzrjTbMIgxMo=";
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
}
