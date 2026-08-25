{
  buildGoModule,
  lib,
  fetchFromGitHub,
  # optional: only needed to build devguardScannerSBOM (passed explicitly
  # from oci.nix). The plain "binaries" call site in flake.nix never
  # references that attribute, so it's fine for these to stay null there.
  runCommand ? null,
  jq ? null,
  trivy ? null,
}:
rec {
  version = "v26.2.0";
  ldflags = [ ];

  # Only include files that affect the Go build output — Go sources, modules,
  # vendored deps, and directories used by //go:embed directives.
  # Excludes nix/, flake.nix, docs, etc. so those changes don't bust the cache.
  src = fetchFromGitHub {
    owner = "ory";
    repo = "kratos";
    rev = version;
    hash = "sha256-u298vFFD/zc7ScdQ5rmvcHqkMMenMVIRC9GChfukml8=";
  };

  kratos = buildGoModule {
    pname = "kratos";
    inherit version src ldflags;
    # Fetch modules via the Go module proxy instead of vendoring: a plain
    # `go mod vendor` tree only records resolved versions (vendor/modules.txt),
    # not which module requires which, so it can't give the supplementary
    # SBOMs below (see sbom-lib.nix) a real transitive dependency tree -
    # a `go mod download`-style module cache has each dependency's own
    # go.mod, which is what's actually needed.
    proxyVendor = true;
    vendorHash = "sha256-N+iFFTE8vP6BbjgovfifsMwrAA+4SiQgocrKn/867RE=";
    buildFlags = [ "-trimpath" ]; # compiler-level flag, mirrors Makefile FLAGS
    doCheck = false;
    env = {
      CGO_ENABLED = 0; # static binary, no cgo
    };
    subPackages = [ "." ];
  };

  mkToolSBOM = import ./sbom-lib.nix { inherit lib runCommand jq; } { inherit trivy; };

  kratosSBOM = mkToolSBOM {
    toolName = "kratos";
    inherit src version;
    inherit (kratos) goModules;
    modulePurl = "pkg:golang/github.com/ory/kratos";
    binaries = [
      {
        name = "kratos";
        binPath = "${kratos}/bin/kratos";
      }
    ];
  };
}
