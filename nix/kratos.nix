{
  buildGoModule,
  lib,
  fetchFromGitHub,
  go,
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

  # Transitive Go module versions to force via `go mod edit -replace`, keyed
  # by module path. Upstream kratos may still pin older, vulnerable versions.
  goModPatches = {
    "golang.org/x/crypto" = "v0.55.0";
    "golang.org/x/net" = "v0.55.0";
    "github.com/jackc/pgx/v5" = "v5.10.0";
    "github.com/go-jose/go-jose/v4" = "v4.1.4";
    "github.com/go-jose/go-jose/v3" = "v3.0.5";
    "go.opentelemetry.io/otel/sdk" = "v1.45.0";
    "go.opentelemetry.io/otel" = "v1.45.0";
    "google.golang.org/grpc" = "v1.83.1";
    "go.mongodb.org/mongo-driver" = "v1.17.9";
    "go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp" = "v1.45.0";
    "github.com/slack-go/slack" = "v0.29.0";
  };

  goModPatchScript = lib.concatStringsSep "\n" (
    lib.mapAttrsToList (
      modulePath: ver: "go mod edit -replace ${modulePath}=${modulePath}@${ver}"
    ) goModPatches
  );

  # Only include files that affect the Go build output — Go sources, modules,
  # vendored deps, and directories used by //go:embed directives.
  # Excludes nix/, flake.nix, docs, etc. so those changes don't bust the cache.
  src = fetchFromGitHub {
    owner = "ory";
    repo = "kratos";
    rev = version;
    hash = "sha256-u298vFFD/zc7ScdQ5rmvcHqkMMenMVIRC9GChfukml8=";
  };

  kratos =
    (buildGoModule {
      pname = "kratos";
      inherit version src ldflags;
      # Fetch modules via the Go module proxy instead of vendoring: a plain
      # `go mod vendor` tree only records resolved versions (vendor/modules.txt),
      # not which module requires which, so it can't give the supplementary
      # SBOMs below (see sbom-lib.nix) a real transitive dependency tree -
      # a `go mod download`-style module cache has each dependency's own
      # go.mod, which is what's actually needed.
      proxyVendor = true;
      vendorHash = "sha256-52aCWgaBC/RkR2Oi67Gx53q4B6xkwl1YjZGIn3jJEkA=";
      buildFlags = [ "-trimpath" ]; # compiler-level flag, mirrors Makefile FLAGS
      doCheck = false;
      env = {
        CGO_ENABLED = 0; # static binary, no cgo
      };
      subPackages = [ "." ];

      # buildGoModule's goModules (module-download FOD) inherits this same
      # postPatch automatically, so the replace lands in both the actual
      # build's go.mod and the module set that gets fetched - no separate
      # overrideModAttrs needed.
      postPatch = goModPatchScript;
    }).overrideAttrs
      (old: {
        # go.mod's replace directive above means go.sum is missing entries
        # for the replaced version, and the default -mod=readonly refuses to
        # add them. Still fully offline: GOPROXY is pointed at the
        # already-fetched local module set and GOSUMDB=off (both set in
        # buildGoModule's configurePhase), so Go computes the missing
        # checksums from local content only.
        env = old.env // {
          GOFLAGS = "${old.env.GOFLAGS} -mod=mod";
        };
      });

  mkToolSBOM = (import ./sbom-lib.nix { inherit lib runCommand jq; }).mkToolSBOM { inherit trivy; };

  kratosSBOM = mkToolSBOM {
    toolName = "kratos";
    inherit src version;
    inherit (kratos) goModules;
    # Same replace as the actual build, so the SBOM reports what's actually
    # shipped instead of the pre-patch versions.
    postPatch =
      goModPatchScript # kratos embeds other Go modules as subdirectories (e.g. oryx/,
      # pkg/client-go/, test/e2e/*), each with its own go.mod/go.sum. Only ./
      # (the root module) is what actually gets built or should show up in the
      # SBOM - remove the rest so tooling (go mod edit above, and later the
      # SBOM's trivy scan) only ever sees one module boundary.
      + ''

        find . -mindepth 2 \( -name go.mod -o -name go.sum \) -delete
      '';
    extraNativeBuildInputs = [ go ];
    modulePurl = "pkg:golang/github.com/ory/kratos";
    binaries = [
      {
        name = "kratos";
        binPath = "${kratos}/bin/kratos";
      }
    ];
  };
}
