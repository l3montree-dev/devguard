{
  description = "DevGuard — build minimal OCI image with Nix";

  inputs = {
    nixpkgs.url    = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    # sbomnix walks the full Nix derivation graph (build + runtime closure)
    # and emits CycloneDX / SPDX SBOMs — including the Go compiler, stdlib,
    # every build tool, and all Go module dependencies.
    sbomnix.url    = "github:tiiuae/sbomnix";
    sbomnix.inputs.nixpkgs.follows = "nixpkgs"; # share the same nixpkgs pin
  };

  outputs = { self, nixpkgs, flake-utils, sbomnix }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs      = nixpkgs.legacyPackages.${system};
        sbomnixPkgs = sbomnix.packages.${system};

        # --- version metadata (mirrors Makefile ldflags) ---
        version   = self.shortRev or self.dirtyShortRev or "dev";
        commit    = self.rev    or self.dirtyRev    or "unknown";
        buildDate = "1970-01-01T00:00:00+0000"; # fixed → reproducible layers

        # -trimpath is a go build flag, NOT a linker flag — keep it out of ldflags.
        ldflags = [
          "-s" "-w"
          "-X github.com/l3montree-dev/devguard/config.Version=${version}"
          "-X github.com/l3montree-dev/devguard/config.Commit=${commit}"
          "-X github.com/l3montree-dev/devguard/config.Branch=main"
          "-X github.com/l3montree-dev/devguard/config.BuildDate=${buildDate}"
        ];

        # Shared build arguments for both binaries.
        commonArgs = {
          src = ./.;
          vendorHash = "sha256-acYlXXbc41EdGblw8azOHUmD73c+xuGla8r5mlAXwyQ=";
          inherit ldflags;
          buildFlags = [ "-trimpath" ]; # compiler-level flag, mirrors Makefile FLAGS
          doCheck = false;
          env = {
            CGO_ENABLED = 0; # static binary, no cgo
          };
        };

        devguard = pkgs.buildGoModule (commonArgs // {
          pname = "devguard";
          inherit version;
          subPackages = [ "cmd/devguard" ];
        });

        devguard-cli = pkgs.buildGoModule (commonArgs // {
          pname = "devguard-cli";
          inherit version;
          subPackages = [ "cmd/devguard-cli" ];
        });

        devguard-scanner = pkgs.buildGoModule (commonArgs // {
          pname = "devguard-scanner";
          inherit version;
          subPackages = [ "cmd/devguard-scanner" ];
        });

        # --- minimal OCI / Docker image ---
        dockerImage = pkgs.dockerTools.buildLayeredImage {
          name = "devguard";
          tag  = version;

          # Only what is strictly necessary goes into the image.
          contents = [
            # TLS root certificates (needed for outbound HTTPS)
            pkgs.cacert
            devguard
            devguard-cli
          ];

          # Copy the runtime config files that the app expects under /app.
          fakeRootCommands = ''
            install -D -m 0644 ${./config/rbac_model.conf}   /app/config/rbac_model.conf
            install -D -m 0644 ${./intoto-public-key.pem}    /app/intoto-public-key.pem
            install -D -m 0644 ${./cosign.pub}               /app/cosign.pub
          '';

          config = {
            Cmd        = [ "/bin/devguard" ];
            WorkingDir = "/app";
            User       = "53111:53111";
            Env = [
              "SSL_CERT_FILE=/etc/ssl/certs/ca-bundle.crt"
            ];
          };
        };

        # --- SBOM generation scripts ---
        #
        # Each script merges two layers into one CycloneDX file:
        #   Layer 1 (sbomnix): Nix closure — Go compiler, toolchain, libc, …
        #   Layer 2 (trivy):   Go modules  — every entry in go.mod/go.sum
        #
        # trivy scans the whole repo root (single go.mod), so it captures
        # dependencies of all three binaries (devguard, devguard-cli,
        # devguard-scanner) regardless of which SBOM type is being produced.
        #
        # Merge is done with devguard-scanner merge-sboms which expects a JSON
        # config: { "purl": "...", "sboms": ["a.json", "b.json"] }
        #
        # nix run .#sbom-runtime   → container contents + all Go modules
        # nix run .#sbom-buildtime → full Nix closure (Go compiler etc.) + all Go modules
        mkFullSbom = type:
          let
            nixFlag = if type == "buildtime" then "--buildtime" else "";
            outFile = "devguard-sbom-${type}.cdx.json";
            purl    = "pkg:golang/github.com/l3montree-dev/devguard@${version}";
          in pkgs.writeShellApplication {
            name = "sbom-${type}";
            runtimeInputs = [
              sbomnixPkgs.sbomnix   # Nix closure → CycloneDX
              pkgs.trivy            # Go modules  → CycloneDX
              devguard-scanner      # merge-sboms  → merged CycloneDX
              pkgs.jq               # build merge config JSON
            ];
            text = ''
              set -euo pipefail
              tmp=$(mktemp -d)
              trap 'rm -rf "$tmp"' EXIT

              echo "[1/3] Nix closure SBOM (${type})…"
              store_path=$(nix build --no-link --print-out-paths .#devguard 2>/dev/null)
              sbomnix "$store_path" ${nixFlag} --cdx="$tmp/nix.cdx.json"

              echo "[2/3] Go module SBOM (trivy fs)…"
              trivy fs \
                --format cyclonedx \
                --quiet \
                --output "$tmp/gomod.cdx.json" \
                ./

              echo "[3/3] Merging → ${outFile}…"
              jq -n \
                --arg purl "${purl}" \
                --arg a   "$tmp/nix.cdx.json" \
                --arg b   "$tmp/gomod.cdx.json" \
                '{"purl": $purl, "sboms": [$a, $b]}' \
                > "$tmp/merge-config.json"

              devguard-scanner merge-sboms "$tmp/merge-config.json" > "${outFile}"
              echo "Done: ${outFile}"
            '';
          };

        sbomRuntime   = mkFullSbom "runtime";
        sbomBuildtime = mkFullSbom "buildtime";

      in {
        packages = {
          inherit devguard devguard-cli devguard-scanner dockerImage
                  sbomRuntime sbomBuildtime;
          default = dockerImage;
        };

        apps = {
          sbom-runtime = {
            type    = "app";
            program = "${sbomRuntime}/bin/sbom-runtime";
          };
          sbom-buildtime = {
            type    = "app";
            program = "${sbomBuildtime}/bin/sbom-buildtime";
          };
        };

        devShells.default = pkgs.mkShell {
          buildInputs = [
            pkgs.go pkgs.gotools pkgs.gopls
          ];
        };
      }
    );
}
