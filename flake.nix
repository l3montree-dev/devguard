{
  description = "DevGuard";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";
    flake-utils.url = "github:numtide/flake-utils";
    # sbomnix walks the full Nix derivation graph (build + runtime closure)
    # and emits CycloneDX / SPDX SBOMs — including the Go compiler, stdlib,
    # every build tool, and all Go module dependencies.
    sbomnix.url = "github:tiiuae/sbomnix";
    sbomnix.inputs.nixpkgs.follows = "nixpkgs"; # share the same nixpkgs pin
  };

  outputs = { self, nixpkgs, flake-utils, sbomnix }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        # Host packages — used for the dev shell and SBOM scripts that run
        # directly on the developer's machine.
        pkgs = nixpkgs.legacyPackages.${system};
        sbomnixPkgs = sbomnix.packages.${system};

        linuxSystem = builtins.replaceStrings ["darwin"] ["linux"] system;

        # OCI images always target linux kernels, regardless of the architecture.
        # On macOS a remote Linux builder is required; configure one via
        # nix-darwin's linux-builder or ~/.config/nix/nix.conf `builders`.
        pkgsLinux = nixpkgs.legacyPackages.${linuxSystem};

        # --- version metadata (mirrors Makefile ldflags) ---
        version = self.shortRev or self.dirtyShortRev or "dev";
        commit = self.rev or self.dirtyRev or "unknown";
        buildDate = "1970-01-01T00:00:00+0000"; # fixed → reproducible layers

        # -trimpath is a go build flag, NOT a linker flag — keep it out of ldflags.
        ldflags = [
          "-s"
          "-w"
          "-X github.com/l3montree-dev/devguard/config.Version=${version}"
          "-X github.com/l3montree-dev/devguard/config.Commit=${commit}"
          "-X github.com/l3montree-dev/devguard/config.Branch=main"
          "-X github.com/l3montree-dev/devguard/config.BuildDate=${buildDate}"
        ];

        # Shared build arguments for all three binaries.
        commonArgs = {
          src = ./.;
          vendorHash = "sha256-gTD/NuT2bL6z5o+aG0PAE5BNxsoKfcW27Yio8pwLBhc=";
          inherit ldflags;
          buildFlags =
            [ "-trimpath" ]; # compiler-level flag, mirrors Makefile FLAGS
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

        devguardCLI = pkgs.buildGoModule (commonArgs // {
          pname = "devguard-cli";
          inherit version;
          subPackages = [ "cmd/devguard-cli" ];
        });

        devguardScanner = pkgs.buildGoModule (commonArgs // {
          pname = "devguard-scanner";
          inherit version;
          subPackages = [ "cmd/devguard-scanner" ];
        });

        # ---------------------------------------------------------------------------
        # Linux ELF binaries (x86_64-linux) — for OCI image contents only.
        # ---------------------------------------------------------------------------
        devguardLinux = pkgsLinux.buildGoModule (commonArgs // {
          pname = "devguard";
          inherit version;
          subPackages = [ "cmd/devguard" ];
        });

        devguardCLILinux = pkgsLinux.buildGoModule (commonArgs // {
          pname = "devguard-cli";
          inherit version;
          subPackages = [ "cmd/devguard-cli" ];
        });

        devguardScannerLinux = pkgsLinux.buildGoModule (commonArgs // {
          pname = "devguard-scanner";
          inherit version;
          subPackages = [ "cmd/devguard-scanner" ];
        });

        # ---------------------------------------------------------------------------
        # Third-party tools built from source — used in the scanner OCI image.
        # ---------------------------------------------------------------------------
        craneFromSource    = pkgsLinux.callPackage ./nix/crane.nix {};
        gitleaksFromSource = pkgsLinux.callPackage ./nix/gitleaks.nix {};
        trivyFromSource    = pkgsLinux.callPackage ./nix/trivy.nix {};
        # Single Python env containing semgrep + checkov.
        # semgrep-core is the pre-built OCaml binary distributed via nixpkgs;
        # the Python CLI and checkov are compiled from source.
        pythonTools        = pkgsLinux.callPackage ./nix/python-tools.nix {};
        postgresqlWithExts    = pkgsLinux.callPackage ./nix/postgresql.nix {};
        postgresqlEntrypoint  = pkgsLinux.callPackage ./nix/postgresql-entrypoint.nix {};
        postgresqlConfig = pkgsLinux.runCommand "postgresql-config" {} ''
          install -D -m 0644 ${./nix/postgresql.conf} $out/etc/postgresql/postgresql.conf
        '';

        # Runtime config files — arch-independent data, built with pkgsLinux so
        # the store path stays within the Linux closure.
        appConfig = pkgsLinux.runCommand "devguard-app-config" { } ''
          install -D -m 0644 ${
            ./config/rbac_model.conf
          } $out/app/config/rbac_model.conf
          install -D -m 0644 ${
            ./intoto-public-key.pem
          }  $out/app/intoto-public-key.pem
          install -D -m 0644 ${./cosign.pub}             $out/app/cosign.pub
        '';

        # ---------------------------------------------------------------------------
        # OCI images — all contents are Linux ELF; images load on any Docker host.
        # ---------------------------------------------------------------------------
        devguardOCI = pkgsLinux.dockerTools.buildLayeredImage {
          name = "devguard";
          tag = version;

          contents = [
            pkgsLinux.cacert  # TLS root certificates (needed for outbound HTTPS)
            devguardLinux
            devguardCLILinux
            appConfig
          ];

          config = {
            Cmd = [ "/bin/devguard" ];
            WorkingDir = "/app";
            User = "53111:53111";
            Env = [ "SSL_CERT_FILE=/etc/ssl/certs/ca-bundle.crt" ];
          };
        };

        devguardScannerOCI = pkgsLinux.dockerTools.buildLayeredImage {
          name = "devguard-scanner";
          tag = version;

          contents = [
            pkgsLinux.cacert  # TLS root certificates (needed for outbound HTTPS)
            devguardScannerLinux
            trivyFromSource
            pythonTools       # semgrep + checkov in one Python env
            craneFromSource
            gitleaksFromSource
          ];

          fakeRootCommands = ''
            mkdir -p tmp
            chmod 1777 tmp
          '';

          enableFakechroot = true;

          config = {
            Cmd = [ "/bin/devguard-scanner" ];
            User = "53111:53111";
            Env = [ "SSL_CERT_FILE=/etc/ssl/certs/ca-bundle.crt" "EIO_BACKEND=posix" ];
          };
        };

        devguardPostgresqlOCI = pkgsLinux.dockerTools.buildLayeredImage {
          name = "devguard-postgresql";
          tag = "16";

          contents = [
            pkgsLinux.cacert
            pkgsLinux.glibcLocales  # en_US.UTF-8 locale support
            postgresqlWithExts
            postgresqlEntrypoint
            postgresqlConfig      # postgresql.conf
            pkgsLinux.bash
            pkgsLinux.coreutils
          ];

          # Create the postgres user (uid/gid 999, matching the official image),
          # the data directory, and the unix socket directory.
          fakeRootCommands = ''
            mkdir -p etc
            echo 'postgres:x:999:999:PostgreSQL Server:/var/lib/postgresql:/bin/bash' \
              >> etc/passwd
            echo 'postgres:x:999:' >> etc/group
            mkdir -p var/lib/postgresql/data
            mkdir -p var/run/postgresql
            chown -R 999:999 var/lib/postgresql var/run/postgresql
          '';
          enableFakechroot = true;

          config = {
            Entrypoint = [ "/bin/docker-entrypoint.sh" ];
            Cmd = [ "postgres" "-c" "config_file=/etc/postgresql/postgresql.conf" ];
            User = "999:999";
            Env = [
              "LANG=en_US.UTF-8"
              "LC_ALL=en_US.UTF-8"
              "PGDATA=/var/lib/postgresql/data"
              "SSL_CERT_FILE=/etc/ssl/certs/ca-bundle.crt"
              # Tell glibc where the locale archive is inside the Nix store.
              "LOCALE_ARCHIVE=${pkgsLinux.glibcLocales}/lib/locale/locale-archive"
            ];
            Volumes = { "/var/lib/postgresql/data" = {}; };
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
        sbomRuntime = let
            outFile = "devguard-sbom.cdx.json";
            purl = "pkg:golang/github.com/l3montree-dev/devguard@${version}";
          in pkgs.writeShellApplication {
            name = "sbomRuntime";
            runtimeInputs = [
              pkgs.trivy # Go modules  → CycloneDX
            ];
            text = ''
              set -euo pipefail
              tmp=$(mktemp -d)
              trap 'rm -rf "$tmp"' EXIT
             
              trivy fs \
                --format cyclonedx \
                --quiet \
                --output "${outFile}" \
                .
            '';
          };

        sbomBuildtime = let
            outFile = "devguard-sbom-buildtime.cdx.json";
            purl = "pkg:golang/github.com/l3montree-dev/devguard@${version}";
          in pkgs.writeShellApplication {
            name = "sbomBuildtime";
            runtimeInputs = [
              sbomnixPkgs.sbomnix # Nix closure → CycloneDX
              pkgs.trivy # Go modules  → CycloneDX
              devguardScanner # merge-sboms  → merged CycloneDX
              pkgs.jq # build merge config JSON
            ];
            text = ''
              set -euo pipefail
              tmp=$(mktemp -d)
              trap 'rm -rf "$tmp"' EXIT

              echo "[1/3] Nix closure SBOM"
              
              store_path=$(nix path-info --derivation .#devguard)

              sbomnix "$store_path" --buildtime --cdx="$tmp/nix.cdx.json"

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

        # PostgreSQL has no Go modules — SBOM is the Nix closure only.
        sbomPostgresqlRuntime = let
            outFile = "devguard-postgresql-sbom.cdx.json";
          in pkgs.writeShellApplication {
            name = "sbomPostgresqlRuntime";
            runtimeInputs = [ sbomnixPkgs.sbomnix ];
            text = ''
              set -euo pipefail
              store_path=$(nix path-info .#devguardPostgresqlOCI)
              sbomnix "$store_path" --cdx="${outFile}"
              echo "Done: ${outFile}"
            '';
          };

        sbomPostgresqlBuildtime = let
            outFile = "devguard-postgresql-sbom-buildtime.cdx.json";
          in pkgs.writeShellApplication {
            name = "sbomPostgresqlBuildtime";
            runtimeInputs = [ sbomnixPkgs.sbomnix ];
            text = ''
              set -euo pipefail
              store_path=$(nix path-info --derivation .#devguardPostgresqlOCI)
              sbomnix "$store_path" --buildtime --cdx="${outFile}"
              echo "Done: ${outFile}"
            '';
          };

      in {
        packages = {
          inherit devguard devguardCLI devguardScanner devguardOCI
            devguardScannerOCI devguardPostgresqlOCI
            sbomRuntime sbomBuildtime
            sbomPostgresqlRuntime sbomPostgresqlBuildtime;
          default = devguardOCI;
        };

        apps = {
          sbom-runtime = {
            type = "app";
            program = "${sbomRuntime}/bin/sbomRuntime";
          };
          sbom-buildtime = {
            type = "app";
            program = "${sbomBuildtime}/bin/sbomBuildtime";
          };
          sbom-postgresql-runtime = {
            type = "app";
            program = "${sbomPostgresqlRuntime}/bin/sbomPostgresqlRuntime";
          };
          sbom-postgresql-buildtime = {
            type = "app";
            program = "${sbomPostgresqlBuildtime}/bin/sbomPostgresqlBuildtime";
          };
        };

        devShells.default =
          pkgs.mkShell { buildInputs = [ pkgs.go pkgs.gotools pkgs.gopls devguardScanner devguardCLI ]; };
      });
}
