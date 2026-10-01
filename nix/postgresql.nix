# PostgreSQL 16 with the pg-semver extension.
#
# Upstream nixpkgs definitions:
#   https://github.com/NixOS/nixpkgs/blob/nixos-25.11/pkgs/servers/sql/postgresql/default.nix
#   https://github.com/NixOS/nixpkgs/blob/nixos-25.11/pkgs/servers/sql/postgresql/ext/pg-semver.nix
{
  pkgs,
}:
rec {

  psql = pkgs.symlinkJoin {
    name = "devguard-postgresql-bundle";
    # Fails the build unless every binary CloudNativePG requires (or
    # optionally wants) of a custom PostgreSQL image actually runs:
    # https://cloudnative-pg.io/docs/1.25/container_images/
    postBuild = ''
      # PostgreSQL executables that must be in the path.
      for bin in initdb postgres pg_ctl pg_controldata pg_basebackup; do
        "$out/bin/$bin" --version
      done

      # Barman Cloud executables that must be in the path.
      for bin in barman-cloud-backup \
                 barman-cloud-backup-delete \
                 barman-cloud-backup-list \
                 barman-cloud-check-wal-archive \
                 barman-cloud-restore \
                 barman-cloud-wal-archive \
                 barman-cloud-wal-restore; do
        "$out/bin/$bin" --help
      done

      # PGAudit extension installed (optional - only if PGAudit is required
      # in the deployed clusters).
      if [ ! -e "$out/share/postgresql/extension/pgaudit.control" ]; then
        echo "Missing PGAudit extension: $out/share/postgresql/extension/pgaudit.control"
        exit 1
      fi

      # du (optional, for `kubectl cnpg status`).
      "$out/bin/du" --version

      # Appropriate locale settings.
      "$out/bin/psql" --version
      if [ ! -e "$out/lib/locale/locale-archive" ]; then
        echo "Missing locale archive: $out/lib/locale/locale-archive"
        exit 1
      fi

      # Non-executable files that must be present in the bundle.
      for f in bin/docker-entrypoint.sh \
               bin/bash \
               bin/tar \
               etc/postgresql/postgresql.conf \
               etc/ssl/certs/ca-bundle.crt \
               sboms/postgresql16.json; do
        if [ ! -e "$out/$f" ]; then
          echo "Missing expected file: $out/$f"
          exit 1
        fi
      done
    '';
    paths = [
      pkgs.cacert
      pkgs.glibcLocales # en_US.UTF-8 locale support
      postgresql
      entrypoint
      config
      sbom
      pkgs.bash
      pkgs.coreutils
      pkgs.gnutar
      pkgs.barman
    ];
  };

  postgresql = pkgs.postgresql_16.withPackages (p: [
    p.pg-semver
    p.pgaudit
  ]);

  entrypoint = pkgs.stdenv.mkDerivation {
    name = "docker-entrypoint";
    src = pkgs.fetchurl {
      url = "https://raw.githubusercontent.com/docker-library/postgres/master/16/bookworm/docker-entrypoint.sh";
      hash = "sha256-nEQCma4EoKedVbi/AzBwNtiQpAl50vtpgHPJBQ1LIKU=";
    };
    dontUnpack = true;
    installPhase = ''
      install -D -m 0755 $src $out/bin/docker-entrypoint.sh
    '';
  };

  config = pkgs.runCommand "postgresql-config" { } ''
    install -D -m 0644 ${./postgresql.conf} $out/etc/postgresql/postgresql.conf
  '';

  version = "16.15-r0";
  sbom = (import ./sbom-lib.nix { inherit (pkgs) lib runCommand jq; }).mkHandwrittenSBOM {
    name = "postgresql16";
    inherit version;
    # we just use the alpine postgresql purl - there are CVEs tracked against this package under that identity, and we want to match them
    purl = "pkg:apk/alpine/postgresql16@${version}?arch=source&distro=3.22.2";
  };
}
