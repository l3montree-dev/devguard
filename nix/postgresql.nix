# PostgreSQL 16 with the pg-semver extension.
#
# Upstream nixpkgs definitions:
#   https://github.com/NixOS/nixpkgs/blob/nixos-25.11/pkgs/servers/sql/postgresql/default.nix
#   https://github.com/NixOS/nixpkgs/blob/nixos-25.11/pkgs/servers/sql/postgresql/ext/pg-semver.nix
{
  lib,
  postgresql_16,
  fetchurl,
  stdenv,
  runCommand,
  jq,
}:
rec {
  psql = postgresql_16.withPackages (p: [ p.pg-semver ]);

  entrypoint = stdenv.mkDerivation {
    name = "docker-entrypoint";
    src = fetchurl {
      url = "https://raw.githubusercontent.com/docker-library/postgres/master/16/bookworm/docker-entrypoint.sh";
      hash = "sha256-nEQCma4EoKedVbi/AzBwNtiQpAl50vtpgHPJBQ1LIKU=";
    };
    dontUnpack = true;
    installPhase = ''
      install -D -m 0755 $src $out/bin/docker-entrypoint.sh
    '';
  };

  config = runCommand "postgresql-config" { } ''
    install -D -m 0644 ${./postgresql.conf} $out/etc/postgresql/postgresql.conf
  '';


  version = "16.15-r0";
  sbom = (import ./sbom-lib.nix { inherit lib runCommand jq; }).mkHandwrittenSBOM {
    name = "postgresql16";
    inherit version;
    # we just use the alpine postgresql purl - there are CVEs tracked against this package under that identity, and we want to match them
    purl = "pkg:apk/alpine/postgresql16@${version}?arch=source&distro=3.22.2";
  };
}
