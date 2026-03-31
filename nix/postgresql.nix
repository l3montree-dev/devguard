# PostgreSQL 16 with the pg-semver extension.
#
# Upstream nixpkgs definitions:
#   https://github.com/NixOS/nixpkgs/blob/nixos-25.11/pkgs/servers/sql/postgresql/default.nix
#   https://github.com/NixOS/nixpkgs/blob/nixos-25.11/pkgs/servers/sql/postgresql/ext/pg-semver.nix
{ postgresql_16, fetchurl, stdenv, runCommand }: rec {
  psql = postgresql_16.withPackages (p: [ p.pg-semver ]);

  entrypoint = stdenv.mkDerivation {
    name = "docker-entrypoint";
    src = fetchurl {
      url = "https://raw.githubusercontent.com/docker-library/postgres/master/16/bookworm/docker-entrypoint.sh";
      hash = "sha256-Gm/1aMecuEfP/EFysiofUBzvBQAbCwl1H0gyNoP7ZKI=";
    };
    dontUnpack = true;
    installPhase = ''
      install -D -m 0755 $src $out/bin/docker-entrypoint.sh
    '';
  };

  config = runCommand "postgresql-config" {} ''
    install -D -m 0644 ${./postgresql.conf} $out/etc/postgresql/postgresql.conf
  '';
}