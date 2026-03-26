# PostgreSQL 16 with the pg-semver extension.
#
# Upstream nixpkgs definitions:
#   https://github.com/NixOS/nixpkgs/blob/nixos-25.11/pkgs/servers/sql/postgresql/default.nix
#   https://github.com/NixOS/nixpkgs/blob/nixos-25.11/pkgs/servers/sql/postgresql/ext/pg-semver.nix
{ postgresql_16 }:

postgresql_16.withPackages (p: [ p.pg-semver ])
