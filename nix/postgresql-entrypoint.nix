# Entrypoint script taken verbatim from the official docker-library/postgres image.
# https://github.com/docker-library/postgres/blob/master/16/bookworm/docker-entrypoint.sh
#
# The script is designed to be PATH-agnostic: it calls initdb, pg_ctl, psql,
# and postgres by name. Our OCI image includes postgresql16 in its closure, so
# all those binaries are available on PATH automatically.
{ fetchurl, stdenv }:

stdenv.mkDerivation {
  name = "docker-entrypoint";

  src = fetchurl {
    url = "https://raw.githubusercontent.com/docker-library/postgres/master/16/bookworm/docker-entrypoint.sh";
    hash = "sha256-Gm/1aMecuEfP/EFysiofUBzvBQAbCwl1H0gyNoP7ZKI=";
  };

  dontUnpack = true;

  installPhase = ''
    install -D -m 0755 $src $out/bin/docker-entrypoint.sh
  '';
}
