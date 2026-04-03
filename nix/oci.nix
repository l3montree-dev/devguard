{ pkgs, self, pyproject-nix, uv2nix, pyproject-build-systems }: rec {
  devguardBinaries = import ./devguard.nix { inherit self; buildGoModule = pkgs.buildGoModule; lib = pkgs.lib; };

  args = { 
    lib = pkgs.lib; 
    buildGoModule = pkgs.buildGoModule; 
    fetchFromGitHub = pkgs.fetchFromGitHub; 
    installShellFiles = pkgs.installShellFiles; 
  };

  craneFromSource = import ./crane.nix args;
  gitleaksFromSource = import ./gitleaks.nix args;
  trivyFromSource = import ./trivy.nix args;
  
  common = import ./common.nix { inherit self; };
  postgresql = import ./postgresql.nix {
    postgresql_16 = pkgs.postgresql_16;
    fetchurl = pkgs.fetchurl;
    stdenv = pkgs.stdenv;
    runCommand = pkgs.runCommand;
  };
  pythonTools = import ./python-tools.nix {
  lib = pkgs.lib;
  python313 = pkgs.python313;
  callPackage = pkgs.callPackage;
  # passed explicitly from flake.nix
  inherit uv2nix pyproject-nix pyproject-build-systems;
  };

  appConfig = pkgs.runCommand "devguard-app-config" { } ''
    install -D -m 0644 ${
      ../config/rbac_model.conf
    } $out/app/config/rbac_model.conf
    install -D -m 0644 ${
      ../intoto-public-key.pem
    }  $out/app/intoto-public-key.pem
    install -D -m 0644 ${../cosign.pub} $out/app/cosign.pub
  '';

  devguardOCI = { debug }: pkgs.dockerTools.buildLayeredImage {
    name = "devguard";
    tag = common.version;

    contents = [
      pkgs.cacert  # TLS root certificates (needed for outbound HTTPS)
      devguardBinaries.devguard
      devguardBinaries.devguardCLI
      appConfig
    ] ++ (if debug then [ pkgs.busybox ] else []);

    config = {
      Cmd = [ "/bin/devguard" ];
      WorkingDir = "/app";
      User = "53111:53111";
      Env = [ "SSL_CERT_FILE=/etc/ssl/certs/ca-bundle.crt" ];
    };
  };

  devguardScannerOCI = pkgs.dockerTools.buildLayeredImage {
    name = "devguard-scanner";
    tag = common.version;
    contents =  [
      pkgs.cacert  # TLS root certificates (needed for outbound HTTPS)
      devguardBinaries.devguardScanner
      trivyFromSource
      pythonTools.venv
      craneFromSource
      gitleaksFromSource
      pkgs.jq
      pkgs.gettext
      pkgs.busybox
    ];

    fakeRootCommands = ''
      mkdir -p /tmp
      chmod 1777 /tmp
    '';
    enableFakechroot = true;

    config = {
      Cmd = [ "/bin/devguard-scanner" ];
      User = "53111:53111";
      Env = [ "SSL_CERT_FILE=/etc/ssl/certs/ca-bundle.crt" "EIO_BACKEND=posix" "HOME=/tmp" "TRIVY_CACHE_DIR=/tmp/.cache/trivy" "SEMGREP_CACHE_DIR=/tmp/.cache/semgrep" "DOCKER_CONFIG=/tmp/.docker" ];
    };
  };

  postgresqlOCI = { debug }: pkgs.dockerTools.buildLayeredImage {
    name = "devguard-postgresql";
    tag = "16";

    contents = [
      pkgs.cacert
      pkgs.glibcLocales  # en_US.UTF-8 locale support
      postgresql.psql
      postgresql.entrypoint
      postgresql.config
      pkgs.bash
      pkgs.coreutils
    ] ++ (if debug then [ pkgs.busybox ] else []);

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
        "LOCALE_ARCHIVE=${pkgs.glibcLocales}/lib/locale/locale-archive"
      ];
      Volumes = { "/var/lib/postgresql/data" = {}; };
    };
  };
}