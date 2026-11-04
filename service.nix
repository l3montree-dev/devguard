{
  lib,
  config,
  pkgs,
  ...
}: let
  cfg = config.services.devguard;
  devguardServerDockerImage = "ghcr.io/l3montree-dev/devguard";
  devguardWebDockerImage = "ghcr.io/l3montree-dev/devguard-web";
  kratosIdentityJson = ./identity.schema.json;
  kratosMapperJsonnet = ./authentik.jsonnet;
in {
  options.services.devguard = with lib; {
    enable = mkEnableOption "Devguard";
    domain = mkOption {
      description = "Domain devguard will be reachable at (no trailing slash)";
      example = "https://devguard.example.org";
      type = types.str;
    };
    docker = mkOption {
      description = "Configuration for docker";
      type = types.submodule {
        options = {
          network = lib.mkOption {
            description = "Subnet base address of the docker network";
            type = types.str;
            default = "172.20.0.0";
          };
          bridgeName = lib.mkOption {
            description = "Name of the network bridge";
            type = types.str;
            default = "br-devguard";
          };
          devguardMigrateContainerIp = lib.mkOption {
            description = "IP address of the devguard-migrate container";
            type = types.str;
            default = "172.20.0.2";
          };
          devguardApiContainerIp = lib.mkOption {
            description = "IP address of the devguard-api container";
            type = types.str;
            default = "172.20.0.3";
          };
          devguardWebContainerIp = lib.mkOption {
            description = "IP address of the devguard-web container";
            type = types.str;
            default = "172.20.0.4";
          };
          kratosMigrateContainerIp = lib.mkOption {
            description = "IP address of the kratos-migrate container";
            type = types.str;
            default = "172.20.0.20";
          };
          kratosContainerIp = lib.mkOption {
            description = "IP address of the kratos container";
            type = types.str;
            default = "172.20.0.21";
          };
        };
      };
    };
    devguard = mkOption {
      type = types.submodule {
        options = {
          serverVersion = mkOption {
            description = "Version of the migrate and api containers";
            example = "v1.10.3";
            type = types.str;
          };
          webVersion = mkOption {
            description = "Version of the web container";
            example = "v1.10.1";
            type = types.str;
          };
          encryptionKeyPath = mkOption {
            description = "Path to the encryption key. Must be owned by devguard:devguard";
            type = types.path;
          };
          database = mkOption {
            description = "configuration for the database";
            type = types.submodule {
              options = {
                host = mkOption {
                  description = "Postgresql host";
                  type = types.str;
                };
                port = mkOption {
                  description = "Postgresql port";
                  type = types.port;
                  default = 5432;
                };
                database = mkOption {
                  description = "Postgresql database name";
                  type = types.str;
                  default = "devguard";
                };
                user = mkOption {
                  description = "Postgresql user";
                  type = types.str;
                  default = "devguard";
                };
                passwordFilePath = mkOption {
                  description = "Path to env file containing the Postgresql users password";
                  type = types.path;
                };
              };
            };
          };
        };
      };
    };
    kratos = mkOption {
      type = types.submodule {
        options = {
          configDirectoryPath = mkOption {
            description = "Path to the config directory";
            default = "/var/lib/kratos";
            type = types.path;
          };
          configPath = mkOption {
            description = "Path to the kratos.yaml configuration file";
            type = types.path;
          };
          dockerImage = mkOption {
            description = "Kratos docker image";
            example = "oryd/kratos:v26.2.0-distroless@sha256:481bfc3022e5427ffb94570eef84480b99c9f8158388378c57df8c1a4a104b3d";
            type = types.str;
          };
          database = mkOption {
            description = "configuration for the database";
            type = types.submodule {
              options = {
                environmentFilePath = mkOption {
                  description = "Path to env file containing the Postgresql DSN";
                  type = types.path;
                };
              };
            };
          };
        };
      };
    };
  };

  config = lib.mkIf cfg.enable {
    virtualisation.docker.enable = true;
    virtualisation.oci-containers.backend = "docker";

    # Devguard runs as uid 53111 inside the container, we need a user we can own the secret files to.
    # Source: https://github.com/l3montree-dev/devguard/blob/main/nix/oci.nix#L103
    users.users.devguard = {
      isSystemUser = true;
      uid = 53111;
      group = "devguard";
    };
    users.groups.devguard.gid = 53111;

    # Kratos runs as uid 65532 inside the container, we need a user we can own the files to.
    # Source: https://github.com/ory/kratos/blob/master/.docker/Dockerfile-distroless-static
    # Source: https://github.com/GoogleContainerTools/distroless/blob/main/common/variables.bzl
    users.users.kratos = {
      isSystemUser = true;
      uid = 65532;
      group = "kratos";
    };
    users.groups.kratos.gid = 65532;

    # We need our own docker network because otherwise we cannot give static IPs to containers
    systemd.services."docker-network-devguard" = {
      path = [pkgs.docker];
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        ExecStop = "${pkgs.writeShellApplication {
          runtimeInputs = [pkgs.docker];
          name = "stop-docker-network-devguard";
          text = "docker network rm -f devguard";
        }}/bin/stop-docker-network-devguard";
      };
      script = ''
        docker network inspect devguard || docker network create devguard --subnet=${cfg.docker.network}/24 --opt com.docker.network.bridge.name=${cfg.docker.bridgeName}
      '';
    };

    # Kratos config directory
    systemd.tmpfiles.rules = [
      "d ${cfg.kratos.configDirectoryPath} 770 kratos kratos - -"
    ];

    # Kratos Identity
    systemd.services.kratos-config = {
      wantedBy = ["multi-user.target"];
      path = [pkgs.coreutils];
      before = ["docker-kratos-migrate.service"];
      requiredBy = ["docker-kratos-migrate.service"];
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
      };
      script = ''
        install -Dm440 -o kratos -g kratos ${kratosIdentityJson} ${cfg.kratos.configDirectoryPath}/identity.schema.json
        install -Dm440 -o kratos -g kratos ${kratosMapperJsonnet} ${cfg.kratos.configDirectoryPath}/authentik.jsonnet
        install -Dm440 -o kratos -g kratos ${cfg.kratos.configPath} ${cfg.kratos.configDirectoryPath}/kratos.yml
      '';
    };

    virtualisation.oci-containers.containers."kratos-migrate" = {
      image = cfg.kratos.dockerImage;
      environmentFiles = [
        # DSN=xxx
        cfg.kratos.database.environmentFilePath
      ];
      volumes = [
        "${cfg.kratos.configDirectoryPath}:/etc/config/kratos:ro"
      ];
      cmd = [
        "-c"
        "/etc/config/kratos/kratos.yml"
        "migrate"
        "sql"
        "--read-from-env"
        "--yes"
      ];
      extraOptions = [
        # add host IP as host.docker.internal
        "--add-host=host.docker.internal:host-gateway"
        "--network=name=devguard,ip=${cfg.docker.kratosMigrateContainerIp}"
      ];
    };
    systemd.services."${config.virtualisation.oci-containers.containers."kratos-migrate".serviceName}" = {
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
      };
      after = [
        "docker-network-devguard.service"
      ];
      requires = [
        "docker-network-devguard.service"
      ];
      wantedBy = ["multi-user.target"];
    };

    virtualisation.oci-containers.containers."kratos" = {
      image = cfg.kratos.dockerImage;
      environmentFiles = [
        # DSN=xxx
        cfg.kratos.database.environmentFilePath
      ];
      volumes = [
        "${cfg.kratos.configDirectoryPath}:/etc/config/kratos:ro"
      ];
      cmd = [
        "serve"
        "-c"
        "/etc/config/kratos/kratos.yml"
        "--watch-courier"
      ];
      extraOptions = [
        # add host IP as host.docker.internal
        "--add-host=host.docker.internal:host-gateway"
        "--network=name=devguard,ip=${cfg.docker.kratosContainerIp}"
      ];
    };
    systemd.services."${config.virtualisation.oci-containers.containers."kratos".serviceName}" = {
      serviceConfig = {
        Restart = lib.mkOverride 90 "always";
        RestartMaxDelaySec = lib.mkOverride 90 "1m";
        RestartSec = lib.mkOverride 90 "100ms";
        RestartSteps = lib.mkOverride 90 9;
      };
      restartTriggers = [
        kratosIdentityJson
        kratosMapperJsonnet
      ];
      after = [
        "${config.virtualisation.oci-containers.containers."kratos-migrate".serviceName}.service"
        "kratos-config.service"
      ];
      requires = [
        "${config.virtualisation.oci-containers.containers."kratos-migrate".serviceName}.service"
      ];
      wantedBy = ["multi-user.target"];
    };

    # Devguard
    virtualisation.oci-containers.containers."devguard-migrate" = {
      image = "${devguardServerDockerImage}:${cfg.devguard.serverVersion}";
      environmentFiles = [
        cfg.devguard.database.passwordFilePath
      ];
      user = "53111:53111";
      environment = {
        "POSTGRES_USER" = "${cfg.devguard.database.user}";
        # POSTGRES_PASSWORD set in devguard.env
        "POSTGRES_DB" = "${cfg.devguard.database.database}";
        "POSTGRES_HOST" = "${cfg.devguard.database.host}";
        "POSTGRES_PORT" = "${toString cfg.devguard.database.port}";
        "FRONTEND_URL" = "${cfg.domain}";
        "APP_SIDE_ENCRYPTION_KEY_PATH" = "/keys/devguard-encryption-key.key";
      };
      volumes = [
        "${cfg.devguard.encryptionKeyPath}:/keys/devguard-encryption-key.key:ro"
      ];
      cmd = [
        "devguard-cli"
        "migrate"
      ];
      extraOptions = [
        # add host IP as host.docker.internal
        "--add-host=host.docker.internal:host-gateway"
        "--network=name=devguard,ip=${cfg.docker.devguardMigrateContainerIp}"
        "--tmpfs=/tmp:size=8G"
      ];
    };
    systemd.services."${config.virtualisation.oci-containers.containers."devguard-migrate".serviceName}" = {
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
      };
      after = [
        "${config.virtualisation.oci-containers.containers."kratos".serviceName}.service"
      ];
      requires = [
        "${config.virtualisation.oci-containers.containers."kratos".serviceName}.service"
      ];
      wantedBy = ["multi-user.target"];
    };

    virtualisation.oci-containers.containers."devguard-api" = {
      image = "${devguardServerDockerImage}:${cfg.devguard.serverVersion}";
      environmentFiles = [
        # POSTGRES_PASSWORD=xxx
        cfg.devguard.database.passwordFilePath
      ];
      user = "53111:53111";
      environment = {
        "POSTGRES_USER" = "${cfg.devguard.database.user}";
        # POSTGRES_PASSWORD set in devguard.env
        "POSTGRES_DB" = "${cfg.devguard.database.database}";
        "POSTGRES_HOST" = "${cfg.devguard.database.host}";
        "POSTGRES_PORT" = "${toString cfg.devguard.database.port}";
        "FRONTEND_URL" = "${cfg.domain}";
        "APP_SIDE_ENCRYPTION_KEY_PATH" = "/keys/devguard-encryption-key.key";
        "ORY_KRATOS_PUBLIC" = "http://${cfg.docker.kratosContainerIp}:4433";
        "ORY_KRATOS_ADMIN" = "http://${cfg.docker.kratosContainerIp}:4434";
        "LOG_LEVEL" = "error";
        "INSTANCE_DOMAIN" = "${cfg.domain}";
      };
      volumes = [
        "${cfg.devguard.encryptionKeyPath}:/keys/devguard-encryption-key.key:ro"
      ];
      extraOptions = [
        # add host IP as host.docker.internal
        "--add-host=host.docker.internal:host-gateway"
        "--network=name=devguard,ip=${cfg.docker.devguardApiContainerIp}"
        # See devguard reference compose file, required for the container to work
        "--tmpfs=/tmp:size=8G"
      ];
    };
    systemd.services."${config.virtualisation.oci-containers.containers."devguard-api".serviceName}" = {
      serviceConfig = {
        Restart = lib.mkOverride 90 "always";
        RestartMaxDelaySec = lib.mkOverride 90 "1m";
        RestartSec = lib.mkOverride 90 "100ms";
        RestartSteps = lib.mkOverride 90 9;
      };
      after = [
        "${config.virtualisation.oci-containers.containers."kratos".serviceName}.service"
        "${config.virtualisation.oci-containers.containers."devguard-migrate".serviceName}.service"
      ];
      requires = [
        "${config.virtualisation.oci-containers.containers."kratos".serviceName}.service"
        "${config.virtualisation.oci-containers.containers."devguard-migrate".serviceName}.service"
      ];
      wantedBy = ["multi-user.target"];
    };

    virtualisation.oci-containers.containers."devguard-web" = {
      image = "${devguardWebDockerImage}:${cfg.devguard.webVersion}";
      environment = {
        "DEVGUARD_API_URL" = "http://${cfg.docker.devguardApiContainerIp}:8080";
        "ORY_SDK_URL" = "http://${cfg.docker.kratosContainerIp}:4433";
        "ORY_SDK_PUBLIC_URL" = "${cfg.domain}";
        "FRONTEND_URL" = "${cfg.domain}";
      };
      user = "53111:53111";
      extraOptions = [
        # add host IP as host.docker.internal
        "--add-host=host.docker.internal:host-gateway"
        "--network=name=devguard,ip=${cfg.docker.devguardWebContainerIp}"
        # See devguard reference compose file, required for the container to work
        "--tmpfs=/tmp:size=100M,mode=777"
        "--tmpfs=/app/.next/cache:size=500M,mode=777"
      ];
    };
    systemd.services."${config.virtualisation.oci-containers.containers."devguard-web".serviceName}" = {
      serviceConfig = {
        Restart = lib.mkOverride 90 "always";
        RestartMaxDelaySec = lib.mkOverride 90 "1m";
        RestartSec = lib.mkOverride 90 "100ms";
        RestartSteps = lib.mkOverride 90 9;
      };
      after = [
        "${config.virtualisation.oci-containers.containers."devguard-api".serviceName}.service"
      ];
      requires = [
        "${config.virtualisation.oci-containers.containers."devguard-api".serviceName}.service"
      ];
      wantedBy = ["multi-user.target"];
    };

    services.nginx = {
      upstreams = {
        "devguard-web" = {
          servers = {
            "${cfg.docker.devguardWebContainerIp}:3000" = {};
          };
        };
        "devguard-api" = {
          servers = {
            "${cfg.docker.devguardApiContainerIp}:8080" = {};
          };
        };
      };
    };
  };
}
