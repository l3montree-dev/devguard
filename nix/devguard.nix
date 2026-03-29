{ buildGoModule, self }: rec {
  common = import ./common.nix { inherit self; };
  ldflags = [
    "-s"
    "-w"
    "-X github.com/l3montree-dev/devguard/config.Version=${common.version}"
    "-X github.com/l3montree-dev/devguard/config.Commit=${common.commit}"
    "-X github.com/l3montree-dev/devguard/config.Branch=main"
    "-X github.com/l3montree-dev/devguard/config.BuildDate=${common.buildDate}"
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

  devguardScanner = buildGoModule (commonArgs // {
    pname = "devguard-scanner";
    version = common.version;
    subPackages = [ "cmd/devguard-scanner" ];
  });

  devguard = buildGoModule (commonArgs // {
    pname = "devguard";
    version = common.version;
    subPackages = [ "cmd/devguard" ];
  });

  devguardCLI = buildGoModule (commonArgs // {
    pname = "devguard-cli";
    version = common.version;
    subPackages = [ "cmd/devguard-cli" ];
  });
}
