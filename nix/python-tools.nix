# Single Python virtual environment containing semgrep and checkov, built from
# a uv lockfile via uv2nix.  All version pins (including CVE fixes) live in
# nix/python-tools/uv.lock — no manual overridePythonAttrs needed.
#
# To regenerate the lockfile after changing pyproject.toml:
#   cd nix/python-tools && uv lock
#
# References:
#   uv2nix hello-world template:
#   https://github.com/pyproject-nix/uv2nix/tree/master/templates/hello-world
{
  # auto-resolved from pkgsLinux by callPackage
  lib,
  python313,
  callPackage,
  # passed explicitly from flake.nix
  uv2nix,
  pyproject-nix,
  pyproject-build-systems,
}: rec {
  workspace = uv2nix.lib.workspace.loadWorkspace {
    workspaceRoot = ./python-tools;
  };

  overlay = workspace.mkPyprojectOverlay {
    # Prefer wheels — semgrep ships a pre-built wheel with the OCaml binary
    # inside, which avoids a full OCaml toolchain build.
    sourcePreference = "wheel";
  };

  pythonSet = (callPackage pyproject-nix.build.packages {
    python = python313;
  }).overrideScope (lib.composeManyExtensions [
    pyproject-build-systems.overlays.default
    overlay
  ]);
  venv = pythonSet.mkVirtualEnv "devguard-scanner-tools" workspace.deps.default;
}

