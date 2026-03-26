# A single Python installation containing semgrep and checkov.
#
# semgrep is already in python3Packages:
#   https://github.com/NixOS/nixpkgs/blob/nixos-25.11/pkgs/development/python-modules/semgrep/default.nix
#
# checkov is only a top-level nixpkgs package (buildPythonApplication), so it
# is not usable with python3.withPackages directly.  We inject it into the
# package set via python3.override / packageOverrides, converting it to a
# buildPythonPackage so withPackages accepts it.  The cyclonedx-python-lib
# pin that checkov requires is applied in the same override:
#   https://github.com/NixOS/nixpkgs/blob/nixos-25.11/pkgs/by-name/ch/checkov/package.nix
{
  lib,
  python3,
  fetchFromGitHub,
  fetchPypi,
}:

let
  py = python3.override {
    packageOverrides = self: super: {

      # CVE fix: urllib3 2.5.0 has GHSA-2xpw-w6gg-jr37 / GHSA-gm62-xv2j-4w53 /
      # GHSA-38jv-5279-wg99 — pin to 2.6.3+ which fixes all three.
      urllib3 = super.urllib3.overridePythonAttrs (_: rec {
        version = "2.6.3";
        src = fetchPypi {
          inherit version;
          pname = "urllib3";
          hash = "sha256-G2K2iElEpX2+MhUJq5T9TTswcHXgwurpkaxx7hWtOO0=";
        };
        # nixpkgs backports CVE-2025-66471 as a patch onto the older version;
        # 2.6.3 already ships with the fix, so the patch would conflict.
        patches = [];
        # nixpkgs postPatch strips a setuptools-scm pin that no longer exists
        # in 2.6.3's pyproject.toml — clear it to avoid a substitution error.
        postPatch = "";
      });

      # CVE fixes for transitive Python deps — pin to versions that contain the fix.
      python-multipart = super.python-multipart.overridePythonAttrs (_: rec {
        version = "0.0.22";
        src = fetchPypi { inherit version; pname = "python_multipart"; hash = "sha256-c0C++Zp+ADJhP1bcNgJ7lZ/Tswp4ftYtMQ6VH3w6Olg="; };
        patches = [];
        postPatch = "";
      });

      starlette = super.starlette.overridePythonAttrs (_: rec {
        version = "0.49.1";
        src = fetchPypi { inherit version; pname = "starlette"; hash = "sha256-SBpDtx4k7YxDsR6gL1NT13hA4BSAiBuMtaJrjK5kqMs="; };
        patches = [];
        postPatch = "";
      });

      wheel = super.wheel.overridePythonAttrs (_: rec {
        version = "0.46.2";
        src = fetchPypi { inherit version; pname = "wheel"; hash = "sha256-PXnkj96YR2GKWhgfPMNXZMNJx1Li/pEeZfoX+quYCbA="; };
        patches = [];
        postPatch = "";
      });

      # jupyter-packaging 0.12.3 imports wheel.bdist_wheel which was removed
      # in wheel 0.46.2 — its tests fail at collection time. The package itself
      # installs fine; only the test suite triggers the import.
      jupyter-packaging = super.jupyter-packaging.overridePythonAttrs (_: {
        doCheck = false;
      });

      mcp = super.mcp.overridePythonAttrs (_: rec {
        version = "1.23.0";
        src = fetchPypi { inherit version; pname = "mcp"; hash = "sha256-hODCkxbQqM8K/9GW/QAEh6xRKqP3cbY7Lqhk4ilhdys="; };
        patches = [];
        postPatch = "";
      });

      # checkov requires cyclonedx-python-lib >=6,<8 but nixpkgs ships a
      # newer version whose `serializable` import was renamed `py_serializable`.
      cyclonedx-python-lib = super.cyclonedx-python-lib.overridePythonAttrs (_: rec {
        version = "7.6.2";
        src = fetchFromGitHub {
          owner = "CycloneDX";
          repo = "cyclonedx-python-lib";
          tag = "v${version}";
          hash = "sha256-nklizCiu7Nmynjd5WU5oX/v2TWy9xFVF4GkmCwFKZLI=";
        };
        postPatch = ''
          find . -name '*.py' | xargs -I{} sed -i \
            -e 's/serializable\./py_serializable\./g' \
            -e 's/@serializable/@py_serializable/g' \
            -e 's/from serializable/from py_serializable/g' \
            -e 's/import serializable/import py_serializable/g' \
            {}
        '';
      });

      # Checkov as a buildPythonPackage (not Application) so that
      # withPackages can include it alongside semgrep.
      checkov = self.buildPythonPackage rec {
        pname = "checkov";
        version = "3.2.495";
        pyproject = true;

        src = fetchFromGitHub {
          owner = "bridgecrewio";
          repo = "checkov";
          tag = version;
          hash = "sha256-jn1p9Rso0/OiV1mI3trC/ebJwzADrfs6wmqxtjsC1KE=";
        };

        pythonRelaxDeps = [
          "asteval"
          "bc-detect-secrets"
          "bc-python-hcl2"
          "boto3"
          "botocore"
          "cachetools"
          "cloudsplaining"
          "dpath"
          "igraph"
          "importlib-metadata"
          "license-expression"
          "networkx"
          "openai"
          "packageurl-python"
          "packaging"
          "rustworkx"
          "schema"
          "termcolor"
          "urllib3"
          "pycep-parser"
        ];

        build-system = with self; [ setuptools-scm ];

        dependencies = with self; [
          aiodns
          aiohttp
          aiomultiprocess
          argcomplete
          asteval
          bc-detect-secrets
          bc-jsonpath-ng
          bc-python-hcl2
          boto3
          cachetools
          charset-normalizer
          cloudsplaining
          colorama
          configargparse
          cyclonedx-python-lib
          docker
          dockerfile-parse
          dpath
          flake8
          gitpython
          igraph
          jmespath
          jsonschema
          junit-xml
          license-expression
          networkx
          openai
          packaging
          policyuniverse
          prettytable
          pycep-parser
          pyyaml
          pydantic
          rustworkx
          semantic-version
          spdx-tools
          tabulate
          termcolor
          tqdm
          typing-extensions
          update-checker
        ];

        doCheck = false;

        postInstall = ''
          chmod +x $out/bin/checkov
        '';

        meta = {
          description = "Static code analysis tool for infrastructure-as-code";
          homepage = "https://github.com/bridgecrewio/checkov";
          license = lib.licenses.asl20;
          mainProgram = "checkov";
        };
      };
    };
  };
in
py.withPackages (ps: [
  ps.semgrep
  ps.checkov
])
