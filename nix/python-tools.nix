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
}:

let
  py = python3.override {
    packageOverrides = self: super: {

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
