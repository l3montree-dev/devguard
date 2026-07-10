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
  runCommand,
  jq,
  # passed explicitly from flake.nix
  uv2nix,
  pyproject-nix,
  pyproject-build-systems,
  # passed explicitly from oci.nix (its own package, built from trivy.nix)
  trivy,
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
    pyproject-build-systems.overlays.wheel
    overlay
  ]);
  venv = pythonSet.mkVirtualEnv "devguard-scanner-tools" workspace.deps.default;

  # Trivy's *image* scan of the venv (installed site-packages) can only see a
  # flat list - pip installs carry no relationship metadata the way a lockfile
  # does, so every package looks like a direct dependency of the image, no
  # matter how deep it actually sits in the real tree. A *source* scan of this
  # same workspace (this uv.lock) sees the real tree. If both scans get
  # ingested for the same product, whichever ran most recently becomes
  # authoritative for any package they share (normalize.SBOMGraph.MergeGraph's
  # "last source wins" semantics) - so which tree "wins" would flip depending
  # on scan order. Baking the real tree into the image itself as a
  # supplementary SBOM (picked up by devguard-scanner's --sbomPath discovery)
  # sidesteps that: it's always there, not a competing scan.
  #
  # Every package already gets a real, correctly-versioned purl from trivy's
  # own image scan (pypi resolution is deterministic, unlike gitleaks' main
  # module case in gitleaks.nix) - so unlike the Go tools' supplementary
  # SBOMs, this doesn't need to retarget any identity.
  #
  # One supplementary SBOM, bundling the entire workspace dependency graph
  # (all packages, all real edges - dangling refs to trivy's own
  # scan-internal nodes filtered out, same as sbom-lib.nix does for the Go
  # tools), rooted at the workspace project's own entry ("devguard-scanner-
  # tools", which trivy resolves with a real purl/version and a real
  # dependsOn: [checkov, semgrep] edge, same as any other uv-managed
  # package - it just isn't installed into the venv's site-packages itself,
  # so it never shows up in the image's own flat scan).
  #
  # Since nothing in the base image scan matches it by name, EnrichSBOM
  # attaches it as a new top-level dependency of the image root. From there,
  # every other package this bundle also contains (checkov, semgrep, and
  # everything transitively beneath them) picks up its real, non-root parent
  # from the very same bundle - so devguard's generalized stale-edge prune
  # (which considers every bundled component, not just direct children)
  # demotes each one's flat direct-root edge in this single merge, no matter
  # how deep it sits in the real tree.
  sbom = runCommand "python-tools-sbom" {
    nativeBuildInputs = [ trivy jq ];
  } ''
    mkdir -p $out/sboms

    export HOME="$TMPDIR"
    export TRIVY_CACHE_DIR="$TMPDIR/.trivy-cache"

    cp -r ${./python-tools} ./src
    chmod -R u+w ./src

    trivy fs --offline-scan --format cyclonedx --output raw.json ./src

    jq '
      ([.components[]?."bom-ref"]) as $valid
      | .components = [.components[] | select(."bom-ref" as $r | $valid | index($r))]
      | .dependencies = [
          .dependencies[]?
          | select(.ref as $r | $valid | index($r))
          | .dependsOn = [(.dependsOn // [])[] | select(. as $d | $valid | index($d))]
        ]
      | .metadata.component = (.components[] | select(.name == "devguard-scanner-tools"))
    ' raw.json > "$out/sboms/devguard-scanner-tools.json"
  '';
}

