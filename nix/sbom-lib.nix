# Shared helper for building a supplementary SBOM for a Go binary tool
# bundled into the devguard-scanner image (gitleaks, trivy, crane).
#
# Trivy's own gobinary scanner can find these statically linked binaries
# inside the image, but can't resolve a version for either the binary itself
# (shown as an unresolved "application" component) or the main Go module
# compiled into it (shown as a versionless "library"/gomod component) - see
# gitleaks.nix for why. This produces one supplementary SBOM per binary that
# fixes both: it runs trivy's own `fs` scanner against the tool's actual Go
# source (its go.sum is enough - no network access needed or available in the
# build sandbox) to get the real, complete transitive dependency tree.
#
# `trivy fs` wraps the whole result under its own synthetic root (an
# arbitrary UUID) plus an intermediate grouping node, both discarded here -
# what we actually want is the module component itself (bom-ref == purl ==
# modulePurl, versionless, buried a couple levels down from the scan root)
# every occurrence of it is retargeted to a properly versioned purl, using
# the exact version this tool was fetched/built at (authoritative regardless
# of what trivy could detect from the compiled binary). That versioned
# module is then wrapped under a synthetic "application" component keyed to
# the binary's exact in-image path, replacing trivy's own synthetic root
# entirely.
#
# devguard-scanner's supplementary-SBOM merge matches (and replaces) existing
# components by exact Name, so this gives it two independent, correctly
# identified nodes to fix: the path-keyed application stub, and the
# versionless module/library duplicate.
{ lib, runCommand, jq }:

{ trivy }:

{ toolName, src, version, modulePurl, binaries }:
let
  versionedModule = "${modulePurl}@${version}";
in
runCommand "${toolName}-sbom" {
  nativeBuildInputs = [ trivy jq ];
} ''
  mkdir -p $out/sboms

  export HOME="$TMPDIR"
  export TRIVY_CACHE_DIR="$TMPDIR/.trivy-cache"

  cp -r ${src} ./src
  chmod -R u+w ./src

  trivy fs --offline-scan --format cyclonedx --output raw.json ./src

  # A source tree full of its own embedded test fixtures (e.g. trivy's own
  # repo, full of testdata go.mod/package.json/etc fixtures for its own
  # analyzer tests) makes trivy's fs scan produce a mess of synthetic
  # intermediate grouping nodes - referenced from .dependencies but with no
  # matching entry in .components at all. Left in, these become dangling refs
  # our merge tries to graft in as if they were real components and crashes
  # on. Filter every dependsOn list (and drop whole dependency entries whose
  # own ref isn't a real component) down to just what's actually backed by a
  # component - the versioned module itself, or one of its real dependencies.
  jq --arg old "${modulePurl}" --arg new "${versionedModule}" --arg version "${version}" '
    (.. | select(. == $old)) = $new
    | (.components[]? | select(."bom-ref" == $new)) |= (. + {"version": $version})
    | (([.components[]?."bom-ref"] + [$new]) | unique) as $valid
    | .dependencies = [
        .dependencies[]?
        | select(.ref as $r | $valid | index($r))
        | .dependsOn = [(.dependsOn // [])[] | select(. as $d | $valid | index($d))]
      ]
  ' raw.json > versioned.json

  ${lib.concatMapStringsSep "\n" ({ name, binPath }:
    let binRef = lib.removePrefix "/" binPath; in ''
    jq '
      .metadata.component = {"type": "application", "bom-ref": "${binRef}", "name": "${binRef}"}
      | .dependencies += [{"ref": "${binRef}", "dependsOn": ["${versionedModule}"]}]
    ' versioned.json > $out/sboms/${name}.json
  '') binaries}
''
