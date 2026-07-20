# Shared helper for building a supplementary SBOM for a Go binary tool
# bundled into the devguard-scanner image (gitleaks, trivy, crane).
#
# Trivy's own gobinary scanner can find these statically linked binaries
# inside the image, but can't resolve a version for either the binary itself
# (shown as an unresolved "application" component) or the main Go module
# compiled into it (shown as a versionless "library"/gomod component) - see
# gitleaks.nix for why. This produces one supplementary SBOM per binary that
# fixes both: it runs trivy's own `fs` scanner against the tool's actual Go
# source to get its dependency tree.
#
# go.sum only records the flat, resolved (module, version) set - not which
# module requires which. To turn that into a real transitive tree, trivy
# needs each dependency's own go.mod. Without them it has no edges to work
# with and reports every resolved module as a direct dependency of the main
# module (a flat tree). Passing `goModules` (a buildGoModule package's
# `.goModules` passthru - the FOD containing its downloaded module cache)
# provides them; the fs-scan step below rearranges it into the extracted
# layout trivy actually reads (see there).
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

{ toolName, src, version, modulePurl, binaries, externalReferences ? [ ], goModules ? null }:
let
  versionedModule = "${modulePurl}@${version}";
  externalReferencesJson = builtins.toJSON externalReferences;
in
runCommand "${toolName}-sbom" {
  nativeBuildInputs = [ trivy jq ];
} ''
  mkdir -p $out/sboms

  export HOME="$TMPDIR"
  export TRIVY_CACHE_DIR="$TMPDIR/.trivy-cache"

  cp -r ${src} ./src
  chmod -R u+w ./src

  ${lib.optionalString (goModules != null) ''
    # For a real transitive tree, trivy reads each dependency's go.mod from the
    # EXTRACTED module layout ($GOPATH/pkg/mod/<escaped-module>@<version>/go.mod;
    # it reads GOPATH, never GOMODCACHE, and never runs `go`). goModules only
    # ships the DOWNLOAD cache (.../cache/download/<module>/@v/<version>.mod),
    # which trivy ignores - so without this, no dep go.mod is found, no edges
    # are built, and every module is dumped flat under the main module.
    # Both layouts share the same escaping, so materialize the extracted go.mod
    # tree from the download cache with a plain copy - no `go`, no network.
    export GOPATH="$TMPDIR/go"
    modcache="$GOPATH/pkg/mod"
    mkdir -p "$modcache/cache"
    cp -r --no-preserve=mode,ownership ${goModules} "$modcache/cache/download"
    chmod -R u+w "$modcache/cache/download"

    prefix="$modcache/cache/download/"
    find "$modcache/cache/download" -type f -name '*.mod' | while read -r modfile; do
      rel="''${modfile#$prefix}"   # <escaped-module>/@v/<version>.mod
      mod="''${rel%%/@v/*}"        # <escaped-module>
      ver="$(basename "$modfile" .mod)"  # <version>
      dest="$modcache/$mod@$ver"
      mkdir -p "$dest"
      cp "$modfile" "$dest/go.mod"
    done
  ''}

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
    jq --argjson externalReferences '${externalReferencesJson}' '
      .metadata.component = {"type": "application", "bom-ref": "${binRef}", "name": "${binRef}"}
      | .dependencies += [{"ref": "${binRef}", "dependsOn": ["${versionedModule}"]}]
      | if ($externalReferences | length) > 0 then .externalReferences = ((.externalReferences // []) + $externalReferences) else . end
    ' versioned.json > $out/sboms/${name}.json
  '') binaries}
''
