# Makes a trivy-generated CycloneDX SBOM reproducible byte-for-byte across
# independent runs of the same scan (e.g. the same commit built on two
# different CI systems). Left unnormalized, none of this is guaranteed
# deterministic:
#
#   - .serialNumber is a fresh random UUID every run.
#   - .metadata.timestamp is the wall-clock scan time.
#   - trivy assigns a random UUID bom-ref to any component it can't derive a
#     purl for (e.g. the synthetic root of a locally-scanned source tree) -
#     that UUID also shows up as a `ref`/`dependsOn` entry elsewhere in the
#     document, so it must be rewritten everywhere it occurs, not just where
#     it's first defined.
#   - component/dependency array order, and even object key order within a
#     single component (trivy attaches some fields, e.g. `licenses`, via a
#     concurrent unordered pass) are not stable between runs.
#
# Callers are expected to also pass jq's `-S` flag (recursively sorts object
# keys), which this filter alone can't do from the inside.
def isUUID: test("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$");

(reduce (.components[]? // empty) as $c (
  {};
  if ($c."bom-ref" // "" | isUUID) then
    . + {($c."bom-ref"): ("component:" + ($c.purl // $c.name // $c."bom-ref"))}
  else . end
)) as $renames
| walk(if type == "string" and ($renames[.]? != null) then $renames[.] else . end)
| del(.serialNumber, .metadata.timestamp)
# Full-value sort (not sort_by a single key) so that components/dependencies
# sharing the same bom-ref - duplicates trivy sometimes emits - still land in
# a deterministic, content-derived order instead of their original (unstable)
# scan order.
| if has("components") then .components |= sort else . end
| if has("dependencies") then
    .dependencies |= (map(.dependsOn |= sort) | sort)
  else . end
