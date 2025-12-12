# METADATA
# title: Current SBOM is present
# custom:
#   description: This policy checks if a current SBOM (not older than one month) is present.
#   priority: 1
#   predicateType: https://cyclonedx.org/bom
#   relatedResources: []
#   tags:
#   - ISO 27001
#   - A.5.7 Threat intelligence
#   - A.5.9 Inventory of information and other associated assets
#   - A.8.8 Management of technical vulnerabilities
#   complianceFrameworks:
#   - ISO 27001
package compliance

import rego.v1

default compliant := false

# Detect a CycloneDX SBOM either at the root or under predicate
sbom_present if {
	bom := input
	bom.bomFormat == "CycloneDX"
	bom.components[_]
}

sbom_present if {
	bom := input.predicate
	bom.bomFormat == "CycloneDX"
	bom.components[_]
}

compliant if sbom_present

violations contains "Attestation does not contain a CycloneDX SBOM" if not sbom_present
