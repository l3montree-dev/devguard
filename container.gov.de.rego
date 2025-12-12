# METADATA
# title: container.gov.de Policy
# custom:
#   description: This policy decides, if a container is compliant to be listed on container.gov.de based on vex attestations.
#   priority: 1
#   predicateType: https://cyclonedx.org/vex
#   relatedResources: []
#   tags:
#   - Legal
#   complianceFrameworks: []
package compliance

import rego.v1

default compliant := false

compliant if {
	input.predicateType == "https://cyclonedx.org/vex"
}