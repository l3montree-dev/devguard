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

compliant if {
	# Parse the timestamp from the SBOM metadata
	sbom_time := time.parse_rfc3339_ns(input.metadata.timestamp)

	# Get current time in nanoseconds
	now := time.now_ns()

	# One month in nanoseconds (~30 days)
	one_month_ns := (((30 * 24) * 60) * 60) * 1000000000

	# SBOM must be no older than one month
	now - sbom_time <= one_month_ns
}
