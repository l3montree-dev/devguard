# METADATA
# title: Security policy present in repository
# custom:
#   description: This policy checks if a security policy (SECURITY.md) exists in the repository.
#   priority: 1
#   predicateType: https://slsa.dev/provenance/v1
#   relatedResources:
#   - https://github.com/ossf/scorecard/blob/main/docs/checks.md#security-policy
#   tags:
#   - Best Practices
#   complianceFrameworks:
#   - Best Practices
#   - OpenSSF Scorecard
package compliance

import rego.v1

default compliant := false

# Set compliant to true if SECURITY.md exists in any resolvedDependency file URI
compliant if {
	# make sure to look at the correct predicate type
	input.predicateType == "https://slsa.dev/provenance/v1"

	some dep in input.predicate.buildDefinition.resolvedDependencies
	endswith(dep.uri, "/SECURITY.md")
}
