# METADATA
# title: CI Image has digest set
# custom:
#   description: This policy checks if the CI image has a digest set.
#   priority: 1
#   predicateType: https://slsa.dev/provenance/v1
#   relatedResources: []
#   tags:
#   - GitLab CI
#   - Legal
#   complianceFrameworks: []
package compliance

import rego.v1

default compliant := false

compliant if {
	input.predicateType == "https://slsa.dev/provenance/v1"

	# @sha256:<64-hex-chars>
	job_image := input.predicate.buildDefinition.externalParameters.jobimage
	job_image != ""
	regex.match(`@sha256:[a-fA-F0-9]{64}$`, job_image)

	ci_var_job_image := input.predicate.buildDefinition.externalParameters.variables.CI_JOB_IMAGE
	ci_var_job_image != ""
	regex.match(`@sha256:[a-fA-F0-9]{64}$`, ci_var_job_image)
}
