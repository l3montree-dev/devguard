# METADATA
# title: Author and commiter email is from organization
# custom:
#   description: This policy checks if the commit is authored and committed with an email address from the organization.
#   priority: 1
#   predicateType: https://slsa.dev/provenance/v1
#   relatedResources: []
#   tags:
#   - Legal
#   complianceFrameworks: []
package compliance

import rego.v1

default compliant := false

compliant if {
	input.predicateType == "https://slsa.dev/provenance/v1"

	author_email := input.predicate.buildDefinition.externalParameters.authoremail
    author_email != ""

    committer_email := input.predicate.buildDefinition.externalParameters.committeremail
    committer_email != ""

    # Match a valid email format
    regex.match(`^[^@<>\s]+@[^@<>\s]+\.[^@<>\s]+$`, author_email)
    regex.match(`^[^@<>\s]+@[^@<>\s]+\.[^@<>\s]+$`, committer_email)

    # Replace 'l3montree.com' with your actual organization domain
    author_domain := split(author_email, "@")[1]
    author_domain == "l3montree.com"

    committer_domain := split(committer_email, "@")[1]
    committer_domain == "l3montree.com"

    author_domain == committer_domain
}
