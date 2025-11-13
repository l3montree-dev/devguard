# METADATA
# title: Commits are signed off
# custom:
#   description: This policy checks if the commit is signed off by the author.
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

	commit_msg := input.predicate.buildDefinition.externalParameters.commitmessage

	commit_msg != ""

	# Match a signed-off-by line with name and valid email "Signed-off-by: Name <email>"
    # (?m)                              Enable multiline mode
    # ^Signed-off-by:\s+                Line must start with 'Signed-off-by: '
    # [^<>\n]+                          Capture non-empty name (no angle brackets)
    # <[^@<>\s]+@[^@<>\s]+\.[^@<>\s]+>  Simple email format
    # \s*$                              Allow optional trailing whitespace, then end of line
	regex.match(`(?m)^Signed-off-by:\s+[^<>\n]+<[^@<>\s]+@[^@<>\s]+\.[^@<>\s]+>\s*$`, commit_msg)
}
