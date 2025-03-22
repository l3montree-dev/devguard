# METADATA
# title: Build from signed source
# description: This policy checks if the build was done from a signed commit. It does not check the signature itself, just that it exists.
# relatedResources:
# - https://docs.example.com/policy/rule/E123
# tags:
# - iso27001
# - A.8 Access Control
package compliance

import rego.v1

allow if {
    # make sure to look at the build definition to see if it was signed
    input.predicateType == "https://slsa.dev/provenance/v1"
    # signature needs to be defined on the external parameters
    input.predicate.buildDefinition.externalParameters.signature
}