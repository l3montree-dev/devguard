# METADATA
# title: Build from signed source
# custom:
#   description: This policy checks if the build was done from a signed commit.
#   priority: 0
#   predicateType: https://slsa.dev/provenance/v1
#   relatedResources: []
#   tags:
#   - ISO 27001
#   - A.8 Access Control
#   complianceFrameworks:
#   - ISO 27001
package compliance

import rego.v1

default compliant := false

# Match SSH signature
compliant if {
    input.predicateType == "https://slsa.dev/provenance/v1"
    sig := input.predicate.buildDefinition.externalParameters.signature
    sig != ""
    is_ssh_signature(sig)
}

# Match GPG signature
compliant if {
    input.predicateType == "https://slsa.dev/provenance/v1"
    sig := input.predicate.buildDefinition.externalParameters.signature
    sig != ""
    is_gpg_signature(sig)
}

is_ssh_signature(sig) if {
    startswith(sig, "-----BEGIN SSH SIGNATURE-----")
    endswith(sig, "-----END SSH SIGNATURE-----\n")
}

is_gpg_signature(sig) if {
    startswith(sig, "-----BEGIN PGP SIGNATURE-----")
    endswith(sig, "-----END PGP SIGNATURE-----\n")
}