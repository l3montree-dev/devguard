package sigstore

import rego.v1

validMeta if input._type == "https://in-toto.io/Statement/v0.1"

buildFromSignedCommit if input.predicate.buildDefinition.externalParameters.signature

# make sure, it was build using a valid email address
buildByTrustedUser if endswith(input.predicate.buildDefinition.externalParameters.committeremail, "@github.com")

buildInTrustedEnvironment if input.predicate.buildDefinition.externalParameters.variables.RUNNER_ENVIRONMENT == "github-hosted"

buildByTrustedBuilder if input.predicate.runDetails.builder.id == "devguard.org"

isCompliant if {
	validMeta
    buildFromSignedCommit
    buildByTrustedUser
    buildInTrustedEnvironment
    buildByTrustedBuilder
}
