# METADATA
# title: Container scanning executed
# custom:
#   description: This policy checks if container scanning was executed.
#   priority: 1
#   predicateType: https://in-toto.io/attestation/test-result/v0.1
#   relatedResources:
#   - https://docs.example.com/policy/rule/E123
#   tags:
#   - ISO 27001
#   - A.5.7 Threat intelligence
#   complianceFrameworks:
#   - ISO 27001
package compliance

import rego.v1

default compliant := false

# compliant if {}
