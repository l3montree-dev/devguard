# METADATA
# title: Secret scanning executed
# custom:
#   description: This policy checks if secret scanning was executed.
#   priority: 1
#   predicateType: https://in-toto.io/attestation/test-result/v0.1
#   relatedResources:
#   - https://docs.example.com/policy/rule/E123
#   tags:
#   - ISO 27001
#   - A.5.7 Threat intelligence
#   policyFrameworks:
#   - framework: ISO 27001
#     controls:
#     - A.5.7

package compliance

import rego.v1

default compliant := false

# compliant if {}
