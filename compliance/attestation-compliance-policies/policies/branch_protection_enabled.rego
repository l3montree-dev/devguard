# METADATA
# title: Branch protection enabled
# custom:
#   description: This policy checks if branch protection is enabled for the default branch.
#   priority: 1
#   predicateType: https://in-toto.io/attestation/test-result/v0.1
#   relatedResources:
#   - https://docs.example.com/policy/rule/E123
#   tags:
#   - ISO 27001
#   - A.8.4 Access to source code
#   complianceFrameworks:
#   - ISO 27001
package compliance

import rego.v1

default compliant := false

# compliant if {}
