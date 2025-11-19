# METADATA
# title: Notification channel for new vulnerabilities
# custom:
#   description: This policy checks if a notification channel is configured for new vulnerabilities.
#   priority: 1
#   predicateType: https://in-toto.io/attestation/test-result/v0.1
#   relatedResources:
#   - https://docs.example.com/policy/rule/E123
#   tags:
#   - ISO 27001
#   - A.8.8 Management of technical vulnerabilities
#   complianceFrameworks:
#   - ISO 27001
package compliance

import rego.v1

default compliant := false

# compliant if {}
