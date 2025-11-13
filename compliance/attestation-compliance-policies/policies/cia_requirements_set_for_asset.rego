# METADATA
# title: CIA requirements set for asset
# custom:
#   description: This policy checks if the CIA (Confidentiality, Integrity, Availability) requirements are set in DevGuard for the asset.
#   priority: 1
#   predicateType: https://in-toto.io/attestation/test-result/v0.1
#   relatedResources:
#   - https://docs.example.com/policy/rule/E123
#   tags:
#   - ISO 27001
#   - A.5.12 Classification of Information
#   complianceFrameworks:
#   - ISO 27001
package compliance

import rego.v1

default compliant := false

# compliant if {}
