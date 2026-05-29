package dtos

import "time"

// DevguardAssetAttestationPredicateType is the predicate type URI used when storing this attestation in the attestations table.
const DevguardAssetAttestationPredicateType = "https://devguard.org/attestation/asset-metrics/v1"

// DevguardAssetAttestationDTO represents a security attestation for an asset.
// It captures measurable metrics about how quickly vulnerabilities are being addressed.
type DevguardAssetAttestationDTO struct {
	// Metadata
	Type          string    `json:"type"`
	GeneratedAt   time.Time `json:"generatedAt"`
	SchemaVersion string    `json:"schemaVersion"`

	// Average time (in hours) to close vulnerabilities, grouped by severity.
	// Based on risk score classification.
	MeanTimeToRemediate MeanTimeToRemediateDTO `json:"meanTimeToRemediate"`
}

// MeanTimeToRemediateDTO holds average remediation durations in hours, split by severity.
type MeanTimeToRemediateDTO struct {
	// Risk-based severity buckets (DevGuard risk score)
	RiskLowAvgHours      float64 `json:"riskLowAvgHours"`
	RiskMediumAvgHours   float64 `json:"riskMediumAvgHours"`
	RiskHighAvgHours     float64 `json:"riskHighAvgHours"`
	RiskCriticalAvgHours float64 `json:"riskCriticalAvgHours"`

	// CVSS-based severity buckets
	CVSSLowAvgHours      float64 `json:"cvssLowAvgHours"`
	CVSSMediumAvgHours   float64 `json:"cvsssMediumAvgHours"`
	CVSSHighAvgHours     float64 `json:"cvssHighAvgHours"`
	CVSSCriticalAvgHours float64 `json:"cvssCriticalAvgHours"`
}
