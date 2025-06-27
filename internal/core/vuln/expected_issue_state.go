package vuln

import (
	"github.com/l3montree-dev/devguard/internal/database/models"
)

type ExpectedIssueState string

const (
	ExpectedIssueStateOpen   ExpectedIssueState = "open"
	ExpectedIssueStateClosed ExpectedIssueState = "closed"
)

func (e ExpectedIssueState) ToGitlab() string {
	switch e {
	case ExpectedIssueStateOpen:
		return "reopen"
	case ExpectedIssueStateClosed:
		return "close"
	default:
		return "reopen" // default to reopen if not specified
	}
}

func (e ExpectedIssueState) ToGithub() string {
	switch e {
	case ExpectedIssueStateOpen:
		return "open"
	case ExpectedIssueStateClosed:
		return "closed"
	default:
		return "open" // default to reopen if not specified
	}
}

func ShouldCreateIssues(assetVersion models.AssetVersion) bool {
	//if the vulnerability was found anywhere else than the default branch we don't want to create an issue
	return assetVersion.DefaultBranch
}

func IsConnectedToThirdPartyIntegration(asset models.Asset) bool {
	// check if repository id is not nil
	if asset.RepositoryID != nil {
		return true
	}

	if asset.ExternalEntityID != nil && asset.ExternalEntityProviderID != nil {
		return true
	}

	return false
}

func GetExpectedIssueState(asset models.Asset, dependencyVuln *models.DependencyVuln) ExpectedIssueState {
	cvssThresholdExceeded := asset.CVSSAutomaticTicketThreshold != nil && float64(dependencyVuln.CVE.CVSS) >= *asset.CVSSAutomaticTicketThreshold
	riskThresholdExceeded := asset.RiskAutomaticTicketThreshold != nil && *dependencyVuln.RawRiskAssessment >= *asset.RiskAutomaticTicketThreshold

	// keep the ticket open if the state is open AND
	// if the CVSS/Risk Threshold is exceeded OR the ticket was manually created
	if dependencyVuln.State == models.VulnStateOpen {
		if (cvssThresholdExceeded || riskThresholdExceeded) || dependencyVuln.ManualTicketCreation {
			return ExpectedIssueStateOpen
		} else {
			return ExpectedIssueStateClosed
		}
	} else {
		return ExpectedIssueStateClosed
	}
}

func ShouldCreateThisIssue(asset models.Asset, dependencyVuln *models.DependencyVuln) bool {
	expectedState := GetExpectedIssueState(asset, dependencyVuln)
	return expectedState == ExpectedIssueStateOpen
}
