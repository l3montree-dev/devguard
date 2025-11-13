package integrations_test

import (
	"testing"

	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/internal/core/vuln"
	"github.com/stretchr/testify/assert"
)

func TestShouldCreateIssue(t *testing.T) {
	t.Run("should return false if the assetVersion is not the default branch", func(t *testing.T) {
		assetVersion := models.AssetVersion{
			DefaultBranch: false,
		}

		defaultBranch := vuln.ShouldCreateIssues(assetVersion)
		if defaultBranch {
			t.Fail()
		}
	})
	t.Run("should return true if the assetVersion is the default branch", func(t *testing.T) {
		assetVersion := models.AssetVersion{
			DefaultBranch: true,
		}

		defaultBranch := vuln.ShouldCreateIssues(assetVersion)
		if !defaultBranch {
			t.Fail()
		}
	})

}

func TestGetExpectedIssueState(t *testing.T) {
	cvssThreshold := 7.0
	riskThreshold := 0.5

	makeAsset := func(cvss, risk *float64) models.Asset {
		return models.Asset{
			CVSSAutomaticTicketThreshold: cvss,
			RiskAutomaticTicketThreshold: risk,
		}
	}
	makeDepVuln := func(state dtos.VulnState, cvss float32, risk *float64, manual bool) *models.DependencyVuln {
		return &models.DependencyVuln{
			Vulnerability: models.Vulnerability{
				State:                state,
				ManualTicketCreation: manual,
			},
			CVE:               &models.CVE{CVSS: cvss},
			RawRiskAssessment: risk,
		}
	}

	t.Run("Ticket should stay open if the cvss threshold is still exceeded", func(t *testing.T) {
		asset := makeAsset(&cvssThreshold, nil)
		dep := makeDepVuln(dtos.VulnStateOpen, 8.0, nil, false)
		assert.Equal(t, vuln.ExpectedIssueStateOpen, vuln.GetExpectedIssueState(asset, dep))
	})

	t.Run("Ticket should stay open if the risk threshold is still exceeded", func(t *testing.T) {
		asset := makeAsset(nil, &riskThreshold)
		risk := 0.7
		dep := makeDepVuln(dtos.VulnStateOpen, 0.0, &risk, false)
		assert.Equal(t, vuln.ExpectedIssueStateOpen, vuln.GetExpectedIssueState(asset, dep))
	})

	t.Run("Ticket should stay open, even if the risk threshold is not exceeded anymore - BUT the user created it manually.", func(t *testing.T) {
		asset := makeAsset(&cvssThreshold, &riskThreshold)
		risk := 0.1
		dep := makeDepVuln(dtos.VulnStateOpen, 1.0, &risk, true)
		assert.Equal(t, vuln.ExpectedIssueStateOpen, vuln.GetExpectedIssueState(asset, dep))
	})

	t.Run("Ticket should get closed, if the ticket was not manually created and the thresholds are not exceeded anymore", func(t *testing.T) {
		asset := makeAsset(&cvssThreshold, &riskThreshold)
		risk := 0.1
		dep := makeDepVuln(dtos.VulnStateOpen, 1.0, &risk, false)
		assert.Equal(t, vuln.ExpectedIssueStateClosed, vuln.GetExpectedIssueState(asset, dep))
	})

	t.Run("Ticket should stay closed, if it is fixed but the thresholds are exceeded", func(t *testing.T) {
		asset := makeAsset(&cvssThreshold, &riskThreshold)
		risk := 1.0
		dep := makeDepVuln(dtos.VulnStateFixed, 10.0, &risk, false)
		assert.Equal(t, vuln.ExpectedIssueStateClosed, vuln.GetExpectedIssueState(asset, dep))
	})

	t.Run("ticket should stay closed, if it is fixed and the thresholds are not exceeded (trivial)", func(t *testing.T) {
		asset := makeAsset(&cvssThreshold, &riskThreshold)
		risk := 0.1
		dep := makeDepVuln(dtos.VulnStateFixed, 1.0, &risk, false)
		assert.Equal(t, vuln.ExpectedIssueStateClosed, vuln.GetExpectedIssueState(asset, dep))
	})

	t.Run("Close the ticket if the thresholds are disabled and the ticket was not created manually", func(t *testing.T) {
		asset := makeAsset(nil, nil)
		dep := makeDepVuln(dtos.VulnStateOpen, 0.0, nil, false)
		assert.Equal(t, vuln.ExpectedIssueStateClosed, vuln.GetExpectedIssueState(asset, dep))
	})

	t.Run("Keep the ticket open even if the thresholds dont exist anymore", func(t *testing.T) {
		asset := makeAsset(nil, nil)
		dep := makeDepVuln(dtos.VulnStateOpen, 0.0, nil, true)
		assert.Equal(t, vuln.ExpectedIssueStateOpen, vuln.GetExpectedIssueState(asset, dep))
	})
}
