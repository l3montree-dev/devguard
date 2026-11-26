package commonint_test

import (
	"testing"

	"github.com/l3montree-dev/devguard/celrules"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/integrations/commonint"

	"github.com/stretchr/testify/assert"
)

func TestGetExpectedIssueState(t *testing.T) {
	cvssRule := `vuln.cve != null && vuln.cve.cvss >= 7`
	riskRule := `vuln.riskAssessment != null && vuln.riskAssessment >= 0.5`
	bothRule := "(" + cvssRule + ") || (" + riskRule + ")"
	defaultBranchRule := `ref.defaultBranch == true && vuln.cve != null && vuln.cve.cvss >= 7`
	defaultBranch := models.AssetVersion{DefaultBranch: true}

	makeAsset := func(cel *string) models.Asset {
		return models.Asset{
			TicketRangeCelExpression: cel,
		}
	}
	makeDepVuln := func(state dtos.VulnState, cvss float32, risk *float64, manual bool) *models.DependencyVuln {
		return &models.DependencyVuln{
			Vulnerability: models.Vulnerability{
				State:                state,
				ManualTicketCreation: manual,
			},
			CVE:            &models.CVE{CVSS: cvss},
			RiskAssessment: risk,
		}
	}

	t.Run("Ticket should stay open if the cvss rule still matches", func(t *testing.T) {
		asset := makeAsset(&cvssRule)
		dep := makeDepVuln(dtos.VulnStateOpen, 8.0, nil, false)
		assert.Equal(t, commonint.ExpectedIssueStateOpen, commonint.GetExpectedIssueState(asset, dep, celrules.NewRefs([]models.AssetVersion{defaultBranch})))
	})

	t.Run("Ticket should stay open if the risk rule still matches", func(t *testing.T) {
		asset := makeAsset(&riskRule)
		risk := 0.7
		dep := makeDepVuln(dtos.VulnStateOpen, 0.0, &risk, false)
		assert.Equal(t, commonint.ExpectedIssueStateOpen, commonint.GetExpectedIssueState(asset, dep, celrules.NewRefs([]models.AssetVersion{defaultBranch})))
	})

	t.Run("Ticket should stay open, even if the rule does not match anymore - BUT the user created it manually.", func(t *testing.T) {
		asset := makeAsset(&bothRule)
		risk := 0.1
		dep := makeDepVuln(dtos.VulnStateOpen, 1.0, &risk, true)
		assert.Equal(t, commonint.ExpectedIssueStateOpen, commonint.GetExpectedIssueState(asset, dep, celrules.NewRefs([]models.AssetVersion{defaultBranch})))
	})

	t.Run("Ticket should get closed, if the ticket was not manually created and the rule does not match anymore", func(t *testing.T) {
		asset := makeAsset(&bothRule)
		risk := 0.1
		dep := makeDepVuln(dtos.VulnStateOpen, 1.0, &risk, false)
		assert.Equal(t, commonint.ExpectedIssueStateClosed, commonint.GetExpectedIssueState(asset, dep, celrules.NewRefs([]models.AssetVersion{defaultBranch})))
	})

	t.Run("Ticket should stay closed, if it is fixed but the rule matches", func(t *testing.T) {
		asset := makeAsset(&bothRule)
		risk := 1.0
		dep := makeDepVuln(dtos.VulnStateFixed, 10.0, &risk, false)
		assert.Equal(t, commonint.ExpectedIssueStateClosed, commonint.GetExpectedIssueState(asset, dep, celrules.NewRefs([]models.AssetVersion{defaultBranch})))
	})

	t.Run("ticket should stay closed, if it is fixed and the rule does not match (trivial)", func(t *testing.T) {
		asset := makeAsset(&bothRule)
		risk := 0.1
		dep := makeDepVuln(dtos.VulnStateFixed, 1.0, &risk, false)
		assert.Equal(t, commonint.ExpectedIssueStateClosed, commonint.GetExpectedIssueState(asset, dep, celrules.NewRefs([]models.AssetVersion{defaultBranch})))
	})

	t.Run("Close the ticket if the rule is disabled and the ticket was not created manually", func(t *testing.T) {
		asset := makeAsset(nil)
		dep := makeDepVuln(dtos.VulnStateOpen, 0.0, nil, false)
		assert.Equal(t, commonint.ExpectedIssueStateClosed, commonint.GetExpectedIssueState(asset, dep, celrules.NewRefs([]models.AssetVersion{defaultBranch})))
	})

	t.Run("Keep the ticket open even if the rule does not exist anymore", func(t *testing.T) {
		asset := makeAsset(nil)
		dep := makeDepVuln(dtos.VulnStateOpen, 0.0, nil, true)
		assert.Equal(t, commonint.ExpectedIssueStateOpen, commonint.GetExpectedIssueState(asset, dep, celrules.NewRefs([]models.AssetVersion{defaultBranch})))
	})

	t.Run("Close the ticket if the rule only matches the default branch and the vuln is on another branch", func(t *testing.T) {
		asset := makeAsset(&defaultBranchRule)
		dep := makeDepVuln(dtos.VulnStateOpen, 9.0, nil, false)
		assert.Equal(t, commonint.ExpectedIssueStateClosed, commonint.GetExpectedIssueState(asset, dep, celrules.NewRefs([]models.AssetVersion{{DefaultBranch: false}})))
	})

	t.Run("Close the ticket if the rule fails to evaluate", func(t *testing.T) {
		rule := `vuln.cve.cvss >= 7`
		asset := makeAsset(&rule)
		dep := &models.DependencyVuln{Vulnerability: models.Vulnerability{State: dtos.VulnStateOpen}}
		assert.Equal(t, commonint.ExpectedIssueStateClosed, commonint.GetExpectedIssueState(asset, dep, celrules.NewRefs([]models.AssetVersion{defaultBranch})))
	})
}
