package models_test

import (
	"testing"

	"github.com/l3montree-dev/devguard/internal/common"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/stretchr/testify/assert"
)

func TestNewRawRiskAssessmentUpdatedEvent(t *testing.T) {
	t.Run("should store the old risk and other fields in the event", func(t *testing.T) {
		vulnID := "vuln123"
		userID := "user123"
		justification := "justification text"
		oldRisk := 0.5
		report := common.RiskCalculationReport{
			// populate with necessary fields
		}

		event := models.NewRawRiskAssessmentUpdatedEvent(vulnID, models.VulnTypeDependencyVuln, userID, justification, &oldRisk, report)

		assert.Equal(t, models.EventTypeRawRiskAssessmentUpdated, event.Type)
		assert.Equal(t, vulnID, event.VulnID)
		assert.Equal(t, userID, event.UserID)
		assert.Equal(t, justification, *event.Justification)

		arbitraryData := event.GetArbitraryJSONData()
		assert.Equal(t, oldRisk, arbitraryData["oldRisk"])
		// Add more assertions based on the fields in RiskCalculationReport
	})
}

func TestVulnEvent_Apply(t *testing.T) {
	t.Run("should set state to fixed for EventTypeFixed", func(t *testing.T) {
		vuln := models.DependencyVuln{}
		event := models.VulnEvent{Type: models.EventTypeFixed}

		event.Apply(&vuln)

		assert.Equal(t, models.VulnStateFixed, vuln.State)
	})
	t.Run("should set state to false positive for EventTypeFalsePositive", func(t *testing.T) {
		vuln := models.DependencyVuln{}
		event := models.VulnEvent{Type: models.EventTypeFalsePositive}

		event.Apply(&vuln)

		assert.Equal(t, models.VulnStateFalsePositive, vuln.State)
	})
	t.Run("should update the risk assessment for EventTypeRawRiskAssessmentUpdated", func(t *testing.T) {
		vuln := models.DependencyVuln{}
		event := models.VulnEvent{
			Type:              models.EventTypeRawRiskAssessmentUpdated,
			ArbitraryJSONData: `{"risk": 0.5 }`,
		}

		event.Apply(&vuln)

		assert.Equal(t, 0.5, vuln.GetRawRiskAssessment())
	})

	t.Run("should update RiskRecalculatedAt for EventTypeRawRiskAssessmentUpdated", func(t *testing.T) {
		vuln := models.DependencyVuln{}
		event := models.VulnEvent{
			Type:              models.EventTypeRawRiskAssessmentUpdated,
			ArbitraryJSONData: `{"risk": 0.5 }`,
		}

		event.Apply(&vuln)

		assert.NotZero(t, vuln.RiskRecalculatedAt)
	})
	t.Run("should set state to open for EventTypeDetected", func(t *testing.T) {
		vuln := models.DependencyVuln{}
		event := models.VulnEvent{Type: models.EventTypeDetected}

		event.Apply(&vuln)

		assert.Equal(t, models.VulnStateOpen, vuln.State)
	})

	t.Run("should update the RiskRecalculatedAt for EventTypeDetected", func(t *testing.T) {
		vuln := models.DependencyVuln{}
		event := models.VulnEvent{
			Type:              models.EventTypeDetected,
			ArbitraryJSONData: `{"risk": 0.5 }`,
		}

		event.Apply(&vuln)

		assert.NotZero(t, vuln.RiskRecalculatedAt)
	})

	t.Run("should update the state to open on reopened event", func(t *testing.T) {
		vuln := models.DependencyVuln{}
		event := models.VulnEvent{Type: models.EventTypeReopened}

		event.Apply(&vuln)

		assert.Equal(t, models.VulnStateOpen, vuln.State)
	})
	t.Run("should set state to accepted for EventTypeAccepted", func(t *testing.T) {
		vuln := models.DependencyVuln{}
		event := models.VulnEvent{Type: models.EventTypeAccepted}

		event.Apply(&vuln)

		assert.Equal(t, models.VulnStateAccepted, vuln.State)
	})
}
