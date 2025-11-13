package models_test

import (
	"testing"

	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/stretchr/testify/assert"
)

func TestNewRawRiskAssessmentUpdatedEvent(t *testing.T) {
	t.Run("should store the old risk and other fields in the event", func(t *testing.T) {
		vulnID := "vuln123"
		userID := "user123"
		justification := "justification text"
		oldRisk := 0.5
		report := dtos.RiskCalculationReport{
			// populate with necessary fields
		}

		event := models.NewRawRiskAssessmentUpdatedEvent(vulnID, dtos.VulnTypeDependencyVuln, userID, justification, &oldRisk, report)

		assert.Equal(t, dtos.EventTypeRawRiskAssessmentUpdated, event.Type)
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
		event := models.VulnEvent{Type: dtos.EventTypeFixed}

		event.Apply(&vuln)

		assert.Equal(t, dtos.VulnStateFixed, vuln.State)
	})
	t.Run("should set state to false positive for EventTypeFalsePositive", func(t *testing.T) {
		vuln := models.DependencyVuln{}
		event := models.VulnEvent{Type: dtos.EventTypeFalsePositive}

		event.Apply(&vuln)

		assert.Equal(t, dtos.VulnStateFalsePositive, vuln.State)
	})
	t.Run("should update the risk assessment for EventTypeRawRiskAssessmentUpdated", func(t *testing.T) {
		vuln := models.DependencyVuln{}
		event := models.VulnEvent{
			Type:              dtos.EventTypeRawRiskAssessmentUpdated,
			ArbitraryJSONData: `{"risk": 0.5 }`,
		}

		event.Apply(&vuln)

		assert.Equal(t, 0.5, vuln.GetRawRiskAssessment())
	})

	t.Run("should update RiskRecalculatedAt for EventTypeRawRiskAssessmentUpdated", func(t *testing.T) {
		vuln := models.DependencyVuln{}
		event := models.VulnEvent{
			Type:              dtos.EventTypeRawRiskAssessmentUpdated,
			ArbitraryJSONData: `{"risk": 0.5 }`,
		}

		event.Apply(&vuln)

		assert.NotZero(t, vuln.RiskRecalculatedAt)
	})
	t.Run("should set state to open for EventTypeDetected", func(t *testing.T) {
		vuln := models.DependencyVuln{}
		event := models.VulnEvent{Type: dtos.EventTypeDetected}

		event.Apply(&vuln)

		assert.Equal(t, dtos.VulnStateOpen, vuln.State)
	})

	t.Run("should update the RiskRecalculatedAt for EventTypeDetected", func(t *testing.T) {
		vuln := models.DependencyVuln{}
		event := models.VulnEvent{
			Type:              dtos.EventTypeDetected,
			ArbitraryJSONData: `{"risk": 0.5 }`,
		}

		event.Apply(&vuln)

		assert.NotZero(t, vuln.RiskRecalculatedAt)
	})

	t.Run("should update the state to open on reopened event", func(t *testing.T) {
		vuln := models.DependencyVuln{}
		event := models.VulnEvent{Type: dtos.EventTypeReopened}

		event.Apply(&vuln)

		assert.Equal(t, dtos.VulnStateOpen, vuln.State)
	})
	t.Run("should set state to accepted for EventTypeAccepted", func(t *testing.T) {
		vuln := models.DependencyVuln{}
		event := models.VulnEvent{Type: dtos.EventTypeAccepted}

		event.Apply(&vuln)

		assert.Equal(t, dtos.VulnStateAccepted, vuln.State)
	})
}
