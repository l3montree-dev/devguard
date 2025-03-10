package models

import (
	"testing"

	"github.com/l3montree-dev/devguard/internal/common"
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

		event := NewRawRiskAssessmentUpdatedEvent(vulnID, userID, justification, &oldRisk, report)

		assert.Equal(t, EventTypeRawRiskAssessmentUpdated, event.Type)
		assert.Equal(t, vulnID, event.VulnID)
		assert.Equal(t, userID, event.UserID)
		assert.Equal(t, justification, *event.Justification)

		arbitraryData := event.GetArbitraryJsonData()
		assert.Equal(t, oldRisk, arbitraryData["oldRisk"])
		// Add more assertions based on the fields in RiskCalculationReport
	})
}
