package models_test

import (
	"testing"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/statemachine"
	"github.com/stretchr/testify/assert"
)

func TestNewRawRiskAssessmentUpdatedEvent(t *testing.T) {
	t.Run("should store the fields in the event", func(t *testing.T) {
		vulnID := uuid.MustParse("ffffffff-ffff-ffff-ffff-ffffffffffff")
		userID := "user123"
		justification := "justification text"

		event := models.NewRawRiskAssessmentUpdatedEvent(vulnID, dtos.VulnTypeDependencyVuln, userID, justification)

		assert.Equal(t, dtos.EventTypeRawRiskAssessmentUpdated, event.Type)
		assert.Equal(t, vulnID, *event.DependencyVulnID)
		assert.Equal(t, userID, event.UserID)
		assert.Equal(t, justification, *event.Justification)
	})
}

func TestVulnEvent_Apply(t *testing.T) {
	t.Run("should set state to fixed for EventTypeFixed", func(t *testing.T) {
		vuln := models.DependencyVuln{}
		event := models.VulnEvent{Type: dtos.EventTypeFixed}

		statemachine.Apply(&vuln, event)

		assert.Equal(t, dtos.VulnStateFixed, vuln.State)
	})
	t.Run("should set state to false positive for EventTypeFalsePositive", func(t *testing.T) {
		vuln := models.DependencyVuln{}
		event := models.VulnEvent{Type: dtos.EventTypeFalsePositive}

		statemachine.Apply(&vuln, event)

		assert.Equal(t, dtos.VulnStateFalsePositive, vuln.State)
	})
	t.Run("should keep the risk assessment and state of the vuln for EventTypeRawRiskAssessmentUpdated", func(t *testing.T) {
		vuln := models.DependencyVuln{RiskAssessment: new(0.5)}
		vuln.State = dtos.VulnStateAccepted
		event := models.VulnEvent{Type: dtos.EventTypeRawRiskAssessmentUpdated}

		statemachine.Apply(&vuln, event)

		assert.Equal(t, 0.5, vuln.GetRawRiskAssessment())
		assert.Equal(t, dtos.VulnStateAccepted, vuln.State)
	})
	t.Run("should set state to open for EventTypeDetected", func(t *testing.T) {
		vuln := models.DependencyVuln{}
		event := models.VulnEvent{Type: dtos.EventTypeDetected}

		statemachine.Apply(&vuln, event)

		assert.Equal(t, dtos.VulnStateOpen, vuln.State)
	})

	t.Run("should update the state to open on reopened event", func(t *testing.T) {
		vuln := models.DependencyVuln{}
		event := models.VulnEvent{Type: dtos.EventTypeReopened}

		statemachine.Apply(&vuln, event)

		assert.Equal(t, dtos.VulnStateOpen, vuln.State)
	})
	t.Run("should keep the risk assessment of the vuln for EventTypeDetected", func(t *testing.T) {
		vuln := models.DependencyVuln{RiskAssessment: new(0.7)}
		event := models.VulnEvent{Type: dtos.EventTypeDetected}

		statemachine.Apply(&vuln, event)

		assert.Equal(t, 0.7, vuln.GetRawRiskAssessment())
	})
	t.Run("should set state to fixed and keep the final license decision for EventTypeLicenseDecision", func(t *testing.T) {
		licenseRisk := models.LicenseRisk{FinalLicenseDecision: new("MIT")}
		event := models.VulnEvent{Type: dtos.EventTypeLicenseDecision}

		statemachine.Apply(&licenseRisk, event)

		assert.Equal(t, dtos.VulnStateFixed, licenseRisk.State)
		assert.Equal(t, "MIT", *licenseRisk.FinalLicenseDecision)
	})
	t.Run("should set state to accepted for EventTypeAccepted", func(t *testing.T) {
		vuln := models.DependencyVuln{}
		event := models.VulnEvent{Type: dtos.EventTypeAccepted}

		statemachine.Apply(&vuln, event)

		assert.Equal(t, dtos.VulnStateAccepted, vuln.State)
	})
}
