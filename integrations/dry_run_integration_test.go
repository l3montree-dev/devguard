package integrations

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// setupNeverCalledIntegration returns a mock IntegrationAggregate where every
// mutating method fails the test if called. GetExcessTicketIDs is allowed
// because it is read-only.
func setupNeverCalledIntegration(t *testing.T) *mocks.IntegrationAggregate {
	t.Helper()
	m := mocks.NewIntegrationAggregate(t)

	m.On("CreateIssue", mock.Anything, mock.Anything, mock.Anything, mock.Anything,
		mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Maybe().
		Run(func(args mock.Arguments) {
			t.Fatal("CreateIssue was called on the real integration — dry-run must not delegate mutations")
		}).
		Return(nil)

	m.On("UpdateIssue", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Maybe().
		Run(func(args mock.Arguments) {
			t.Fatal("UpdateIssue was called on the real integration — dry-run must not delegate mutations")
		}).
		Return(nil)

	m.On("CreateLabels", mock.Anything, mock.Anything).
		Maybe().
		Run(func(args mock.Arguments) {
			t.Fatal("CreateLabels was called on the real integration — dry-run must not delegate mutations")
		}).
		Return(nil)

	// The dry-run wrapper must NOT forward CompareIssueStatesAndResolveDifferences to the
	// real implementation, because that would close tickets in the external system.
	m.On("CompareIssueStatesAndResolveDifferences", mock.Anything, mock.Anything, mock.Anything).
		Maybe().
		Run(func(args mock.Arguments) {
			t.Fatal("CompareIssueStatesAndResolveDifferences was called on the real integration — dry-run must use GetExcessTicketIDs instead")
		}).
		Return(nil)

	// GetExcessTicketIDs is read-only and may be called.
	m.On("GetExcessTicketIDs", mock.Anything, mock.Anything, mock.Anything).
		Maybe().
		Return([]string{"123", "456"}, nil)

	return m
}

func dryRunTestAsset() models.Asset {
	return models.Asset{Model: models.Model{ID: uuid.New()}, Slug: "test-asset"}
}

func TestDryRunIntegration(t *testing.T) {
	t.Run("CreateIssue does not delegate to real integration", func(t *testing.T) {
		real := setupNeverCalledIntegration(t)
		dr := NewDryRunIntegration(real)

		vuln := &models.DependencyVuln{}
		vuln.ID = uuid.New()
		err := dr.CreateIssue(context.Background(), dryRunTestAsset(), "v1", vuln, "proj", "org", "justification", "system", nil)
		assert.NoError(t, err)
	})

	t.Run("UpdateIssue does not delegate to real integration", func(t *testing.T) {
		real := setupNeverCalledIntegration(t)
		dr := NewDryRunIntegration(real)

		vuln := &models.DependencyVuln{}
		vuln.ID = uuid.New()
		err := dr.UpdateIssue(context.Background(), dryRunTestAsset(), "v1", vuln, nil)
		assert.NoError(t, err)
	})

	t.Run("CreateLabels does not delegate to real integration", func(t *testing.T) {
		real := setupNeverCalledIntegration(t)
		dr := NewDryRunIntegration(real)

		err := dr.CreateLabels(context.Background(), dryRunTestAsset())
		assert.NoError(t, err)
	})

	t.Run("CompareIssueStates uses read-only GetExcessTicketIDs and never closes tickets", func(t *testing.T) {
		real := setupNeverCalledIntegration(t)
		dr := NewDryRunIntegration(real)

		ticketID := "abc/42"
		vulns := []models.DependencyVuln{
			{Vulnerability: models.Vulnerability{TicketID: &ticketID}},
		}

		err := dr.CompareIssueStatesAndResolveDifferences(context.Background(), dryRunTestAsset(), vulns)
		assert.NoError(t, err)
		real.AssertCalled(t, "GetExcessTicketIDs", mock.Anything, mock.Anything, mock.Anything)
	})
}
