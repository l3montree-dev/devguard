package integrations

import (
	"context"
	"log/slog"

	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/integrations/commonint"
	"github.com/l3montree-dev/devguard/shared"
)

// dryRunIntegration wraps a real IntegrationAggregate and intercepts all
// ticket mutations, logging what would happen instead of executing them.
// Read-only operations are forwarded to the real implementation so log
// output reflects actual remote state.
type dryRunIntegration struct {
	real shared.IntegrationAggregate
}

var _ shared.IntegrationAggregate = &dryRunIntegration{}

func NewDryRunIntegration(real shared.IntegrationAggregate) shared.IntegrationAggregate {
	slog.Warn("[DRY-RUN] ticket operations are disabled — no writes to any external system will occur")
	return &dryRunIntegration{real: real}
}

func (d *dryRunIntegration) CreateIssue(ctx context.Context, asset models.Asset, assetVersionName string, vuln models.Vuln, projectSlug string, orgSlug string, justification string, userID string, userAgent *string) error {
	slog.Info("[DRY-RUN] would open ticket", "vuln", vuln.GetID(), "asset", asset.Slug, "assetVersion", assetVersionName, "justification", justification)
	return nil
}

func (d *dryRunIntegration) UpdateIssue(ctx context.Context, asset models.Asset, assetVersionSlug string, vuln models.Vuln, userAgent *string) error {
	var expectedState string
	switch v := vuln.(type) {
	case *models.DependencyVuln:
		expectedState = string(commonint.GetExpectedIssueState(asset, v))
	case *models.FirstPartyVuln:
		expectedState = string(commonint.GetExpectedIssueStateForFirstPartyVuln(asset, v))
	default:
		expectedState = "unknown"
	}
	slog.Info("[DRY-RUN] would update ticket", "vuln", vuln.GetID(), "asset", asset.Slug, "ticketID", vuln.GetTicketID(), "expectedState", expectedState)
	return nil
}

func (d *dryRunIntegration) CreateLabels(ctx context.Context, asset models.Asset) error {
	slog.Info("[DRY-RUN] would create labels", "asset", asset.Slug)
	return nil
}

// CompareIssueStatesAndResolveDifferences fetches the real remote state from
// all integrations and logs which tickets would be closed, without applying any mutations.
func (d *dryRunIntegration) CompareIssueStatesAndResolveDifferences(ctx context.Context, asset models.Asset, vulnsWithTickets []models.DependencyVuln) error {
	excessIDs, err := d.real.GetExcessTicketIDs(ctx, asset, vulnsWithTickets)
	if err != nil {
		slog.Error("[DRY-RUN] failed to fetch excess tickets", "asset", asset.Slug, "err", err)
		return err
	}
	if len(excessIDs) == 0 {
		slog.Info("[DRY-RUN] no excess tickets to close", "asset", asset.Slug)
		return nil
	}
	for _, id := range excessIDs {
		slog.Info("[DRY-RUN] would close ticket", "asset", asset.Slug, "ticketID", id)
	}
	return nil
}

func (d *dryRunIntegration) GetExcessTicketIDs(ctx context.Context, asset models.Asset, vulnsWithTickets []models.DependencyVuln) ([]string, error) {
	return d.real.GetExcessTicketIDs(ctx, asset, vulnsWithTickets)
}

// All non-mutating methods are forwarded to the real implementation.

func (d *dryRunIntegration) WantsToHandleWebhook(ctx shared.Context) bool {
	return d.real.WantsToHandleWebhook(ctx)
}

func (d *dryRunIntegration) HandleWebhook(ctx shared.Context) error {
	return d.real.HandleWebhook(ctx)
}

func (d *dryRunIntegration) ListOrgs(ctx shared.Context) ([]models.Org, error) {
	return d.real.ListOrgs(ctx)
}

func (d *dryRunIntegration) ListGroups(ctx context.Context, userID string, providerID string) ([]models.Project, []shared.Role, error) {
	return d.real.ListGroups(ctx, userID, providerID)
}

func (d *dryRunIntegration) ListProjects(ctx context.Context, userID string, providerID string, groupID string) ([]models.Asset, []shared.Role, error) {
	return d.real.ListProjects(ctx, userID, providerID, groupID)
}

func (d *dryRunIntegration) ListRepositories(ctx shared.Context) ([]dtos.GitRepository, error) {
	return d.real.ListRepositories(ctx)
}

func (d *dryRunIntegration) HasAccessToExternalEntityProvider(ctx shared.Context, externalEntityProviderID string) (bool, error) {
	return d.real.HasAccessToExternalEntityProvider(ctx, externalEntityProviderID)
}

func (d *dryRunIntegration) HandleEvent(ctx context.Context, event any, userAgent *string) error {
	return d.real.HandleEvent(ctx, event, userAgent)
}

func (d *dryRunIntegration) GetID() shared.IntegrationID {
	return d.real.GetID()
}

func (d *dryRunIntegration) GetIntegration(id shared.IntegrationID) shared.ThirdPartyIntegration {
	return d.real.GetIntegration(id)
}

func (d *dryRunIntegration) GetUsers(org models.Org) []dtos.UserDTO {
	return d.real.GetUsers(org)
}
