package commonint

import (
	"log/slog"

	"github.com/l3montree-dev/devguard/celrules"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
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

func GetExpectedIssueStateForFirstPartyVuln(asset models.Asset, firstPartyVuln *models.FirstPartyVuln) ExpectedIssueState {
	if firstPartyVuln.State == dtos.VulnStateOpen {
		return ExpectedIssueStateOpen
	} else {
		return ExpectedIssueStateClosed
	}
}

func GetExpectedIssueState(asset models.Asset, dependencyVuln *models.DependencyVuln, assetVersion models.AssetVersion) ExpectedIssueState {
	ruleMatches := false
	if asset.TicketRangeCelExpression != nil && *asset.TicketRangeCelExpression != "" {
		matches, err := celrules.EvalTicketRangeRule(*asset.TicketRangeCelExpression, *dependencyVuln, assetVersion)
		if err != nil {
			slog.Warn("could not evaluate ticket range rule", "assetID", asset.ID, "vulnID", dependencyVuln.ID, "err", err)
		}
		ruleMatches = err == nil && matches
	}

	// keep the ticket open if the state is open AND
	// if the ticket range rule matches OR the ticket was manually created
	if dependencyVuln.State == dtos.VulnStateOpen && (ruleMatches || dependencyVuln.ManualTicketCreation) {
		return ExpectedIssueStateOpen
	}
	return ExpectedIssueStateClosed
}

func ShouldCreateThisIssue(asset models.Asset, dependencyVuln *models.DependencyVuln, assetVersion models.AssetVersion) bool {
	return GetExpectedIssueState(asset, dependencyVuln, assetVersion) == ExpectedIssueStateOpen
}
