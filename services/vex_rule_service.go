// Copyright (C) 2026 l3montree GmbH
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package services

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/crowdsourcevexing"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/statemachine"
	"github.com/l3montree-dev/devguard/transformer"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/l3montree-dev/devguard/vexrules"
	"github.com/pkg/errors"
	"go.opentelemetry.io/otel/attribute"
)

func createVulnEventFromVEXRule(vuln models.DependencyVuln, rule *models.VEXRule) (models.VulnEvent, error) {
	var ev models.VulnEvent
	var err error

	switch rule.EventType {
	case dtos.EventTypeFalsePositive:
		ev, err = models.NewFalsePositiveEvent(
			vuln.CalculateHash(),
			dtos.VulnTypeDependencyVuln,
			rule.CreatedByID,
			rule.Justification,
			rule.MechanicalJustification,
			"",
			true,
			nil,
		), nil

	case dtos.EventTypeAccepted:
		ev, err = models.NewAcceptedEvent(
			vuln.CalculateHash(),
			dtos.VulnTypeDependencyVuln,
			rule.CreatedByID,
			rule.Justification,
			true,
			nil,
		), nil

	default:
		ev, err = models.VulnEvent{}, fmt.Errorf("unsupported event type from VEX rule: %s", rule.EventType)
	}
	ev.VexRuleID = &rule.ID
	if err != nil {
		return models.VulnEvent{}, fmt.Errorf("failed to create event from VEX rule: %w", err)
	}

	return ev, nil
}

func isVexEventAlreadyApplied(vuln models.DependencyVuln, event models.VulnEvent) bool {
	events := vuln.GetEvents()
	if len(events) == 0 {
		return false
	}
	var ev models.VulnEvent
	found := false

	for i := len(events) - 1; i >= 0; i-- {
		if events[i].Type == dtos.EventTypeRawRiskAssessmentUpdated {
			continue
		}
		ev = events[i]
		found = true
		break
	}

	if !found {
		return false
	}

	if ev.Type != event.Type {
		return false
	}

	if ev.Justification == nil || event.Justification == nil {
		return ev.Justification == nil && event.Justification == nil
	}

	return *ev.Justification == *event.Justification
}

func MatchRulesToVulns(ctx context.Context, rules []models.UpstreamVEXRule, vulns []models.DependencyVuln) (map[string][]models.DependencyVuln, error) {
	ctx, span := servicesTracer.Start(ctx, "services.MatchRulesToVulns")
	defer span.End()

	lookupMap := make(map[uuid.UUID]models.DependencyVuln, len(vulns))
	for _, vuln := range vulns {
		lookupMap[vuln.ID] = vuln
	}

	// prepare the vulns for evaluation by converting them to CEL-compatible maps
	vulnMaps, err := vexrules.PrepareVulnsForEval(ctx, vulns)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare vulns for evaluation: %w", err)
	}

	compiledRules, err := vexrules.CompileRules(ctx, rules)
	if err != nil {
		return nil, fmt.Errorf("failed to compile VEX rules: %w", err)
	}

	// matches is keyed by vulnID and value is a list of ruleIDs that match that vuln
	// we need to convert it to a map keyed by ruleID and value is a list of matching vulns
	matches, err := vexrules.EvalCompiledRules(ctx, compiledRules, vulnMaps)
	if err != nil {
		return nil, fmt.Errorf("failed to evaluate CEL expressions for VEX rules: %w", err)
	}

	result := make(map[string][]models.DependencyVuln)

	span.SetAttributes(
		attribute.Int("rules.cel_total", len(rules)),
		attribute.Int("vulns.total", len(vulns)),
		attribute.Int("evaluations.total", len(rules)*len(vulns)),
	)

	for vulnID, matchingRuleIDs := range matches {
		parsedID, err := uuid.Parse(vulnID)
		if err != nil {
			continue
		}

		vuln, ok := lookupMap[parsedID]
		if !ok {
			continue
		}
		for _, ruleID := range matchingRuleIDs {
			result[ruleID] = append(result[ruleID], vuln)
		}
	}
	return result, nil
}

func ApplyVEXRulesToVulns(ctx context.Context, rules []models.VEXRule, vulns []models.DependencyVuln) (updatedVulns []models.DependencyVuln, events []models.VulnEvent, err error) {
	vulnsByRule, err := MatchRulesToVulns(ctx, transformer.VEXRulesToUpstreamVEXRules(utils.Filter(rules, func(r models.VEXRule) bool { return r.Enabled })), vulns)
	if err != nil {
		slog.Error("failed to match VEX rules to existing vulnerabilities", "error", err)
		return nil, nil, err
	}
	ruleMap := make(map[string]*models.VEXRule)
	for i := range rules {
		ruleMap[rules[i].ID] = &rules[i]
	}

	vulnMap := make(map[uuid.UUID]models.DependencyVuln)
	eventsByVuln := make(map[uuid.UUID][]models.VulnEvent)

	for ruleID, matchingVulns := range vulnsByRule {
		rule := ruleMap[ruleID]
		for _, vuln := range matchingVulns {
			ev, err := createVulnEventFromVEXRule(vuln, rule)
			if err != nil {
				slog.Error("failed to create event from VEX rule", "error", err)
				return nil, nil, err
			}

			if isVexEventAlreadyApplied(vuln, ev) {
				continue
			}

			vulnID := vuln.ID
			vulnMap[vulnID] = vuln
			eventsByVuln[vulnID] = append(eventsByVuln[vulnID], ev)
		}
	}

	if len(vulnMap) == 0 {
		return nil, nil, nil
	}

	updatedVulns = make([]models.DependencyVuln, 0, len(vulnMap))
	events = make([]models.VulnEvent, 0)

	for vulnID, vuln := range vulnMap {
		updatedVuln := vuln
		for _, ev := range eventsByVuln[vulnID] {
			statemachine.Apply(&updatedVuln, ev)
			events = append(events, ev)
		}
		updatedVulns = append(updatedVulns, updatedVuln)
	}

	slog.Info("applied VEX rules to existing vulnerabilities",
		"rulesApplied", len(rules),
		"vulnsUpdated", len(updatedVulns),
		"eventsCreated", len(events))
	return updatedVulns, events, nil
}

func SetVEXRulesEnabledFromParanoidMode(rules []models.VEXRule, paranoidMode bool) {
	enabled := !paranoidMode
	for i := range rules {
		rules[i].Enabled = enabled
	}
}

type assetAndSource struct {
	AssetID   uuid.UUID
	VexSource string
}

func GroupRulesByAssetAndSource(rules []models.VEXRule) map[assetAndSource][]models.VEXRule {
	grouped := make(map[assetAndSource][]models.VEXRule)
	for _, r := range rules {
		key := assetAndSource{AssetID: r.AssetID, VexSource: r.VexSource}
		grouped[key] = append(grouped[key], r)
	}
	return grouped
}

func DiffVEXRulesForSource(newRules []models.VEXRule, existingRules []models.VEXRule) (rulesToAdd []models.VEXRule, rulesToRemove []models.VEXRule) {
	if len(newRules) == 0 {
		return nil, nil
	}
	result := utils.CompareSlices(newRules, existingRules, func(a models.VEXRule) string {
		return a.ID
	})
	return result.OnlyInA, result.OnlyInB
}

func MatchingSessionAccessibleRules(ctx context.Context, vulns []models.DependencyVuln, vexRules []models.VEXRule, assetIDsForSession []string) (map[uuid.UUID][]models.VEXRule, error) {
	assetIDSet := make(map[string]struct{}, len(assetIDsForSession))
	for _, id := range assetIDsForSession {
		assetIDSet[id] = struct{}{}
	}

	sessionRuleMap := make(map[string]models.VEXRule, len(vexRules))
	sessionRules := make([]models.VEXRule, 0, len(vexRules))
	for _, rule := range vexRules {
		if _, ok := assetIDSet[rule.AssetID.String()]; ok {
			sessionRuleMap[rule.ID] = rule
			sessionRules = append(sessionRules, rule)
		}
	}
	compiledRules, err := vexrules.CompileRules(ctx, utils.Map(sessionRules, transformer.VEXRuleToUpstreamVEXRule))
	if err != nil {
		return nil, fmt.Errorf("failed to compile VEX rules: %w", err)
	}
	vulnMaps, err := vexrules.PrepareVulnsForEval(ctx, vulns)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare vulns for evaluation: %w", err)
	}

	matches, err := vexrules.EvalCompiledRules(ctx, compiledRules, vulnMaps)
	if err != nil {
		return nil, fmt.Errorf("failed to evaluate CEL expressions for VEX rules: %w", err)
	}

	// a single vuln can match more than one vex rule - keep all of them, instead of
	// arbitrarily picking one as "the" recommendation.
	result := make(map[uuid.UUID][]models.VEXRule)
	for vulnID, matchingRuleIDs := range matches {
		// parse the vulnid back to uuid.UUID
		parsedVulnID, err := uuid.Parse(vulnID)
		if err != nil {
			// this should never happen
			return nil, fmt.Errorf("failed to parse vulnID %s: %w", vulnID, err)
		}
		for _, ruleID := range matchingRuleIDs {
			result[parsedVulnID] = append(result[parsedVulnID], sessionRuleMap[ruleID])
		}
	}

	return result, nil
}

type CrowdsourcedVexingContext struct {
	VexRules              []models.VEXRule
	CrowdSourceVexingOrgs []crowdsourcevexing.Organization
	CrowdSourceVexingProj []crowdsourcevexing.Project
	Assets                []models.Asset
}

type OrgRBACData struct {
	OrgID     uuid.UUID
	OwnerID   string
	MemberIDs []string
}

func BuildCrowdsourcedVexingContext(
	vexRules []models.VEXRule,
	projects []models.Project,
	orgs []models.Org,
	projectTrustScores map[uuid.UUID]float64,
	orgTrustScores map[uuid.UUID]float64,
	orgRBACData []OrgRBACData,
) CrowdsourcedVexingContext {
	rbacByOrg := make(map[uuid.UUID]OrgRBACData, len(orgRBACData))
	for _, d := range orgRBACData {
		rbacByOrg[d.OrgID] = d
	}

	crowdSourceVexingOrgs := make([]crowdsourcevexing.Organization, len(orgs))
	for i, org := range orgs {
		rbacData := rbacByOrg[org.ID]
		crowdSourceVexingOrgs[i] = mapOrg(org, orgTrustScores[org.ID], rbacData.OwnerID, rbacData.MemberIDs)
	}

	return CrowdsourcedVexingContext{
		VexRules:              vexRules,
		CrowdSourceVexingOrgs: crowdSourceVexingOrgs,
		CrowdSourceVexingProj: utils.Map(projects, func(p models.Project) crowdsourcevexing.Project {
			return mapProject(p, projectTrustScores[p.ID])
		}),
		Assets: utils.Map(vexRules, func(r models.VEXRule) models.Asset { return r.Asset }),
	}
}

func ComputeVEXRuleRecommendations(
	ctx context.Context,
	allVulns []models.DependencyVuln,
	allRules []models.VEXRule,
	upstreamRules []models.UpstreamVEXRule,
	crowdsourcedCtx CrowdsourcedVexingContext,
) ([]models.VEXRuleRecommendation, error) {
	mapOfRules := make(map[string]models.VEXRule, len(allRules))

	for _, rule := range allRules {
		mapOfRules[rule.ID] = rule
	}

	compiledVexRules, err := vexrules.CompileRules(ctx, transformer.VEXRulesToUpstreamVEXRules(allRules))
	if err != nil {
		return nil, fmt.Errorf("failed to compile all VEX rules: %w", err)
	}
	compiledUpstreamRules, err := vexrules.CompileRules(ctx, upstreamRules)
	if err != nil {
		return nil, fmt.Errorf("failed to compile all upstream VEX rules: %w", err)
	}

	vulnMaps, err := vexrules.PrepareVulnsForEval(ctx, allVulns)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare vulns for evaluation: %w", err)
	}

	vexRuleResults, err := vexrules.EvalCompiledRules(ctx, compiledVexRules, vulnMaps)
	if err != nil {
		return nil, fmt.Errorf("failed to evaluate VEX rules: %w", err)
	}
	upstreamRuleResults, err := vexrules.EvalCompiledRules(ctx, compiledUpstreamRules, vulnMaps)
	if err != nil {
		return nil, fmt.Errorf("failed to evaluate upstream VEX rules: %w", err)
	}

	// at most one recommendation per dependency vuln - an upstream rule match takes
	// priority over a crowdsourced recommendation for the same vuln.
	recommendationsByVulnID := make(map[uuid.UUID]models.VEXRuleRecommendation, len(upstreamRuleResults))
	for vulnID, matchingRules := range upstreamRuleResults {
		if len(matchingRules) == 0 {
			continue
		}
		parsedID, err := uuid.Parse(vulnID)
		if err != nil {
			continue
		}
		upstreamRuleID := matchingRules[0]
		recommendationsByVulnID[parsedID] = models.VEXRuleRecommendation{
			UpstreamVEXRuleID: &upstreamRuleID,
			DependencyVulnID:  parsedID,
		}
	}

	for vulnID, matchingRules := range vexRuleResults {
		parsedID, err := uuid.Parse(vulnID)
		if err != nil {
			continue
		}
		if _, ok := recommendationsByVulnID[parsedID]; ok {
			// a
			continue
		}

		recommendedRule, confidence, votes, err := crowdsourcevexing.CrowdsourcedVexing(
			utils.Map(matchingRules, func(el string) models.VEXRule {
				return mapOfRules[el]
			}),
			crowdsourcedCtx.CrowdSourceVexingOrgs,
			crowdsourcedCtx.CrowdSourceVexingProj,
			crowdsourcedCtx.Assets,
		)
		if err != nil {
			if !errors.Is(err, crowdsourcevexing.ErrNoRecommendation) {
				slog.Error("failed to execute crowdsourced vexing", "err", err)
			}
			continue
		}

		vexRuleID := recommendedRule.ID
		recommendationsByVulnID[parsedID] = models.VEXRuleRecommendation{
			VEXRuleID:        &vexRuleID,
			DependencyVulnID: parsedID,
			Confidence:       confidence,
			VerifiedVotes:    votes.Verified,
			TotalVotes:       votes.Total,
		}
	}

	ruleRecommendations := make([]models.VEXRuleRecommendation, 0, len(recommendationsByVulnID))
	for _, recommendation := range recommendationsByVulnID {
		ruleRecommendations = append(ruleRecommendations, recommendation)
	}

	return ruleRecommendations, nil
}

func mapOrg(org models.Org, orgTrustscore float64, ownerID string, organizationMemberIDs []string) crowdsourcevexing.Organization {
	return crowdsourcevexing.Organization{
		ID:         org.ID,
		Trustscore: orgTrustscore,
		CreatedAt:  org.CreatedAt,
		CreatedBy:  ownerID,
		UserIDs:    organizationMemberIDs,
	}
}

func mapProject(project models.Project, projectTrustscore float64) crowdsourcevexing.Project {
	return crowdsourcevexing.Project{
		ID:             project.ID,
		OrganizationID: project.OrganizationID,
		Trustscore:     projectTrustscore,
	}
}
