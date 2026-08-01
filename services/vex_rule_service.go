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
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/statemachine"
	"github.com/l3montree-dev/devguard/transformer"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/l3montree-dev/devguard/vexrules"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"gorm.io/gorm"
)

type VEXRuleService struct {
	vexRuleRepository               shared.VEXRuleRepository
	upstreamVEXRuleRepository       shared.UpstreamVEXRuleRepository
	dependencyVulnRepository        shared.DependencyVulnRepository
	vulnEventRepository             shared.VulnEventRepository
	cveRepository                   shared.CveRepository
	cveRelationshipRepository       shared.CVERelationshipRepository
	cveRelationshipService          shared.CVERelationshipService
	upstreamVexRuleRepository       shared.UpstreamVEXRuleRepository
	organisationRepository          shared.OrganizationRepository
	projectRepository               shared.ProjectRepository
	assetVersionRepository          shared.AssetVersionRepository
	trustedEntityRepository         shared.TrustedEntityRepository
	rbacProvider                    shared.RBACProvider
	assetRepository                 shared.AssetRepository
	vexRuleRecommendationRepository shared.VEXRuleRecommendationRepository
}

var _ shared.VEXRuleService = (*VEXRuleService)(nil)

func NewVEXRuleService(
	vexRuleRepository shared.VEXRuleRepository,
	upstreamVEXRuleRepository shared.UpstreamVEXRuleRepository,
	dependencyVulnRepository shared.DependencyVulnRepository,
	vulnEventRepository shared.VulnEventRepository,
	cveRepository shared.CveRepository,
	cveRelationshipRepository shared.CVERelationshipRepository,
	cveRelationshipService shared.CVERelationshipService,
	upstreamVexRuleRepository shared.UpstreamVEXRuleRepository,
	organisationRepository shared.OrganizationRepository,
	projectRepository shared.ProjectRepository,
	assetVersionRepository shared.AssetVersionRepository,
	trustedEntityRepository shared.TrustedEntityRepository,
	rbacProvider shared.RBACProvider,
	assetRepository shared.AssetRepository,
	vexRuleRecommendationRepository shared.VEXRuleRecommendationRepository,
) *VEXRuleService {
	return &VEXRuleService{
		vexRuleRepository:               vexRuleRepository,
		upstreamVEXRuleRepository:       upstreamVEXRuleRepository,
		dependencyVulnRepository:        dependencyVulnRepository,
		vulnEventRepository:             vulnEventRepository,
		cveRepository:                   cveRepository,
		cveRelationshipRepository:       cveRelationshipRepository,
		cveRelationshipService:          cveRelationshipService,
		upstreamVexRuleRepository:       upstreamVexRuleRepository,
		organisationRepository:          organisationRepository,
		projectRepository:               projectRepository,
		assetVersionRepository:          assetVersionRepository,
		trustedEntityRepository:         trustedEntityRepository,
		rbacProvider:                    rbacProvider,
		assetRepository:                 assetRepository,
		vexRuleRecommendationRepository: vexRuleRecommendationRepository,
	}
}

func (s *VEXRuleService) Create(ctx context.Context, tx shared.DB, rule *models.VEXRule) error {
	// Ensure the ID is calculated from composite key components
	rule.EnsureID()
	if err := s.vexRuleRepository.Create(ctx, tx, rule); err != nil {
		return fmt.Errorf("failed to create VEX rule: %w", err)
	}

	return nil
}

func (s *VEXRuleService) Begin(ctx context.Context) shared.DB {
	return s.vexRuleRepository.Begin(ctx)
}

func (s *VEXRuleService) Delete(ctx context.Context, tx shared.DB, rule models.VEXRule) error {
	return s.vexRuleRepository.Delete(ctx, tx, rule)
}

func (s *VEXRuleService) FindByAssetID(ctx context.Context, tx shared.DB, assetID uuid.UUID) ([]models.VEXRule, error) {
	return s.vexRuleRepository.FindByAssetID(ctx, tx, assetID)
}

func (s *VEXRuleService) FindByAssetIDPaged(ctx context.Context, tx shared.DB, assetID uuid.UUID, pageInfo shared.PageInfo, search string, filterQuery []shared.FilterQuery, sortQuery []shared.SortQuery) (shared.Paged[models.VEXRule], error) {
	return s.vexRuleRepository.FindByAssetIDPaged(ctx, tx, assetID, pageInfo, search, filterQuery, sortQuery)
}

func (s *VEXRuleService) FindByID(ctx context.Context, tx shared.DB, id string) (models.VEXRule, error) {
	return s.vexRuleRepository.FindByID(ctx, tx, id)
}

// CountMatchingVulns returns the number of dependency vulnerabilities that a VEX rule has been applied to
func (s *VEXRuleService) CountMatchingVulns(ctx context.Context, tx shared.DB, rule models.VEXRule) (int, error) {
	counts, err := s.vulnEventRepository.CountByVexRuleIDs(ctx, tx, []string{rule.ID})
	if err != nil {
		return 0, fmt.Errorf("failed to count matching vulns: %w", err)
	}
	return counts[rule.ID], nil
}

// CountMatchingVulnsForRules returns, for each rule, the number of distinct
// dependency vulns it has an applied event for - i.e. vuln_events grouped by
// vex_rule_id. This avoids loading every vuln ever recorded for the asset
// (with full event/CVE preloads) just to recompute CEL matches that were
// already evaluated and recorded when the rule was applied.
func (s *VEXRuleService) CountMatchingVulnsForRules(ctx context.Context, tx shared.DB, rules []models.VEXRule) (map[string]int, error) {
	ctx, span := servicesTracer.Start(ctx, "VEXRuleService.CountMatchingVulnsForRules")
	defer span.End()
	span.SetAttributes(attribute.Int("rules.total", len(rules)))

	if len(rules) == 0 {
		return make(map[string]int), nil
	}

	ruleIDs := utils.Map(rules, func(r models.VEXRule) string { return r.ID })
	counts, err := s.vulnEventRepository.CountByVexRuleIDs(ctx, tx, ruleIDs)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("failed to count matching vulns: %w", err)
	}

	result := make(map[string]int, len(rules))
	for _, rule := range rules {
		if count, ok := counts[rule.ID]; ok {
			result[rule.ID] = count
		} else {
			result[rule.ID] = 0
		}
	}

	return result, nil
}

// CreateVulnEventFromVEXRule creates a VulnEvent based on a VEX rule and vulnerability.
// The event type is determined by the rule's EventType field.
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

func (s *VEXRuleService) ApplyRulesToExisting(ctx context.Context, tx shared.DB, rules []models.VEXRule, vulns []models.DependencyVuln) ([]models.DependencyVuln, error) {
	vulnsByRule := s.matchRulesToVulns(ctx, transformer.VEXRulesToUpstreamVEXRules(utils.Filter(rules, func(r models.VEXRule) bool { return r.Enabled })), vulns)
	ruleMap := make(map[string]*models.VEXRule)
	for i := range rules {
		ruleMap[rules[i].ID] = &rules[i]
	}

	// Collect all vulns to update (deduplicated by ID)
	vulnMap := make(map[uuid.UUID]models.DependencyVuln)
	eventsByVuln := make(map[uuid.UUID][]models.VulnEvent)

	for ruleID, matchingVulns := range vulnsByRule {
		rule := ruleMap[ruleID]
		for _, vuln := range matchingVulns {
			ev, err := createVulnEventFromVEXRule(vuln, rule)
			if err != nil {
				slog.Error("failed to create event from VEX rule", "error", err)
				continue
			}

			// Skip duplicate events unless force reapply is enabled
			if isVexEventAlreadyApplied(vuln, ev) {
				continue
			}

			vulnID := vuln.ID
			vulnMap[vulnID] = vuln
			eventsByVuln[vulnID] = append(eventsByVuln[vulnID], ev)
		}
	}

	if len(vulnMap) == 0 {
		return vulns, nil
	}

	// Apply all events to vulns and collect updated vulns and events
	updatedVulns := make([]models.DependencyVuln, 0, len(vulnMap))
	allEvents := make([]models.VulnEvent, 0)

	for vulnID, vuln := range vulnMap {
		updatedVuln := vuln
		for _, ev := range eventsByVuln[vulnID] {
			statemachine.Apply(&updatedVuln, ev)
			allEvents = append(allEvents, ev)
		}
		updatedVulns = append(updatedVulns, updatedVuln)
	}

	// Save all updated vulns and events in one batch
	if err := s.dependencyVulnRepository.SaveBatchBestEffort(ctx, tx, updatedVulns); err != nil {
		return nil, fmt.Errorf("failed to save updated vulns: %w", err)
	}

	if err := s.vulnEventRepository.SaveBatchBestEffort(ctx, tx, allEvents); err != nil {
		return nil, fmt.Errorf("failed to save events: %w", err)
	}

	logAction := "applied"
	slog.Info(logAction+" VEX rules to existing vulnerabilities",
		"rulesApplied", len(rules),
		"vulnsUpdated", len(updatedVulns),
		"eventsCreated", len(allEvents))
	return updatedVulns, nil
}

// ApplyRulesToExistingVulns applies multiple VEX rules to all existing vulnerabilities
// that match each rule's path pattern and CVE. This is more efficient than applying
// rules one by one as it batches database queries and saves.
func (s *VEXRuleService) ApplyRulesToExistingVulns(ctx context.Context, tx shared.DB, assetID uuid.UUID, rules []models.VEXRule) ([]models.DependencyVuln, error) {
	if len(rules) == 0 {
		return nil, nil
	}

	// Find all vulns matching all rules at once
	// we need to fetch with events right here to make sure we can identify vex rules which were already applied.
	vulns, err := s.dependencyVulnRepository.GetAllOpenVulnsByAssetID(ctx, tx, assetID)

	if err != nil {
		return nil, fmt.Errorf("failed to fetch existing vulns for asset: %w", err)
	}
	return s.ApplyRulesToExisting(ctx, tx, rules, vulns)
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

// IngestVEXRules syncs the given rules for a single source and applies them to existing
// vulns. This is the format-agnostic ingestion entry point: callers run the appropriate
// transformer (CycloneDX/CSAF/OpenVEX) to produce the rules, then hand them here.
func (s *VEXRuleService) IngestVEXRules(ctx context.Context, tx shared.DB, asset models.Asset, rules []models.VEXRule) error {
	addedRules, err := s.syncRulesForSource(ctx, tx, asset, rules)
	if err != nil {
		return fmt.Errorf("failed to sync VEX rules: %w", err)
	}
	_, err = s.ApplyRulesToExistingVulns(ctx, tx, asset.ID, addedRules)
	return err
}

// syncRulesForSource sets the Enabled flag based on ParanoidMode and syncs the rules for the
// given source, returning the rules that were newly added.
func (s *VEXRuleService) syncRulesForSource(ctx context.Context, tx shared.DB, asset models.Asset, rules []models.VEXRule) ([]models.VEXRule, error) {
	// Rules are enabled if ParanoidMode is disabled
	enabled := !asset.ParanoidMode
	for i := range rules {
		rules[i].Enabled = enabled
	}
	addedRules, _, err := s.syncVEXRulesFromSource(ctx, tx, asset.ID, rules)
	return addedRules, err
}

// SyncVEXRulesFromSource syncs VEX rules from a specific source.
// It fetches existing rules for the given asset and vexSource, compares them with
// the new rules, adds new ones and removes ones that no longer exist.
func (s *VEXRuleService) syncVEXRulesFromSource(ctx context.Context, tx shared.DB, assetID uuid.UUID, newRules []models.VEXRule) ([]models.VEXRule, []models.VEXRule, error) {
	// read the source from the first rule to ensure consistency
	if len(newRules) == 0 {
		return nil, nil, nil
	}
	vexSource := newRules[0].VexSource
	// Fetch existing rules for this asset and vexSource
	existingRules, err := s.vexRuleRepository.FindByAssetAndVexSource(ctx, tx, assetID, vexSource)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to fetch existing VEX rules: %w", err)
	}

	result := utils.CompareSlices(newRules, existingRules, func(a models.VEXRule) string {
		return a.ID
	})

	rulesToAdd := result.OnlyInA
	rulesToRemove := result.OnlyInB

	// Add new rules
	if len(rulesToAdd) > 0 {
		if err := s.vexRuleRepository.UpsertBatch(ctx, tx, rulesToAdd); err != nil {
			return nil, nil, fmt.Errorf("failed to add new VEX rules: %w", err)
		}
		slog.Info("added new VEX rules from source",
			"assetID", assetID,
			"vexSource", vexSource,
			"count", len(rulesToAdd))
	}

	// Remove old rules
	if len(rulesToRemove) > 0 {
		if err := s.vexRuleRepository.DeleteBatch(ctx, tx, rulesToRemove); err != nil {
			return nil, nil, fmt.Errorf("failed to remove old VEX rules: %w", err)
		}
		slog.Info("removed old VEX rules from source",
			"assetID", assetID,
			"vexSource", vexSource,
			"count", len(rulesToRemove))
	}

	return rulesToAdd, rulesToRemove, nil
}

func (s *VEXRuleService) matchRulesToVulns(ctx context.Context, rules []models.UpstreamVEXRule, vulns []models.DependencyVuln) map[string][]models.DependencyVuln {
	ctx, span := servicesTracer.Start(ctx, "VEXRuleService.matchRulesToVulns")
	defer span.End()

	result := make(map[string][]models.DependencyVuln)

	span.SetAttributes(
		attribute.Int("rules.cel_total", len(rules)),
		attribute.Int("vulns.total", len(vulns)),
		attribute.Int("evaluations.total", len(rules)*len(vulns)),
	)

	for _, vuln := range vulns {
		matches, err := vexrules.EvalRules(ctx, rules, vuln)
		if err != nil {
			slog.Error("failed to evaluate CEL expressions for VEX rules", "error", err)
			continue
		}
		for _, rule := range rules {
			if matches[rule.ID] {
				result[rule.ID] = append(result[rule.ID], vuln)
			}
		}
	}
	return result
}

func (s *VEXRuleService) Recommend(ctx shared.Context, tx shared.DB, vulnID uuid.UUID) (dtos.VexRuleRecommendation, error) {
	requestCtx, span := servicesTracer.Start(ctx.Request().Context(), "CrowdsourcedVexingService.Recommend")
	defer span.End()
	span.SetAttributes(attribute.String("dependencyVuln.id", vulnID.String()))

	traceErr := func(err error) (dtos.VexRuleRecommendation, error) {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return dtos.VexRuleRecommendation{}, err
	}

	vuln, err := s.dependencyVulnRepository.Read(requestCtx, tx, vulnID)
	if err != nil {
		return traceErr(err)
	}

	vexRules, err := s.vexRuleRepository.All(requestCtx, tx)
	if err != nil {
		return traceErr(err)
	}

	rulesInSessionOrg, err := rulesInSessionOrg(ctx, vexRules)
	if err != nil {
		return traceErr(err)
	}

	if rule, ok, err := checkIfUserHasAccessToMatchingRule(requestCtx, vexRules, rulesInSessionOrg, vuln); err != nil {
		return traceErr(err)
	} else if ok {
		project, err := s.assetRepository.ReadWithProject(requestCtx, tx, rule.AssetID)
		if err != nil {
			return traceErr(err)
		}
		return transformer.VEXRuleToOriginRecommendationDTO(rule, project.Slug, rule.Asset.Slug), nil
	}

	recommendations, err := s.vexRuleRecommendationRepository.FindByDependencyVulnIDs(requestCtx, tx, []uuid.UUID{vulnID})
	if err != nil {
		return traceErr(err)
	}

	best, ok := bestRecommendation(recommendations)
	if !ok {
		return dtos.VexRuleRecommendation{}, nil
	}

	return transformer.VEXRuleRecommendationToDTO(best), nil
}

// bestRecommendation returns the recommendation with the highest confidence.
func bestRecommendation(recommendations []models.VEXRuleRecommendation) (models.VEXRuleRecommendation, bool) {
	if len(recommendations) == 0 {
		return models.VEXRuleRecommendation{}, false
	}
	best := recommendations[0]
	for _, rec := range recommendations[1:] {
		if rec.Confidence > best.Confidence {
			best = rec
		}
	}
	return best, true
}

// return type is keyed by dependency vuln ID
func (s *VEXRuleService) RecommendBatch(ctx shared.Context, tx shared.DB, vulns []models.DependencyVuln) (map[string]dtos.VexRuleRecommendation, error) {
	requestCtx, span := servicesTracer.Start(ctx.Request().Context(), "CrowdsourcedVexingService.RecommendBatch")
	defer span.End()
	span.SetAttributes(attribute.Int("dependencyVulns.total", len(vulns)))

	traceErr := func(err error) (map[string]dtos.VexRuleRecommendation, error) {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	vexRules, err := s.vexRuleRepository.All(requestCtx, tx)
	if err != nil {
		return traceErr(err)
	}

	rulesInSessionOrg, err := rulesInSessionOrg(ctx, vexRules)
	if err != nil {
		return traceErr(err)
	}

	vulnIDs := utils.Map(vulns, func(v models.DependencyVuln) uuid.UUID { return v.ID })
	storedRecommendations, err := s.vexRuleRecommendationRepository.FindByDependencyVulnIDs(requestCtx, tx, vulnIDs)
	if err != nil {
		return traceErr(err)
	}
	recommendationsByVulnID := make(map[uuid.UUID][]models.VEXRuleRecommendation, len(storedRecommendations))
	for _, rec := range storedRecommendations {
		recommendationsByVulnID[rec.DependencyVulnID] = append(recommendationsByVulnID[rec.DependencyVulnID], rec)
	}

	type vulnRecommendation struct {
		id  string
		dto dtos.VexRuleRecommendation
	}

	eg := utils.ErrGroup[*vulnRecommendation](100)
	for _, vuln := range vulns {
		eg.Go(func() (*vulnRecommendation, error) {
			if rule, ok, err := checkIfUserHasAccessToMatchingRule(requestCtx, vexRules, rulesInSessionOrg, vuln); err != nil {
				return nil, err
			} else if ok {
				// we have the asset id, we need assetSlug and projectSlug to return the recommendation DTO
				asset, err := s.assetRepository.ReadWithProject(ctx.Request().Context(), nil, rule.AssetID)
				if err != nil {
					return nil, err
				}
				id, err := vexrules.IdentityOfRule(models.UpstreamVEXRule{
					CELExpression:           rule.CELExpression,
					MechanicalJustification: rule.MechanicalJustification,
					EventType:               rule.EventType,
				})
				if err != nil {
					slog.Warn("could not calculate identity of rule", "err", err)
					return nil, nil
				}
				return &vulnRecommendation{id: id, dto: transformer.VEXRuleToOriginRecommendationDTO(rule, asset.Slug, asset.Project.Slug)}, nil
			}

			best, ok := bestRecommendation(recommendationsByVulnID[vuln.ID])
			if !ok {
				return nil, nil
			}

			id := best.VEXRuleID
			if id == "" {
				id = best.UpstreamVEXRuleID
			}
			return &vulnRecommendation{id: id, dto: transformer.VEXRuleRecommendationToDTO(best)}, nil
		})
	}
	results, err := eg.WaitAndCollect()
	if err != nil {
		return traceErr(err)
	}

	found := utils.Filter(results, func(res *vulnRecommendation) bool { return res != nil })
	recommendations := utils.Reduce(found, func(acc map[string]dtos.VexRuleRecommendation, res *vulnRecommendation) map[string]dtos.VexRuleRecommendation {
		if r, ok := acc[res.id]; ok {
			r.AppliesToAmountOfDependencyVulns++
			acc[res.id] = r
		} else {
			res.dto.AppliesToAmountOfDependencyVulns = 1
			acc[res.id] = res.dto
		}
		return acc
	}, make(map[string]dtos.VexRuleRecommendation, len(found)))
	span.SetAttributes(attribute.Int("recommendations.total", len(recommendations)))

	return recommendations, nil
}

func checkIfUserHasAccessToMatchingRule(ctx context.Context, vexRules []models.VEXRule, rulesInSessionOrg map[string]struct{}, vuln models.DependencyVuln) (models.VEXRule, bool, error) {
	if len(rulesInSessionOrg) == 0 {
		return models.VEXRule{}, false, nil
	}

	matches, err := vexrules.EvalRules(ctx, utils.Map(vexRules, transformer.VEXRuleToUpstreamVEXRule), vuln)
	if err != nil {
		return models.VEXRule{}, false, err
	}

	for _, rule := range vexRules {
		if !matches[rule.ID] {
			continue
		}
		if _, ok := rulesInSessionOrg[rule.ID]; ok {
			return rule, true, nil
		}
	}
	return models.VEXRule{}, false, nil
}

func checkIfSystemVexRuleMatchesVuln(ctx context.Context, vexRules []models.UpstreamVEXRule, vuln models.DependencyVuln) (models.UpstreamVEXRule, bool, error) {
	matches, err := vexrules.EvalRules(ctx, vexRules, vuln)
	if err != nil {
		return models.UpstreamVEXRule{}, false, err
	}

	for _, rule := range vexRules {
		if !matches[rule.ID] {
			continue
		}
		// just use the first rule and return it.
		return rule, true, nil
	}
	return models.UpstreamVEXRule{}, false, nil
}

func rulesInSessionOrg(ctx shared.Context, vexRules []models.VEXRule) (map[string]struct{}, error) {
	rbac := shared.GetRBAC(ctx)
	assetIDs, err := rbac.GetAllAssetsForSession(ctx.Request().Context(), shared.GetSession(ctx))
	if err != nil {
		return nil, err
	}
	assetIDSet := make(map[string]struct{}, len(assetIDs))
	for _, id := range assetIDs {
		assetIDSet[id] = struct{}{}
	}

	result := make(map[string]struct{})
	for _, rule := range vexRules {
		if _, ok := assetIDSet[rule.AssetID.String()]; ok {
			result[rule.ID] = struct{}{}
		}
	}
	return result, nil
}

func (s *VEXRuleService) buildCrowdsourcedVexingContext(ctx context.Context, tx shared.DB, vexRules []models.VEXRule) (crowdsourcedVexingContext, error) {
	projectIDs := utils.Map(vexRules, func(r models.VEXRule) uuid.UUID { return r.Asset.ProjectID })

	projects, err := s.projectRepository.GetByProjectIDs(ctx, tx, projectIDs)
	if err != nil {
		return crowdsourcedVexingContext{}, err
	}

	orgIDs := utils.Map(projects, func(p models.Project) uuid.UUID { return p.OrganizationID })

	orgs, err := s.organisationRepository.GetOrgByIDs(ctx, tx, orgIDs)
	if err != nil {
		return crowdsourcedVexingContext{}, err
	}

	projectTrustedEntities, err := s.trustedEntityRepository.GetTrustedEntitiesByProjectIDs(ctx, tx, projectIDs)
	if err != nil {
		return crowdsourcedVexingContext{}, err
	}
	projectTrustScores := make(map[uuid.UUID]float64, len(projectTrustedEntities))
	for _, te := range projectTrustedEntities {
		projectTrustScores[*te.ProjectID] = te.TrustScore
	}

	orgTrustedEntities, err := s.trustedEntityRepository.GetTrustedEntitiesByOrganizationIDs(ctx, tx, orgIDs)
	if err != nil {
		return crowdsourcedVexingContext{}, err
	}
	orgTrustScores := make(map[uuid.UUID]float64, len(orgTrustedEntities))
	for _, te := range orgTrustedEntities {
		orgTrustScores[*te.OrganizationID] = te.TrustScore
	}

	crowdSourceVexingOrgs := make([]crowdsourcevexing.Organization, len(orgs))
	for i, org := range orgs {
		domainRBAC := s.rbacProvider.GetDomainRBAC(org.ID.String())
		memberIDs, err := domainRBAC.GetAllMembersOfOrganization()
		if err != nil {
			return crowdsourcedVexingContext{}, err
		}
		ownerID, err := domainRBAC.GetOwnerOfOrganization()
		if err != nil {
			return crowdsourcedVexingContext{}, err
		}
		crowdSourceVexingOrgs[i] = mapOrg(org, orgTrustScores[org.ID], ownerID, memberIDs)
	}

	return crowdsourcedVexingContext{
		vexRules:              vexRules,
		crowdSourceVexingOrgs: crowdSourceVexingOrgs,
		crowdSourceVexingProj: utils.Map(projects, func(p models.Project) crowdsourcevexing.Project {
			return mapProject(p, projectTrustScores[p.ID])
		}),
		assets: utils.Map(vexRules, func(r models.VEXRule) models.Asset { return r.Asset }),
	}, nil
}

func (s *VEXRuleService) BuildAndSaveRecommendationsForAll(ctx context.Context, tx shared.DB) error {
	// we need to match ALL vulns against ALL rules to build the recommendations

	allVulns, err := s.dependencyVulnRepository.GetAllOpenVulnsWithoutEvents(ctx, tx)
	if err != nil {
		return fmt.Errorf("failed to fetch all open vulns: %w", err)
	}

	allRules, err := s.vexRuleRepository.All(ctx, tx)
	if err != nil {
		return fmt.Errorf("failed to fetch all VEX rules: %w", err)
	}
	// create a map of all rules for easy lookup
	mapOfRules := make(map[string]models.VEXRule, len(allRules))
	for _, rule := range allRules {
		mapOfRules[rule.ID] = rule
	}

	crowdsourcedCtx, err := s.buildCrowdsourcedVexingContext(ctx, tx, allRules)
	if err != nil {
		return fmt.Errorf("failed to build crowdsourced vexing context: %w", err)
	}

	// now we need to fetch all upstream rules as well
	upstreamRules, err := s.upstreamVEXRuleRepository.All(ctx, tx)
	if err != nil {
		return fmt.Errorf("failed to compile all upstream VEX rules: %w", err)
	}

	compiledVexRules, err := vexrules.CompileRules(ctx, transformer.VEXRulesToUpstreamVEXRules(allRules))
	if err != nil {
		return fmt.Errorf("failed to compile all VEX rules: %w", err)
	}
	compiledUpstreamRules, err := vexrules.CompileRules(ctx, upstreamRules)

	if err != nil {
		return fmt.Errorf("failed to compile all upstream VEX rules: %w", err)
	}

	vulnMaps, err := vexrules.PrepareVulnsForEval(ctx, allVulns)
	if err != nil {
		return fmt.Errorf("failed to prepare vulns for evaluation: %w", err)
	}

	vexRuleResults, err := vexrules.EvalCompiledRules(ctx, compiledVexRules, vulnMaps)
	upstreamRuleResults, err := vexrules.EvalCompiledRules(ctx, compiledUpstreamRules, vulnMaps)

	ruleRecommendations := make([]models.VEXRuleRecommendation, len(upstreamRuleResults))
	// all upstream rules are considered to be trusted
	// we can straight away create a recommendation based on them
	for vulnID, matchingRules := range upstreamRuleResults {
		parsedID, err := uuid.Parse(vulnID)
		if err != nil {
			continue
		}
		for _, ruleID := range matchingRules {
			ruleRecommendations = append(ruleRecommendations, models.VEXRuleRecommendation{
				UpstreamVEXRuleID: ruleID,
				DependencyVulnID:  parsedID,
			})
		}
	}

	// check if we find a recommendation using the crowdsourced approach first, if not, we fall back to the upstream rules.
	for vulnID, matchingRules := range vexRuleResults {
		parsedID, err := uuid.Parse(vulnID)
		if err != nil {
			continue
		}

		recommendedRule, confidence, votes, err := crowdsourcevexing.CrowdsourcedVexing(
			utils.Map(matchingRules, func(el string) models.VEXRule {
				return mapOfRules[el]
			}),
			crowdsourcedCtx.crowdSourceVexingOrgs,
			crowdsourcedCtx.crowdSourceVexingProj,
			crowdsourcedCtx.assets,
		)
		if err != nil {
			slog.Error("failed to execute crowdsourced vexing", "err", err)
			continue
		}

		ruleRecommendations = append(ruleRecommendations, models.VEXRuleRecommendation{
			UpstreamVEXRuleID: recommendedRule.ID,
			DependencyVulnID:  parsedID,
			Confidence:        confidence,
			VerifiedVotes:     votes.Verified,
			TotalVotes:        votes.Total,
		})
	}
	// delete all existing recommendations, then bulk-insert the freshly computed ones
	db := s.vexRuleRepository.GetDB(ctx, tx)
	if err := db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&models.VEXRuleRecommendation{}).Error; err != nil {
		return fmt.Errorf("failed to delete all VEX rule recommendations: %w", err)
	}

	if len(ruleRecommendations) == 0 {
		slog.Info("no VEX rule recommendations to save")
		return nil
	}

	slog.Info("saving VEX rule recommendations", "count", len(ruleRecommendations), "totalVulns", len(allVulns), "totalCrowdsourcedRules", len(allRules), "totalUpstreamRules", len(upstreamRules))

	if err := db.CreateInBatches(ruleRecommendations, 500).Error; err != nil {
		return fmt.Errorf("failed to save VEX rule recommendations: %w", err)
	}

	return nil
}

type crowdsourcedVexingContext struct {
	vexRules              []models.VEXRule
	crowdSourceVexingOrgs []crowdsourcevexing.Organization
	crowdSourceVexingProj []crowdsourcevexing.Project
	assets                []models.Asset
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
