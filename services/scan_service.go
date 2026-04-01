// Copyright (C) 2025 l3montree GmbH
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
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	databasetypes "github.com/l3montree-dev/devguard/database/types"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/dtos/sarif"
	"github.com/l3montree-dev/devguard/normalize"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/statemachine"
	"github.com/l3montree-dev/devguard/transformer"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/l3montree-dev/devguard/vulndb/scan"
	"github.com/package-url/packageurl-go"
	"github.com/pkg/errors"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"gorm.io/gorm"
)

type scanService struct {
	sbomScanner                 shared.SBOMScanner
	dependencyVulnService       shared.DependencyVulnService
	firstPartyVulnRepository    shared.FirstPartyVulnRepository
	dependencyVulnRepository    shared.DependencyVulnRepository
	thirdPartyIntegration       shared.IntegrationAggregate
	firstPartyVulnService       shared.FirstPartyVulnService
	cveRepository               shared.CveRepository
	csafService                 shared.CSAFService
	assetVersionService         shared.AssetVersionService
	vexRuleService              shared.VEXRuleService
	externalReferenceRepository shared.ExternalReferenceRepository
	componentService            shared.ComponentService
	// mark public to let it be overridden in tests
	utils.FireAndForgetSynchronizer
}

var _ shared.ScanService = (*scanService)(nil)

func NewScanService(
	db shared.DB,
	cveRepository shared.CveRepository,
	dependencyVulnService shared.DependencyVulnService,
	synchronizer utils.FireAndForgetSynchronizer,
	firstPartyVulnService shared.FirstPartyVulnService,
	firstPartyVulnRepository shared.FirstPartyVulnRepository,
	dependencyVulnRepository shared.DependencyVulnRepository,
	thirdPartyIntegration shared.IntegrationAggregate,
	csafService shared.CSAFService,
	assetVersionService shared.AssetVersionService,
	vexRuleService shared.VEXRuleService,
	externalReferenceRepository shared.ExternalReferenceRepository,
	componentService shared.ComponentService,
) *scanService {
	purlComparer := scan.NewPurlComparer(db)
	scanner := scan.NewSBOMScanner(purlComparer, cveRepository)
	return &scanService{
		sbomScanner:                 scanner,
		dependencyVulnService:       dependencyVulnService,
		firstPartyVulnRepository:    firstPartyVulnRepository,
		firstPartyVulnService:       firstPartyVulnService,
		FireAndForgetSynchronizer:   synchronizer,
		dependencyVulnRepository:    dependencyVulnRepository,
		thirdPartyIntegration:       thirdPartyIntegration,
		cveRepository:               cveRepository,
		csafService:                 csafService,
		assetVersionService:         assetVersionService,
		vexRuleService:              vexRuleService,
		externalReferenceRepository: externalReferenceRepository,
		componentService:            componentService,
	}
}

var _ shared.ScanService = &scanService{}

func (s *scanService) ScanNormalizedSBOM(ctx context.Context, tx shared.DB, org models.Org, project models.Project, asset models.Asset, assetVersion models.AssetVersion, artifact models.Artifact, normalizedBom *normalize.SBOMGraph, userID string) ([]models.DependencyVuln, []models.DependencyVuln, []models.DependencyVuln, error) {
	ctx, span := servicesTracer.Start(ctx, "scanService.ScanNormalizedSBOM")
	defer span.End()

	span.SetAttributes(
		attribute.String("artifact.name", artifact.ArtifactName),
		attribute.String("asset.slug", asset.Slug),
		attribute.String("assetVersion.name", assetVersion.Name),
	)

	// remove all other artifacts from the bom
	err := normalizedBom.ScopeToArtifact(artifact.ArtifactName)
	if err != nil {
		// If artifact node is not reachable, it means the artifact has no components (empty artifact)
		// This is a valid scenario, so we return early with no vulnerabilities
		if errors.Is(err, normalize.ErrNodeNotReachable) {
			slog.Debug("artifact has no components, skipping scan", "artifactName", artifact.ArtifactName)
			return nil, nil, nil, nil
		}
		slog.Error("could not scope bom to artifact", "err", err)
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, nil, nil, err
	}

	scanCtx, scanSpan := servicesTracer.Start(ctx, "SBOMScanner.Scan")
	vulns, err := s.sbomScanner.Scan(scanCtx, normalizedBom)
	scanSpan.SetAttributes(attribute.Int("vulns.found", len(vulns)))
	scanSpan.End()

	if err != nil {
		slog.Error("could not scan file", "err", err)
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, nil, nil, err
	}

	// handle the scan result
	resultCtx, resultSpan := servicesTracer.Start(ctx, "scanService.HandleScanResult")
	opened, closed, newState, err := s.HandleScanResult(resultCtx, tx, org, project, asset, &assetVersion, normalizedBom, vulns, artifact.ArtifactName, userID)
	resultSpan.End()
	if err != nil {
		slog.Error("could not handle scan result", "err", err)
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, nil, nil, err
	}

	rules, err := s.vexRuleService.FindByAssetVersion(ctx, tx, asset.ID, assetVersion.Name)
	if err != nil {
		slog.Error("failed to fetch VEX rules for asset version", "error", err)
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, nil, nil, fmt.Errorf("failed to fetch VEX rules for asset version: %w", err)
	}

	// apply the vex rules to the new state
	newState, err = s.vexRuleService.ApplyRulesToExisting(ctx, tx, rules, newState)
	if err != nil {
		slog.Error("failed to apply VEX rules to new state", "error", err)
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, nil, nil, fmt.Errorf("failed to apply VEX rules to new state: %w", err)
	}

	span.SetAttributes(
		attribute.Int("scan.opened", len(opened)),
		attribute.Int("scan.closed", len(closed)),
		attribute.Int("scan.total", len(newState)),
	)

	return opened, closed, newState, nil
}

func (s *scanService) HandleFirstPartyVulnResult(ctx context.Context, org models.Org, project models.Project, asset models.Asset, assetVersion *models.AssetVersion, sarifScan sarif.SarifSchema210Json, scannerID string, userID string) ([]models.FirstPartyVuln, []models.FirstPartyVuln, []models.FirstPartyVuln, error) {
	ctx, span := servicesTracer.Start(ctx, "scanService.HandleFirstPartyVulnResult")
	defer span.End()

	span.SetAttributes(
		attribute.String("scanner.id", scannerID),
		attribute.String("asset.slug", asset.Slug),
		attribute.String("assetVersion.name", assetVersion.Name),
	)

	firstPartyVulnerabilitiesMap := make(map[string]models.FirstPartyVuln)

	ruleMap := make(map[string]sarif.ReportingDescriptor)
	for _, run := range sarifScan.Runs {
		for _, rule := range run.Tool.Driver.Rules {
			ruleMap[rule.ID] = rule
		}
	}

	for _, run := range sarifScan.Runs {
		for _, result := range run.Results {
			if slices.Contains(sarifResultKindsIndicatingNotAndIssue, string(result.Kind)) {
				continue
			}

			rule := ruleMap[utils.OrDefault(result.RuleID, "")]

			ruleProperties := map[string]any{}
			if rule.Properties != nil {
				ruleProperties = rule.Properties.AdditionalProperties
			}

			firstPartyVulnerability := models.FirstPartyVuln{
				Vulnerability: models.Vulnerability{
					AssetVersionName: assetVersion.Name,
					AssetID:          asset.ID,
					Message:          &result.Message.Text,
				},
				ScannerIDs:      scannerID,
				RuleID:          utils.OrDefault(result.RuleID, ""),
				RuleHelp:        preferMarkdown(utils.OrDefault(rule.Help, sarif.MultiformatMessageString{})),
				RuleName:        utils.OrDefault(rule.Name, ""),
				RuleHelpURI:     utils.OrDefault(rule.HelpURI, ""),
				RuleDescription: getBestDescription(rule),
				RuleProperties:  databasetypes.JSONB(ruleProperties),
			}
			if result.PartialFingerprints != nil {
				firstPartyVulnerability.Commit = result.PartialFingerprints["commitSha"]
				firstPartyVulnerability.Email = result.PartialFingerprints["email"]
				firstPartyVulnerability.Author = result.PartialFingerprints["author"]
				firstPartyVulnerability.Date = result.PartialFingerprints["date"]
			}

			var hash string
			if result.Fingerprints != nil {
				if result.Fingerprints["calculatedFingerprint"] != "" {
					firstPartyVulnerability.Fingerprint = result.Fingerprints["calculatedFingerprint"]
				}
			}

			if len(result.Locations) > 0 {
				loc := result.Locations[0]
				firstPartyVulnerability.URI = utils.OrDefault(loc.PhysicalLocation.ArtifactLocation.URI, "")

				var snippetContent dtos.SnippetContent

				if loc.PhysicalLocation.Region == nil {
					snippetContent = dtos.SnippetContent{
						StartLine:   0,
						EndLine:     0,
						StartColumn: 0,
						EndColumn:   0,
						Snippet:     "",
					}
				} else {
					snippetContent = dtos.SnippetContent{
						StartLine:   utils.OrDefault(loc.PhysicalLocation.Region.StartLine, 0),
						EndLine:     utils.OrDefault(loc.PhysicalLocation.Region.EndLine, 0),
						StartColumn: utils.OrDefault(loc.PhysicalLocation.Region.StartColumn, 0),
						EndColumn:   utils.OrDefault(loc.PhysicalLocation.Region.EndColumn, 0),
						Snippet:     utils.OrDefault(loc.PhysicalLocation.Region.Snippet.Text, ""),
					}
				}

				hash = firstPartyVulnerability.CalculateHash()
				if existingVuln, ok := firstPartyVulnerabilitiesMap[hash]; ok {
					snippetContents, err := transformer.FromJSONSnippetContents(existingVuln)
					if err != nil {
						return []models.FirstPartyVuln{}, []models.FirstPartyVuln{}, []models.FirstPartyVuln{}, errors.Wrap(err, "could not parse existing snippet contents")
					}
					snippetContents.Snippets = append(snippetContents.Snippets, snippetContent)
					firstPartyVulnerability.SnippetContents, err = transformer.SnippetContentsToJSON(snippetContents)
					if err != nil {
						return []models.FirstPartyVuln{}, []models.FirstPartyVuln{}, []models.FirstPartyVuln{}, errors.Wrap(err, "could not convert snippet contents to JSON")
					}

				} else {

					snippetContents := dtos.SnippetContents{
						Snippets: []dtos.SnippetContent{snippetContent},
					}
					var err error
					firstPartyVulnerability.SnippetContents, err = transformer.SnippetContentsToJSON(snippetContents)
					if err != nil {
						return []models.FirstPartyVuln{}, []models.FirstPartyVuln{}, []models.FirstPartyVuln{}, errors.Wrap(err, "could not convert snippet contents to JSON")
					}

				}
				firstPartyVulnerabilitiesMap[hash] = firstPartyVulnerability

			}

		}
	}
	var firstPartyVulnerabilities []models.FirstPartyVuln
	for _, vuln := range firstPartyVulnerabilitiesMap {
		firstPartyVulnerabilities = append(firstPartyVulnerabilities, vuln)
	}

	opened, closed, newState, err := s.handleFirstPartyVulnResult(ctx, nil, userID, scannerID, assetVersion, firstPartyVulnerabilities, asset, org, project)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return []models.FirstPartyVuln{}, []models.FirstPartyVuln{}, []models.FirstPartyVuln{}, err
	}

	if assetVersion.Metadata == nil {
		assetVersion.Metadata = make(map[string]any)
	}

	assetVersion.Metadata[scannerID] = models.ScannerInformation{LastScan: utils.Ptr(time.Now())}

	span.SetAttributes(
		attribute.Int("scan.opened", len(opened)),
		attribute.Int("scan.closed", len(closed)),
		attribute.Int("scan.total", len(newState)),
	)
	return opened, closed, newState, nil
}

func (s *scanService) handleFirstPartyVulnResult(ctx context.Context, tx *gorm.DB, userID string, scannerID string, assetVersion *models.AssetVersion, vulns []models.FirstPartyVuln, asset models.Asset, org models.Org, project models.Project) ([]models.FirstPartyVuln, []models.FirstPartyVuln, []models.FirstPartyVuln, error) {
	// get all existing vulns from the database, which are not fixed yet - this is the old state
	existingVulns, err := s.firstPartyVulnRepository.ListUnfixedByAssetAndAssetVersionAndScanner(ctx, tx, assetVersion.Name, assetVersion.AssetID, scannerID)
	if err != nil {
		slog.Error("could not get existing first party vulns", "err", err)
		return []models.FirstPartyVuln{}, []models.FirstPartyVuln{}, []models.FirstPartyVuln{}, err
	}

	existingVulnsOnOtherBranch, err := s.firstPartyVulnRepository.GetFirstPartyVulnsByOtherAssetVersions(ctx, tx, assetVersion.Name, assetVersion.AssetID, scannerID)
	if err != nil {
		slog.Error("could not get existing vulns on other branches", "err", err)
		return []models.FirstPartyVuln{}, []models.FirstPartyVuln{}, []models.FirstPartyVuln{}, err
	}

	existingVulnsOnOtherBranch = utils.Filter(existingVulnsOnOtherBranch, func(dependencyVuln models.FirstPartyVuln) bool {
		return dependencyVuln.State != dtos.VulnStateFixed
	})

	comparison := utils.CompareSlices(existingVulns, vulns, func(vuln models.FirstPartyVuln) string {
		return vuln.CalculateHash()
	})

	newVulns := comparison.OnlyInB
	inBoth := comparison.InBoth // these are the vulns that are already in the database, but we need to update them
	updatedFirstPartyVulns := make([]models.FirstPartyVuln, 0)

	for i := range inBoth {
		for n := range vulns {
			if inBoth[i].ID == vulns[n].ID {
				// we found a new vuln that is already in the database, we need to update it
				inBoth[i].SnippetContents = vulns[n].SnippetContents
				updatedFirstPartyVulns = append(updatedFirstPartyVulns, inBoth[i])
			}
		}
	}
	// filter out any vulnerabilities which were already fixed, by only keeping the open ones
	fixedVulns := utils.Filter(comparison.OnlyInA, func(vuln models.FirstPartyVuln) bool {
		return vuln.State == dtos.VulnStateOpen
	})

	branchDiff := statemachine.DiffVulnsBetweenBranches(utils.Map(newVulns, utils.Ptr), utils.Map(existingVulnsOnOtherBranch, utils.Ptr))

	// get a transaction
	if err := s.firstPartyVulnRepository.Transaction(ctx, func(tx shared.DB) error {
		// Process new vulnerabilities that exist on other branches with lifecycle management
		if err := s.firstPartyVulnService.UserDetectedExistingFirstPartyVulnOnDifferentBranch(ctx, tx, scannerID, branchDiff.ExistingOnOtherBranches, *assetVersion, asset); err != nil {
			slog.Error("error when trying to add events for existing first party vulnerability on different branch", "err", err)
			return err
		}

		// Process new vulnerabilities that don't exist on other branches
		if err := s.firstPartyVulnService.UserDetectedFirstPartyVulns(ctx, tx, userID, scannerID, utils.DereferenceSlice(branchDiff.NewToAllBranches)); err != nil {
			return err
		}

		// Process fixed vulnerabilities
		if err := s.firstPartyVulnService.UserFixedFirstPartyVulns(ctx, tx, userID, fixedVulns); err != nil {
			return err
		}

		// update existing first party vulns within the transaction
		for _, v := range updatedFirstPartyVulns {
			if err := s.firstPartyVulnRepository.Save(ctx, tx, &v); err != nil {
				slog.Error("could not update existing first party vulns", "err", err)
				return err
			}
		}
		return nil
	}); err != nil {
		slog.Error("could not save vulns", "err", err)
		return []models.FirstPartyVuln{}, []models.FirstPartyVuln{}, []models.FirstPartyVuln{}, err
	}

	if len(branchDiff.NewToAllBranches) > 0 && (assetVersion.DefaultBranch || assetVersion.Type == models.AssetVersionTag) {
		// detach from request context but keep the trace for background integration work
		linkedCtx := trace.ContextWithSpan(context.Background(), trace.SpanFromContext(ctx))
		s.FireAndForget(func() {
			if err = s.thirdPartyIntegration.HandleEvent(linkedCtx, shared.FirstPartyVulnsDetectedEvent{
				AssetVersion: shared.ToAssetVersionObject(*assetVersion),
				Asset:        shared.ToAssetObject(asset),
				Project:      shared.ToProjectObject(project),
				Org:          shared.ToOrgObject(org),
				Vulns:        utils.Map(utils.DereferenceSlice(branchDiff.NewToAllBranches), transformer.FirstPartyVulnToDto),
			}); err != nil {
				slog.Error("could not handle first party vulnerabilities detected event", "err", err)
			}
		})
	}

	v, err := s.firstPartyVulnRepository.ListUnfixedByAssetAndAssetVersionAndScanner(ctx, nil, assetVersion.Name, assetVersion.AssetID, scannerID)
	if err != nil {
		slog.Error("could not get existing first party vulns", "err", err)
		return []models.FirstPartyVuln{}, []models.FirstPartyVuln{}, []models.FirstPartyVuln{}, err
	}

	return utils.DereferenceSlice(branchDiff.NewToAllBranches), fixedVulns, v, nil
}

func (s *scanService) HandleScanResult(ctx context.Context, tx shared.DB, org models.Org, project models.Project, asset models.Asset, assetVersion *models.AssetVersion, sbom *normalize.SBOMGraph, vulns []models.VulnInPackage, artifactName string, userID string) (opened []models.DependencyVuln, closed []models.DependencyVuln, newState []models.DependencyVuln, err error) {
	ctx, span := servicesTracer.Start(ctx, "scanService.HandleScanResult")
	defer span.End()
	span.SetAttributes(
		attribute.String("artifact.name", artifactName),
		attribute.String("asset.slug", asset.Slug),
		attribute.String("assetVersion.name", assetVersion.Name),
		attribute.Int("scan.input_vuln_count", len(vulns)),
	)

	// scope the sbom to the current artifact only
	err = sbom.ScopeToArtifact(artifactName)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return []models.DependencyVuln{}, []models.DependencyVuln{}, []models.DependencyVuln{}, errors.Wrap(err, "could not scope sbom to artifact")
	}
	// create dependencyVulns out of those vulnerabilities - one per unique path
	// Pre-allocate with estimated capacity (assume ~2 paths per vuln on average)
	dependencyVulns := make([]models.DependencyVuln, 0, len(vulns)*2)

	for _, vuln := range vulns {
		dependencyVulns = append(dependencyVulns, transformer.VulnInPackageToDependencyVulns(vuln, sbom, asset.ID, assetVersion.Name, artifactName)...)
		if len(dependencyVulns) > 10000 {
			// unique those
			dependencyVulns = utils.UniqBy(dependencyVulns, func(f models.DependencyVuln) string {
				return f.CalculateHash()
			})
		}
	}

	dependencyVulns = utils.UniqBy(dependencyVulns, func(f models.DependencyVuln) string {
		return f.CalculateHash()
	})

	opened, closed, newState, err = s.handleScanResult(ctx, tx, userID, artifactName, assetVersion, sbom, dependencyVulns, asset)
	if err != nil {
		return []models.DependencyVuln{}, []models.DependencyVuln{}, []models.DependencyVuln{}, err
	}

	if assetVersion.Metadata == nil {
		assetVersion.Metadata = make(map[string]any)
	}

	assetVersion.Metadata[artifactName] = models.ScannerInformation{LastScan: utils.Ptr(time.Now())}

	newState, err = s.dependencyVulnService.RecalculateRawRiskAssessment(ctx, tx, "system", newState, "", asset)
	if err != nil {
		slog.Error("could not recalculate raw risk assessment", "err", err)
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return opened, closed, newState, errors.Wrap(err, "could not recalculate raw risk assessment")
	}

	span.SetAttributes(
		attribute.Int("scan.opened", len(opened)),
		attribute.Int("scan.closed", len(closed)),
		attribute.Int("scan.total", len(newState)),
	)

	// detach from request context (avoids cancellation on response) but keep the trace
	linkedCtx := trace.ContextWithSpan(context.Background(), span)

	if len(opened) > 0 && (assetVersion.DefaultBranch || assetVersion.Type == models.AssetVersionTag) {
		s.FireAndForget(func() {
			if err = s.thirdPartyIntegration.HandleEvent(linkedCtx, shared.DependencyVulnsDetectedEvent{
				AssetVersion: shared.ToAssetVersionObject(*assetVersion),
				Asset:        shared.ToAssetObject(asset),
				Project:      shared.ToProjectObject(project),
				Org:          shared.ToOrgObject(org),
				Vulns:        utils.Map(opened, transformer.DependencyVulnToDTO),
				Artifact: shared.ArtifactObject{
					ArtifactName: artifactName,
				},
			}); err != nil {
				slog.Error("could not handle dependency vulnerabilities detected event", "err", err)
			}
		})
	}
	return opened, closed, newState, nil
}

func (s *scanService) handleScanResult(ctx context.Context, tx shared.DB, userID string, artifactName string, assetVersion *models.AssetVersion, sbom *normalize.SBOMGraph, dependencyVulns []models.DependencyVuln, asset models.Asset) ([]models.DependencyVuln, []models.DependencyVuln, []models.DependencyVuln, error) {
	existingDependencyVulns, err := s.dependencyVulnRepository.ListByAssetAndAssetVersion(ctx, nil, assetVersion.Name, assetVersion.AssetID)
	if err != nil {
		slog.Error("could not get existing dependencyVulns", "err", err)
		return []models.DependencyVuln{}, []models.DependencyVuln{}, []models.DependencyVuln{}, err
	}

	// get all vulns from other branches
	existingVulnsOnOtherBranch, err := s.dependencyVulnRepository.GetDependencyVulnsByOtherAssetVersions(ctx, tx, assetVersion.Name, assetVersion.AssetID)
	if err != nil {
		slog.Error("could not get existing dependencyVulns on default branch", "err", err)
		return []models.DependencyVuln{}, []models.DependencyVuln{}, []models.DependencyVuln{}, err
	}

	// Keep all fixed vulns in existingDependencyVulns so that when a component reappears,
	// the vuln lands in Unchanged rather than NewlyDiscovered. This lets us fire an
	// explicit reopened event instead of silently resetting state via a detected event.
	existingVulnsOnOtherBranch = utils.Filter(existingVulnsOnOtherBranch, func(dv models.DependencyVuln) bool {
		return dv.State != dtos.VulnStateFixed
	})

	diff := statemachine.DiffScanResults(artifactName, dependencyVulns, existingDependencyVulns)
	// remove from fixed vulns and fixed on this artifact name all vulns, that have more than a single path to them
	// this means, that another source is still saying, its part of this artifact
	unfixablePurls := sbom.ComponentsWithMultipleSources()
	filterPredicate := func(dv models.DependencyVuln) bool {
		return !slices.Contains(unfixablePurls, dv.ComponentPurl)
	}

	// Only generate fix events for vulns that are not already fixed, to avoid duplicate events.
	fixedVulns := utils.Filter(diff.FixedEverywhere, func(dv models.DependencyVuln) bool {
		return filterPredicate(dv) && dv.State != dtos.VulnStateFixed
	})
	fixedOnThisArtifactName := utils.Filter(diff.RemovedFromArtifact, filterPredicate)

	// newDetectedVulnsNotOnOtherBranch, newDetectedButOnOtherBranchExisting, existingEvents := diffVulnsBetweenBranches(diff.NewlyDiscovered, existingVulnsOnOtherBranch)
	branchDiff := statemachine.DiffVulnsBetweenBranches(utils.Map(diff.NewlyDiscovered, utils.Ptr), utils.Map(existingVulnsOnOtherBranch, utils.Ptr))

	// make sure to first create a user detected event for vulnerabilities with just upstream events
	// this way we preserve the event history
	if err := s.dependencyVulnService.UserDetectedExistingVulnOnDifferentBranch(ctx, tx, artifactName, branchDiff.ExistingOnOtherBranches, *assetVersion, asset); err != nil {
		slog.Error("error when trying to add events for existing vulnerability on different branch")
		return []models.DependencyVuln{}, []models.DependencyVuln{}, []models.DependencyVuln{}, err
	}
	// We can create the newly found one without checking anything
	if err := s.dependencyVulnService.UserDetectedDependencyVulns(ctx, tx, artifactName, utils.DereferenceSlice(branchDiff.NewToAllBranches), *assetVersion, asset); err != nil {
		return []models.DependencyVuln{}, []models.DependencyVuln{}, []models.DependencyVuln{}, err
	}

	err = s.dependencyVulnService.UserDetectedDependencyVulnInAnotherArtifact(ctx, tx, diff.NewInArtifact, artifactName)
	if err != nil {
		slog.Error("error when trying to add events for adding scanner to vulnerability")
		return []models.DependencyVuln{}, []models.DependencyVuln{}, []models.DependencyVuln{}, err
	}

	err = s.dependencyVulnService.UserDidNotDetectDependencyVulnInArtifactAnymore(ctx, tx, fixedOnThisArtifactName, artifactName)
	if err != nil {
		slog.Error("error when trying to add events for removing scanner from vulnerability")
		return []models.DependencyVuln{}, []models.DependencyVuln{}, []models.DependencyVuln{}, err
	}

	if err := s.dependencyVulnService.UserFixedDependencyVulns(ctx, tx, userID, fixedVulns, *assetVersion, asset); err != nil {
		slog.Error("error when trying to add fix event")
		return []models.DependencyVuln{}, []models.DependencyVuln{}, []models.DependencyVuln{}, err
	}

	// Vulns that were fixed and now the component reappeared: fire an explicit reopened event
	// instead of silently resetting state via the detected path on a fresh struct.
	vulnsToReopen := utils.Filter(diff.Unchanged, func(dv models.DependencyVuln) bool {
		return dv.State == dtos.VulnStateFixed
	})
	if err := s.dependencyVulnService.UserReopenedToOpen(ctx, tx, userID, vulnsToReopen); err != nil {
		slog.Error("error when trying to reopen previously fixed vulnerability")
		return []models.DependencyVuln{}, []models.DependencyVuln{}, []models.DependencyVuln{}, err
	}

	v, err := s.dependencyVulnRepository.ListUnfixedByAssetAndAssetVersion(ctx, tx, assetVersion.Name, assetVersion.AssetID, &artifactName)
	if err != nil {
		slog.Error("could not get existing dependencyVulns", "err", err)
		return []models.DependencyVuln{}, []models.DependencyVuln{}, []models.DependencyVuln{}, err
	}

	return append(utils.DereferenceSlice(branchDiff.NewToAllBranches), vulnsToReopen...), fixedVulns, v, nil
}

func (s *scanService) FetchSbomsFromUpstream(ctx context.Context, artifactName string, ref string, upstreamURLs []string, keepOriginalSbomRootComponent bool) (boms []*normalize.SBOMGraph, validURLs []string, invalidURLs []dtos.ExternalReferenceError) {
	client := &http.Client{Transport: utils.EgressTransport}
	//check if the upstream urls are valid urls
	for _, url := range upstreamURLs {
		url = normalize.SanitizeExternalReferencesURL(url)
		// skip CSAF URLs - they're handled separately
		if strings.HasSuffix(url, "/provider-metadata.json") {
			continue
		}
		//check if the file is a valid url
		if url == "" || !strings.HasPrefix(url, "http") {
			invalidURLs = append(invalidURLs, dtos.ExternalReferenceError{
				URL:    url,
				Reason: "invalid url, no http prefix found",
			})
			continue
		}

		var bom cyclonedx.BOM
		ctx, cancel := context.WithTimeout(ctx, time.Second*30)
		defer cancel()
		// fetch the file from the url
		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)

		if err != nil {
			invalidURLs = append(invalidURLs, dtos.ExternalReferenceError{
				URL:    url,
				Reason: fmt.Sprintf("could not create request for url: %v", err),
			})
			continue
		}

		resp, err := client.Do(req)
		if err != nil || resp.StatusCode != 200 {
			invalidURLs = append(invalidURLs, dtos.ExternalReferenceError{
				URL:    url,
				Reason: fmt.Sprintf("could not fetch url or non 200 status code: %v", err),
			})
			continue
		}
		defer resp.Body.Close()

		// download the url and check if it is a valid sbom
		file, err := io.ReadAll(resp.Body)
		if err != nil {
			invalidURLs = append(invalidURLs, dtos.ExternalReferenceError{
				URL:    url,
				Reason: fmt.Sprintf("could not read response body: %v", err),
			})
			continue
		}

		err = json.Unmarshal(file, &bom)
		if err != nil {
			invalidURLs = append(invalidURLs, dtos.ExternalReferenceError{
				URL:    url,
				Reason: fmt.Sprintf("could not unmarshal response body into cyclonedx bom: %v", err),
			})
			continue
		}

		// Only process SBOMs (not VEX)
		if normalize.BomIsSBOM(&bom) {
			normalizedBOM, err := normalize.SBOMGraphFromCycloneDX(&bom, artifactName, url, keepOriginalSbomRootComponent)
			if err != nil {
				slog.Warn("could not normalize sbom from url", "err", err, "url", url)
				invalidURLs = append(invalidURLs, dtos.ExternalReferenceError{
					URL:    url,
					Reason: fmt.Sprintf("could not normalize sbom: %v", err),
				})
				continue
			}

			validURLs = append(validURLs, url)
			// add the sbom prefix
			boms = append(boms, normalizedBOM)
		}
	}

	return boms, validURLs, invalidURLs
}

func (s *scanService) FetchVexFromUpstream(ctx context.Context, upstreamURLs []models.ExternalReference) (vexReports []*normalize.VexReport, valid []models.ExternalReference, invalid []models.ExternalReference) {
	client := &http.Client{Transport: utils.EgressTransport}
	//check if the upstream urls are valid urls
	for _, ref := range upstreamURLs {
		switch ref.Type {
		case models.ExternalReferenceTypeCSAF:
			purl, err := packageurl.FromString(ref.CSAFPackageScope)
			if err != nil {
				// this should actually never happen, because we validate the purl on creation of the external reference, but just to be sure, we catch this error and continue with the next url
				invalid = append(invalid, ref)
				continue
			}

			bom, err := s.csafService.GetVexFromCsafProvider(ctx, purl, ref.URL)
			if err != nil {
				slog.Warn("could not download csaf from csaf provider", "err", err)
				invalid = append(invalid, ref)
				continue
			}

			vexReport, err := normalize.NewVexReport(bom, ref.URL)
			if err != nil {
				slog.Warn("could not normalize csaf from csaf provider", "err", err)
				invalid = append(invalid, ref)
				continue
			}

			valid = append(valid, ref)
			vexReports = append(vexReports, vexReport)

		case models.ExternalReferenceTypeCycloneDxVEX:
			//check if the file is a valid url

			if ref.URL == "" || !strings.HasPrefix(ref.URL, "http") {
				invalid = append(invalid, ref)
				continue
			}

			var bom cyclonedx.BOM
			ctx, cancel := context.WithTimeout(ctx, time.Second*30)
			defer cancel()
			// fetch the file from the url
			req, err := http.NewRequestWithContext(ctx, "GET", ref.URL, nil)

			if err != nil {
				invalid = append(invalid, ref)
				continue
			}

			resp, err := client.Do(req)
			if err != nil || resp.StatusCode != 200 {
				invalid = append(invalid, ref)
				continue
			}
			defer resp.Body.Close()

			// download the url and check if it is a valid vex file
			file, err := io.ReadAll(resp.Body)
			if err != nil {
				invalid = append(invalid, ref)
				continue
			}

			err = json.Unmarshal(file, &bom)
			if err != nil {
				invalid = append(invalid, ref)
				continue
			}

			// Only process VEX (not SBOMs)
			if !normalize.BomIsSBOM(&bom) {
				valid = append(valid, ref)
				vexReports = append(vexReports, &normalize.VexReport{
					Report: &bom,
					Source: ref.URL,
				})
			}
		}
	}

	return vexReports, valid, invalid
}

// RunArtifactSecurityLifecycle orchestrates the complete security lifecycle for an artifact:
// 1. Fetches information sources (SBOM URLs) from the artifact
// 2. Fetches VEX URLs from external references
// 3. Fetches SBOMs and VEX reports from upstream
// 4. Updates the SBOM in the database
// 5. Scans the normalized SBOM for vulnerabilities
// 6. Ingests VEX rules
// It returns the normalized BOM and VEX reports for further processing if needed
func (s *scanService) RunArtifactSecurityLifecycle(ctx context.Context,
	tx shared.DB,
	org models.Org,
	project models.Project,
	asset models.Asset,
	assetVersion models.AssetVersion,
	artifact models.Artifact,
	userID string,
) (*normalize.SBOMGraph, []*normalize.VexReport, []models.DependencyVuln, error) {
	// Fetch information sources (SBOM URLs) from the artifact
	rootNodes, err := s.componentService.FetchInformationSources(ctx, nil, &artifact)
	if err != nil {
		slog.Error("failed to fetch information sources", "error", err, "artifactName", artifact.ArtifactName)
		return nil, nil, nil, fmt.Errorf("failed to fetch information sources: %w", err)
	}

	// Extract unique HTTP URLs from information sources
	sbomUpstreamURLs := utils.UniqBy(utils.Filter(utils.Map(rootNodes, func(el models.ComponentDependency) string {
		_, origin := normalize.RemoveInformationSourcePrefixIfExists(el.DependencyID)
		return origin
	}), func(el string) bool {
		return strings.HasPrefix(el, "http")
	}), func(el string) string {
		return el
	})

	// Fetch VEX URLs from external references
	vexRefs, err := s.externalReferenceRepository.FindByAssetVersion(ctx, tx, asset.ID, assetVersion.Name)
	if err != nil {
		slog.Error("failed to fetch vex external references", "error", err, "artifactName", artifact.ArtifactName)
		// Don't fail the entire operation if fetching external refs fails
	}

	// Fetch SBOMs and VEX reports from upstream
	boms, _, _ := s.FetchSbomsFromUpstream(ctx, artifact.ArtifactName, assetVersion.Name, sbomUpstreamURLs, asset.KeepOriginalSbomRootComponent)
	vexReports, _, _ := s.FetchVexFromUpstream(ctx, vexRefs)
	// Merge all BOMs into a single graph
	newGraph := normalize.NewSBOMGraph()
	for _, bom := range boms {
		newGraph.MergeGraph(bom)
	}

	// Update SBOM in database
	normalizedBom, err := s.assetVersionService.UpdateSBOM(
		ctx,
		tx,
		org,
		project,
		asset,
		assetVersion,
		artifact.ArtifactName,
		newGraph,
	)
	if err != nil {
		slog.Error("failed to update sbom in security lifecycle", "error", err, "artifactName", artifact.ArtifactName, "assetVersionName", assetVersion.Name)
		return nil, nil, nil, fmt.Errorf("failed to update sbom: %w", err)
	}

	// Scan the normalized SBOM for vulnerabilities
	_, _, dependencyVulns, err := s.ScanNormalizedSBOM(ctx, tx, org, project, asset, assetVersion, artifact, normalizedBom, userID)
	if err != nil {
		slog.Error("failed to scan normalized sbom in security lifecycle", "error", err, "artifactName", artifact.ArtifactName, "assetVersionName", assetVersion.Name)
		return nil, nil, nil, fmt.Errorf("failed to scan normalized sbom: %w", err)
	}

	// Ingest VEX rules
	if err := s.vexRuleService.IngestVexes(ctx, tx, asset, assetVersion, vexReports); err != nil {
		slog.Error("failed to ingest vex reports in security lifecycle", "error", err, "artifactName", artifact.ArtifactName, "assetVersionName", assetVersion.Name)
		return nil, nil, nil, fmt.Errorf("failed to ingest vex reports: %w", err)
	}

	return normalizedBom, vexReports, dependencyVulns, nil
}

func (s *scanService) ScanSBOMWithoutSaving(ctx context.Context, bom *cyclonedx.BOM) (dtos.ScanResponse, error) {
	normalized, err := normalize.SBOMGraphFromCycloneDX(bom, "scan", "DEFAULT", false)
	if err != nil {
		return dtos.ScanResponse{}, fmt.Errorf("invalid SBOM: %w", err)
	}

	vulns, err := s.sbomScanner.Scan(ctx, normalized)
	if err != nil {
		return dtos.ScanResponse{}, err
	}

	vulnDTOs := make([]dtos.DependencyVulnDTO, 0, len(vulns))
	for _, v := range vulns {
		dependencyVulns := transformer.VulnInPackageToDependencyVulnsWithoutArtifact(v, normalized, uuid.Nil, "")
		for _, dv := range dependencyVulns {
			vulnDTOs = append(vulnDTOs, dtos.DependencyVulnDTO{
				CVEID:                 dv.CVEID,
				CVE:                   transformer.CVEToDTO(dv.CVE),
				ComponentPurl:         dv.ComponentPurl,
				ComponentFixedVersion: dv.ComponentFixedVersion,
				VulnerabilityPath:     dv.VulnerabilityPath,
				State:                 dtos.VulnStateOpen,
			})
		}
	}

	return dtos.ScanResponse{
		AmountOpened:    len(vulnDTOs),
		DependencyVulns: vulnDTOs,
	}, nil
}
