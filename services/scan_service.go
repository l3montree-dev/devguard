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

func (s *scanService) ScanNormalizedSBOM(tx shared.DB, org models.Org, project models.Project, asset models.Asset, assetVersion models.AssetVersion, artifact models.Artifact, normalizedBom *normalize.SBOMGraph, userID string) ([]models.DependencyVuln, []models.DependencyVuln, []models.DependencyVuln, error) {
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
		return nil, nil, nil, err
	}
	vulns, err := s.sbomScanner.Scan(normalizedBom)

	if err != nil {
		slog.Error("could not scan file", "err", err)
		return nil, nil, nil, err
	}

	// handle the scan result
	opened, closed, newState, err := s.HandleScanResult(tx, org, project, asset, &assetVersion, normalizedBom, vulns, artifact.ArtifactName, userID)
	if err != nil {
		slog.Error("could not handle scan result", "err", err)
		return nil, nil, nil, err
	}

	rules, err := s.vexRuleService.FindByAssetVersion(tx, asset.ID, assetVersion.Name)
	if err != nil {
		slog.Error("failed to fetch VEX rules for asset version", "error", err)
		return nil, nil, nil, fmt.Errorf("failed to fetch VEX rules for asset version: %w", err)
	}

	// apply the vex rules to the new state
	newState, err = s.vexRuleService.ApplyRulesToExisting(tx, rules, newState)
	if err != nil {
		slog.Error("failed to apply VEX rules to new state", "error", err)
		return nil, nil, nil, fmt.Errorf("failed to apply VEX rules to new state: %w", err)
	}

	return opened, closed, newState, nil
}

func (s *scanService) HandleFirstPartyVulnResult(org models.Org, project models.Project, asset models.Asset, assetVersion *models.AssetVersion, sarifScan sarif.SarifSchema210Json, scannerID string, userID string) ([]models.FirstPartyVuln, []models.FirstPartyVuln, []models.FirstPartyVuln, error) {

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

				snippetContent := dtos.SnippetContent{
					StartLine:   utils.OrDefault(loc.PhysicalLocation.Region.StartLine, 0),
					EndLine:     utils.OrDefault(loc.PhysicalLocation.Region.EndLine, 0),
					StartColumn: utils.OrDefault(loc.PhysicalLocation.Region.StartColumn, 0),
					EndColumn:   utils.OrDefault(loc.PhysicalLocation.Region.EndColumn, 0),
					Snippet:     utils.OrDefault(loc.PhysicalLocation.Region.Snippet.Text, ""),
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

	opened, closed, newState, err := s.handleFirstPartyVulnResult(userID, scannerID, assetVersion, firstPartyVulnerabilities, asset, org, project)
	if err != nil {
		return []models.FirstPartyVuln{}, []models.FirstPartyVuln{}, []models.FirstPartyVuln{}, err
	}

	if assetVersion.Metadata == nil {
		assetVersion.Metadata = make(map[string]any)
	}

	assetVersion.Metadata[scannerID] = models.ScannerInformation{LastScan: utils.Ptr(time.Now())}

	return opened, closed, newState, nil
}

func (s *scanService) handleFirstPartyVulnResult(userID string, scannerID string, assetVersion *models.AssetVersion, vulns []models.FirstPartyVuln, asset models.Asset, org models.Org, project models.Project) ([]models.FirstPartyVuln, []models.FirstPartyVuln, []models.FirstPartyVuln, error) {
	// get all existing vulns from the database, which are not fixed yet - this is the old state
	existingVulns, err := s.firstPartyVulnRepository.ListUnfixedByAssetAndAssetVersionAndScanner(assetVersion.Name, assetVersion.AssetID, scannerID)
	if err != nil {
		slog.Error("could not get existing first party vulns", "err", err)
		return []models.FirstPartyVuln{}, []models.FirstPartyVuln{}, []models.FirstPartyVuln{}, err
	}

	existingVulnsOnOtherBranch, err := s.firstPartyVulnRepository.GetFirstPartyVulnsByOtherAssetVersions(nil, assetVersion.Name, assetVersion.AssetID, scannerID)
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
	if err := s.firstPartyVulnRepository.Transaction(func(tx shared.DB) error {
		// Process new vulnerabilities that exist on other branches with lifecycle management
		if err := s.firstPartyVulnService.UserDetectedExistingFirstPartyVulnOnDifferentBranch(tx, scannerID, branchDiff.ExistingOnOtherBranches, *assetVersion, asset); err != nil {
			slog.Error("error when trying to add events for existing first party vulnerability on different branch", "err", err)
			return err
		}

		// Process new vulnerabilities that don't exist on other branches
		if err := s.firstPartyVulnService.UserDetectedFirstPartyVulns(tx, userID, scannerID, utils.DereferenceSlice(branchDiff.NewToAllBranches)); err != nil {
			return err
		}

		// Process fixed vulnerabilities
		if err := s.firstPartyVulnService.UserFixedFirstPartyVulns(tx, userID, fixedVulns); err != nil {
			return err
		}

		// update existing first party vulns within the transaction
		for _, v := range updatedFirstPartyVulns {
			if err := s.firstPartyVulnRepository.Save(tx, &v); err != nil {
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
		s.FireAndForget(func() {
			if err = s.thirdPartyIntegration.HandleEvent(shared.FirstPartyVulnsDetectedEvent{
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

	v, err := s.firstPartyVulnRepository.ListUnfixedByAssetAndAssetVersionAndScanner(assetVersion.Name, assetVersion.AssetID, scannerID)
	if err != nil {
		slog.Error("could not get existing first party vulns", "err", err)
		return []models.FirstPartyVuln{}, []models.FirstPartyVuln{}, []models.FirstPartyVuln{}, err
	}

	return utils.DereferenceSlice(branchDiff.NewToAllBranches), fixedVulns, v, nil
}

func (s *scanService) HandleScanResult(tx shared.DB, org models.Org, project models.Project, asset models.Asset, assetVersion *models.AssetVersion, sbom *normalize.SBOMGraph, vulns []models.VulnInPackage, artifactName string, userID string) (opened []models.DependencyVuln, closed []models.DependencyVuln, newState []models.DependencyVuln, err error) {
	// scope the sbom to the current artifact only
	err = sbom.ScopeToArtifact(artifactName)
	if err != nil {
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

	opened, closed, newState, err = s.handleScanResult(tx, userID, artifactName, assetVersion, sbom, dependencyVulns, asset)
	if err != nil {
		return []models.DependencyVuln{}, []models.DependencyVuln{}, []models.DependencyVuln{}, err
	}

	if assetVersion.Metadata == nil {
		assetVersion.Metadata = make(map[string]any)
	}

	assetVersion.Metadata[artifactName] = models.ScannerInformation{LastScan: utils.Ptr(time.Now())}

	newState, err = s.dependencyVulnService.RecalculateRawRiskAssessment(tx, "system", newState, "", asset)

	if err != nil {
		slog.Error("could not recalculate raw risk assessment", "err", err)
		return opened, closed, newState, errors.Wrap(err, "could not recalculate raw risk assessment")
	}

	if len(opened) > 0 && (assetVersion.DefaultBranch || assetVersion.Type == models.AssetVersionTag) {
		s.FireAndForget(func() {
			if err = s.thirdPartyIntegration.HandleEvent(shared.DependencyVulnsDetectedEvent{
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

func (s *scanService) handleScanResult(tx shared.DB, userID string, artifactName string, assetVersion *models.AssetVersion, sbom *normalize.SBOMGraph, dependencyVulns []models.DependencyVuln, asset models.Asset) ([]models.DependencyVuln, []models.DependencyVuln, []models.DependencyVuln, error) {
	existingDependencyVulns, err := s.dependencyVulnRepository.ListByAssetAndAssetVersion(assetVersion.Name, assetVersion.AssetID)
	if err != nil {
		slog.Error("could not get existing dependencyVulns", "err", err)
		return []models.DependencyVuln{}, []models.DependencyVuln{}, []models.DependencyVuln{}, err
	}

	// get all vulns from other branches
	existingVulnsOnOtherBranch, err := s.dependencyVulnRepository.GetDependencyVulnsByOtherAssetVersions(tx, assetVersion.Name, assetVersion.AssetID)
	if err != nil {
		slog.Error("could not get existing dependencyVulns on default branch", "err", err)
		return []models.DependencyVuln{}, []models.DependencyVuln{}, []models.DependencyVuln{}, err
	}

	// Filter out fixed vulnerabilities from the comparison.
	// The state machine prevents detected events from reopening fixed/accepted/falsePositive vulns.
	var filterFixed = func(dv models.DependencyVuln) bool {
		return dv.State != dtos.VulnStateFixed
	}
	existingVulnsOnOtherBranch = utils.Filter(existingVulnsOnOtherBranch, filterFixed)
	existingDependencyVulns = utils.Filter(existingDependencyVulns, filterFixed)

	diff := statemachine.DiffScanResults(artifactName, dependencyVulns, existingDependencyVulns)
	// remove from fixed vulns and fixed on this artifact name all vulns, that have more than a single path to them
	// this means, that another source is still saying, its part of this artifact
	unfixablePurls := sbom.ComponentsWithMultipleSources()
	filterPredicate := func(dv models.DependencyVuln) bool {
		return !slices.Contains(unfixablePurls, dv.ComponentPurl)
	}

	fixedVulns := utils.Filter(diff.FixedEverywhere, filterPredicate)
	fixedOnThisArtifactName := utils.Filter(diff.RemovedFromArtifact, filterPredicate)

	// newDetectedVulnsNotOnOtherBranch, newDetectedButOnOtherBranchExisting, existingEvents := diffVulnsBetweenBranches(diff.NewlyDiscovered, existingVulnsOnOtherBranch)
	branchDiff := statemachine.DiffVulnsBetweenBranches(utils.Map(diff.NewlyDiscovered, utils.Ptr), utils.Map(existingVulnsOnOtherBranch, utils.Ptr))

	// make sure to first create a user detected event for vulnerabilities with just upstream events
	// this way we preserve the event history
	if err := s.dependencyVulnService.UserDetectedExistingVulnOnDifferentBranch(tx, artifactName, branchDiff.ExistingOnOtherBranches, *assetVersion, asset); err != nil {
		slog.Error("error when trying to add events for existing vulnerability on different branch")
		return []models.DependencyVuln{}, []models.DependencyVuln{}, []models.DependencyVuln{}, err
	}
	// We can create the newly found one without checking anything
	if err := s.dependencyVulnService.UserDetectedDependencyVulns(tx, artifactName, utils.DereferenceSlice(branchDiff.NewToAllBranches), *assetVersion, asset); err != nil {
		return []models.DependencyVuln{}, []models.DependencyVuln{}, []models.DependencyVuln{}, err
	}

	err = s.dependencyVulnService.UserDetectedDependencyVulnInAnotherArtifact(tx, diff.NewInArtifact, artifactName)
	if err != nil {
		slog.Error("error when trying to add events for adding scanner to vulnerability")
		return []models.DependencyVuln{}, []models.DependencyVuln{}, []models.DependencyVuln{}, err
	}

	err = s.dependencyVulnService.UserDidNotDetectDependencyVulnInArtifactAnymore(tx, fixedOnThisArtifactName, artifactName)
	if err != nil {
		slog.Error("error when trying to add events for removing scanner from vulnerability")
		return []models.DependencyVuln{}, []models.DependencyVuln{}, []models.DependencyVuln{}, err
	}

	if err := s.dependencyVulnService.UserFixedDependencyVulns(tx, userID, fixedVulns, *assetVersion, asset); err != nil {
		slog.Error("error when trying to add fix event")
		return []models.DependencyVuln{}, []models.DependencyVuln{}, []models.DependencyVuln{}, err
	}

	v, err := s.dependencyVulnRepository.ListUnfixedByAssetAndAssetVersion(tx, assetVersion.Name, assetVersion.AssetID, &artifactName)
	if err != nil {
		slog.Error("could not get existing dependencyVulns", "err", err)
		return []models.DependencyVuln{}, []models.DependencyVuln{}, []models.DependencyVuln{}, err
	}

	return utils.DereferenceSlice(branchDiff.NewToAllBranches), fixedVulns, v, nil
}

func (s *scanService) FetchSbomsFromUpstream(artifactName string, ref string, upstreamURLs []string, keepOriginalSbomRootComponent bool) (boms []*normalize.SBOMGraph, validURLs []string, invalidURLs []string) {
	client := &http.Client{}
	//check if the upstream urls are valid urls
	for _, url := range upstreamURLs {
		url = normalize.SanitizeExternalReferencesURL(url)
		// skip CSAF URLs - they're handled separately
		if strings.HasSuffix(url, "/provider-metadata.json") {
			continue
		}
		//check if the file is a valid url
		if url == "" || !strings.HasPrefix(url, "http") {
			invalidURLs = append(invalidURLs, url)
			continue
		}

		var bom cyclonedx.BOM
		ctx, cancel := context.WithTimeout(context.Background(), time.Second*30)
		defer cancel()
		// fetch the file from the url
		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)

		if err != nil {
			invalidURLs = append(invalidURLs, url)
			continue
		}

		resp, err := client.Do(req)
		if err != nil || resp.StatusCode != 200 {
			invalidURLs = append(invalidURLs, url)
			continue
		}
		defer resp.Body.Close()

		// download the url and check if it is a valid sbom
		file, err := io.ReadAll(resp.Body)
		if err != nil {
			invalidURLs = append(invalidURLs, url)
			continue
		}

		err = json.Unmarshal(file, &bom)
		if err != nil {
			invalidURLs = append(invalidURLs, url)
			continue
		}

		// Only process SBOMs (not VEX)
		if normalize.BomIsSBOM(&bom) {
			validURLs = append(validURLs, url)
			boms = append(boms, normalize.SBOMGraphFromCycloneDX(&bom, artifactName, url, keepOriginalSbomRootComponent))
		}
	}

	return boms, validURLs, invalidURLs
}

func (s *scanService) FetchVexFromUpstream(artifactName string, ref string, upstreamURLs []string) (vexReports []*normalize.VexReport, validURLs []string, invalidURLs []string) {
	client := &http.Client{}
	//check if the upstream urls are valid urls
	for _, url := range upstreamURLs {
		url = normalize.SanitizeExternalReferencesURL(url)
		// check if csaf provider-metadata.json is appended
		if strings.HasSuffix(url, "/provider-metadata.json") {
			// we need to use the csaf ingestion here.
			// extract the purl from the url
			// split at http or https
			protocol := "http://"
			purlSlice := strings.SplitN(url, "http://", 2)
			if len(purlSlice) == 1 {
				purlSlice = strings.SplitN(url, "https://", 2)
				protocol = "https://"
			}
			if len(purlSlice) != 2 {
				invalidURLs = append(invalidURLs, url)
				continue
			}
			purlStr := strings.TrimSuffix(purlSlice[0], ":")
			sanitizedURL := fmt.Sprintf("%s%s", protocol, purlSlice[1])

			purl, err := packageurl.FromString(purlStr)
			if err != nil {
				invalidURLs = append(invalidURLs, url)
				continue
			}
			bom, err := s.csafService.GetVexFromCsafProvider(purl, ref, url, sanitizedURL)
			if err != nil {
				slog.Warn("could not download csaf from csaf provider", "err", err)
				invalidURLs = append(invalidURLs, url)
				continue
			}
			validURLs = append(validURLs, url)
			vexReports = append(vexReports, &normalize.VexReport{
				Report: bom,
				Source: sanitizedURL,
			})
			continue
		}
		//check if the file is a valid url
		if url == "" || !strings.HasPrefix(url, "http") {
			invalidURLs = append(invalidURLs, url)
			continue
		}

		var bom cyclonedx.BOM
		ctx, cancel := context.WithTimeout(context.Background(), time.Second*30)
		defer cancel()
		// fetch the file from the url
		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)

		if err != nil {
			invalidURLs = append(invalidURLs, url)
			continue
		}

		resp, err := client.Do(req)
		if err != nil || resp.StatusCode != 200 {
			invalidURLs = append(invalidURLs, url)
			continue
		}
		defer resp.Body.Close()

		// download the url and check if it is a valid vex file
		file, err := io.ReadAll(resp.Body)
		if err != nil {
			invalidURLs = append(invalidURLs, url)
			continue
		}

		err = json.Unmarshal(file, &bom)
		if err != nil {
			invalidURLs = append(invalidURLs, url)
			continue
		}

		// Only process VEX (not SBOMs)
		if !normalize.BomIsSBOM(&bom) {
			validURLs = append(validURLs, url)
			vexReports = append(vexReports, &normalize.VexReport{
				Report: &bom,
				Source: url,
			})
		}
	}

	return vexReports, validURLs, invalidURLs
}

// RunArtifactSecurityLifecycle orchestrates the complete security lifecycle for an artifact:
// 1. Fetches information sources (SBOM URLs) from the artifact
// 2. Fetches VEX URLs from external references
// 3. Fetches SBOMs and VEX reports from upstream
// 4. Updates the SBOM in the database
// 5. Scans the normalized SBOM for vulnerabilities
// 6. Ingests VEX rules
// It returns the normalized BOM and VEX reports for further processing if needed
func (s *scanService) RunArtifactSecurityLifecycle(
	tx shared.DB,
	org models.Org,
	project models.Project,
	asset models.Asset,
	assetVersion models.AssetVersion,
	artifact models.Artifact,
	userID string,
) (*normalize.SBOMGraph, []*normalize.VexReport, []models.DependencyVuln, error) {
	// Fetch information sources (SBOM URLs) from the artifact
	rootNodes, err := s.componentService.FetchInformationSources(&artifact)
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
	vexRefs, err := s.externalReferenceRepository.FindByAssetVersion(tx, asset.ID, assetVersion.Name)
	if err != nil {
		slog.Error("failed to fetch vex external references", "error", err, "artifactName", artifact.ArtifactName)
		// Don't fail the entire operation if fetching external refs fails
	}

	// Collect VEX URLs from external references
	vexURLs := make([]string, 0, len(vexRefs))
	for _, ref := range vexRefs {
		if ref.Type == "vex" {
			vexURLs = append(vexURLs, ref.URL)
		}
	}

	// Combine SBOM and VEX URLs
	allURLs := append(sbomUpstreamURLs, vexURLs...)

	// Fetch SBOMs and VEX reports from upstream
	boms, _, _ := s.FetchSbomsFromUpstream(artifact.ArtifactName, assetVersion.Name, allURLs, asset.KeepOriginalSbomRootComponent)
	vexReports, _, _ := s.FetchVexFromUpstream(artifact.ArtifactName, assetVersion.Name, allURLs)
	// Merge all BOMs into a single graph
	newGraph := normalize.NewSBOMGraph()
	for _, bom := range boms {
		newGraph.MergeGraph(bom)
	}

	// Update SBOM in database
	normalizedBom, err := s.assetVersionService.UpdateSBOM(
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
	_, _, dependencyVulns, err := s.ScanNormalizedSBOM(tx, org, project, asset, assetVersion, artifact, normalizedBom, userID)
	if err != nil {
		slog.Error("failed to scan normalized sbom in security lifecycle", "error", err, "artifactName", artifact.ArtifactName, "assetVersionName", assetVersion.Name)
		return nil, nil, nil, fmt.Errorf("failed to scan normalized sbom: %w", err)
	}

	// Ingest VEX rules
	if err := s.vexRuleService.IngestVexes(tx, asset, assetVersion, vexReports); err != nil {
		slog.Error("failed to ingest vex reports in security lifecycle", "error", err, "artifactName", artifact.ArtifactName, "assetVersionName", assetVersion.Name)
		return nil, nil, nil, fmt.Errorf("failed to ingest vex reports: %w", err)
	}

	return normalizedBom, vexReports, dependencyVulns, nil
}
