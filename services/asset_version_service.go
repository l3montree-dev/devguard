package services

import (
	"bytes"
	"fmt"
	"html/template"
	"log/slog"
	"math"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/dtos/sarif"
	"github.com/l3montree-dev/devguard/normalize"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/transformer"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/l3montree-dev/devguard/vulndb"
	"github.com/openvex/go-vex/pkg/vex"

	"github.com/package-url/packageurl-go"
	"github.com/pkg/errors"
)

type assetVersionService struct {
	dependencyVulnRepository shared.DependencyVulnRepository
	firstPartyVulnRepository shared.FirstPartyVulnRepository
	componentRepository      shared.ComponentRepository
	dependencyVulnService    shared.DependencyVulnService
	firstPartyVulnService    shared.FirstPartyVulnService
	assetVersionRepository   shared.AssetVersionRepository
	assetRepository          shared.AssetRepository
	projectRepository        shared.ProjectRepository
	orgRepository            shared.OrganizationRepository
	vulnEventRepository      shared.VulnEventRepository
	componentService         shared.ComponentService
	httpClient               *http.Client
	thirdPartyIntegration    shared.IntegrationAggregate
	licenseRiskRepository    shared.LicenseRiskRepository
	utils.FireAndForgetSynchronizer
}

func NewAssetVersionService(assetVersionRepository shared.AssetVersionRepository, componentRepository shared.ComponentRepository, dependencyVulnRepository shared.DependencyVulnRepository, firstPartyVulnRepository shared.FirstPartyVulnRepository, dependencyVulnService shared.DependencyVulnService, firstPartyVulnService shared.FirstPartyVulnService, assetRepository shared.AssetRepository, projectRepository shared.ProjectRepository, orgRepository shared.OrganizationRepository, vulnEventRepository shared.VulnEventRepository, componentService shared.ComponentService, thirdPartyIntegration shared.IntegrationAggregate, licenseRiskRepository shared.LicenseRiskRepository, synchronizer utils.FireAndForgetSynchronizer) *assetVersionService {
	return &assetVersionService{
		assetVersionRepository:    assetVersionRepository,
		componentRepository:       componentRepository,
		dependencyVulnRepository:  dependencyVulnRepository,
		firstPartyVulnRepository:  firstPartyVulnRepository,
		dependencyVulnService:     dependencyVulnService,
		firstPartyVulnService:     firstPartyVulnService,
		vulnEventRepository:       vulnEventRepository,
		componentService:          componentService,
		assetRepository:           assetRepository,
		httpClient:                &http.Client{},
		thirdPartyIntegration:     thirdPartyIntegration,
		projectRepository:         projectRepository,
		orgRepository:             orgRepository,
		licenseRiskRepository:     licenseRiskRepository,
		FireAndForgetSynchronizer: synchronizer,
	}
}

func (s *assetVersionService) GetAssetVersionsByAssetID(assetID uuid.UUID) ([]models.AssetVersion, error) {
	return s.assetVersionRepository.GetAssetVersionsByAssetID(nil, assetID)
}

var sarifResultKindsIndicatingNotAndIssue = []string{
	"notApplicable",
	"informational",
	"pass",
	"open",
}

func getBestDescription(rule sarif.ReportingDescriptor) string {
	if rule.FullDescription != nil {
		if rule.FullDescription.Markdown != nil {
			return utils.OrDefault(rule.FullDescription.Markdown, "")
		}
		if rule.FullDescription.Text != "" {
			return rule.FullDescription.Text
		}
	}
	if rule.ShortDescription.Markdown != nil {
		return utils.OrDefault(rule.ShortDescription.Markdown, "")
	}

	return rule.ShortDescription.Text
}

func preferMarkdown(text sarif.MultiformatMessageString) string {
	if text.Markdown != nil {
		return utils.OrDefault(text.Markdown, "")
	}
	return text.Text
}

func (s *assetVersionService) HandleFirstPartyVulnResult(org models.Org, project models.Project, asset models.Asset, assetVersion *models.AssetVersion, sarifScan sarif.SarifSchema210Json, scannerID string, userID string) ([]models.FirstPartyVuln, []models.FirstPartyVuln, []models.FirstPartyVuln, error) {

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
				RuleProperties:  database.JSONB(ruleProperties),
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

func (s *assetVersionService) handleFirstPartyVulnResult(userID string, scannerID string, assetVersion *models.AssetVersion, vulns []models.FirstPartyVuln, asset models.Asset, org models.Org, project models.Project) ([]models.FirstPartyVuln, []models.FirstPartyVuln, []models.FirstPartyVuln, error) {
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

	newDetectedVulnsNotOnOtherBranch, newDetectedButOnOtherBranchExisting, existingEvents := diffVulnsBetweenBranches(newVulns, existingVulnsOnOtherBranch)

	// get a transaction
	if err := s.firstPartyVulnRepository.Transaction(func(tx shared.DB) error {
		// Process new vulnerabilities that exist on other branches with lifecycle management
		if err := s.firstPartyVulnService.UserDetectedExistingFirstPartyVulnOnDifferentBranch(tx, scannerID, newDetectedButOnOtherBranchExisting, existingEvents, *assetVersion, asset); err != nil {
			slog.Error("error when trying to add events for existing first party vulnerability on different branch", "err", err)
			return err
		}

		// Process new vulnerabilities that don't exist on other branches
		if err := s.firstPartyVulnService.UserDetectedFirstPartyVulns(tx, userID, scannerID, newDetectedVulnsNotOnOtherBranch); err != nil {
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

	if len(newDetectedVulnsNotOnOtherBranch) > 0 && (assetVersion.DefaultBranch || assetVersion.Type == models.AssetVersionTag) {
		s.FireAndForget(func() {
			if err = s.thirdPartyIntegration.HandleEvent(shared.FirstPartyVulnsDetectedEvent{
				AssetVersion: shared.ToAssetVersionObject(*assetVersion),
				Asset:        shared.ToAssetObject(asset),
				Project:      shared.ToProjectObject(project),
				Org:          shared.ToOrgObject(org),
				Vulns:        utils.Map(newDetectedVulnsNotOnOtherBranch, transformer.FirstPartyVulnToDto),
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

	return newDetectedVulnsNotOnOtherBranch, fixedVulns, v, nil
}

func (s *assetVersionService) HandleScanResult(org models.Org, project models.Project, asset models.Asset, assetVersion *models.AssetVersion, vulns []models.VulnInPackage, artifactName string, userID string, upstream dtos.UpstreamState) (opened []models.DependencyVuln, closed []models.DependencyVuln, newState []models.DependencyVuln, err error) {
	// create dependencyVulns out of those vulnerabilities
	dependencyVulns := []models.DependencyVuln{}

	// load all asset components again and build a dependency tree
	assetComponents, err := s.componentRepository.LoadComponents(nil, assetVersion.Name, assetVersion.AssetID, &artifactName)
	if err != nil {
		return []models.DependencyVuln{}, []models.DependencyVuln{}, []models.DependencyVuln{}, errors.Wrap(err, "could not load asset components")
	}

	// calculate the depth of each component
	sbom, err := s.BuildSBOM(asset, *assetVersion, artifactName, org.Name, assetComponents)
	if err != nil {
		return []models.DependencyVuln{}, []models.DependencyVuln{}, []models.DependencyVuln{}, errors.Wrap(err, "could not build sbom for depth calculation")
	}
	depthMap := sbom.CalculateDepth()
	for _, vuln := range vulns {
		v := vuln
		fixedVersion := normalize.FixFixedVersion(v.Purl, v.FixedVersion)
		// check if we could calculate a depth for this component
		if _, ok := depthMap[v.Purl]; !ok {
			// if not, set it to 1 (direct dependency)
			depthMap[v.Purl] = 1
		}

		dependencyVuln := models.DependencyVuln{
			Vulnerability: models.Vulnerability{
				AssetVersionName: assetVersion.Name,
				AssetID:          asset.ID,
			},
			Artifacts: []models.Artifact{
				{
					ArtifactName:     artifactName,
					AssetVersionName: assetVersion.Name,
					AssetID:          asset.ID,
				},
			},

			CVEID:                 utils.Ptr(v.CVEID),
			ComponentPurl:         utils.Ptr(v.Purl),
			ComponentFixedVersion: fixedVersion,
			ComponentDepth:        utils.Ptr(depthMap[v.Purl]),
			CVE:                   &v.CVE,
		}

		dependencyVulns = append(dependencyVulns, dependencyVuln)
	}

	dependencyVulns = utils.UniqBy(dependencyVulns, func(f models.DependencyVuln) string {
		return f.CalculateHash()
	})

	opened, closed, newState, err = s.handleScanResult(userID, artifactName, assetVersion, sbom, dependencyVulns, asset, upstream)
	if err != nil {
		return []models.DependencyVuln{}, []models.DependencyVuln{}, []models.DependencyVuln{}, err
	}

	if assetVersion.Metadata == nil {
		assetVersion.Metadata = make(map[string]any)
	}

	assetVersion.Metadata[artifactName] = models.ScannerInformation{LastScan: utils.Ptr(time.Now())}

	newState, err = s.dependencyVulnService.RecalculateRawRiskAssessment(nil, "system", newState, "", asset)

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

func diffScanResults(currentArtifactName string, foundVulnerabilities []models.DependencyVuln, existingDependencyVulns []models.DependencyVuln) ([]models.DependencyVuln, []models.DependencyVuln, []models.DependencyVuln, []models.DependencyVuln, []models.DependencyVuln) {

	var firstDetected []models.DependencyVuln
	var fixedOnAll []models.DependencyVuln
	var firstDetectedOnThisArtifactName []models.DependencyVuln
	var fixedOnThisArtifactName []models.DependencyVuln
	var nothingChanged []models.DependencyVuln

	var foundVulnsMappedByID = make(map[string]models.DependencyVuln)
	for _, vuln := range foundVulnerabilities {
		if _, ok := foundVulnsMappedByID[vuln.CalculateHash()]; !ok {
			foundVulnsMappedByID[vuln.CalculateHash()] = vuln
		}
	}

	for _, existingVulns := range existingDependencyVulns {
		if _, ok := foundVulnsMappedByID[existingVulns.CalculateHash()]; !ok {
			if len(existingVulns.Artifacts) == 1 && existingVulns.Artifacts[0].ArtifactName == currentArtifactName {
				fixedOnAll = append(fixedOnAll, existingVulns)
			} else {
				fixedOnThisArtifactName = append(fixedOnThisArtifactName, existingVulns)
			}
		} else {
			// still exists and nothing changed
			nothingChanged = append(nothingChanged, existingVulns)
		}
	}
	var existingVulnsMappedByID = make(map[string]models.DependencyVuln)
	for _, vuln := range existingDependencyVulns {
		if _, ok := existingVulnsMappedByID[vuln.CalculateHash()]; !ok {
			existingVulnsMappedByID[vuln.CalculateHash()] = vuln
		}
	}

	for _, foundVuln := range foundVulnerabilities {
		if existingVuln, ok := existingVulnsMappedByID[foundVuln.CalculateHash()]; !ok {
			firstDetected = append(firstDetected, foundVuln)
		} else {
			// existing vulnerability artifacts inspected instead of newly built vuln artifacts
			alreadyDetectedOnThisArtifactName := false
			for _, existingArtifact := range existingVuln.Artifacts {
				if existingArtifact.ArtifactName == currentArtifactName {
					alreadyDetectedOnThisArtifactName = true
					break
				}
			}
			if !alreadyDetectedOnThisArtifactName {
				firstDetectedOnThisArtifactName = append(firstDetectedOnThisArtifactName, existingVuln)
			}
		}
	}

	return firstDetected, fixedOnAll, firstDetectedOnThisArtifactName, fixedOnThisArtifactName, nothingChanged
}

type Diffable interface {
	AssetVersionIndependentHash() string
	GetAssetVersionName() string
	GetEvents() []models.VulnEvent
}

func diffVulnsBetweenBranches[T Diffable](foundVulnerabilities []T, existingVulns []T) ([]T, []T, [][]models.VulnEvent) {
	newDetectedVulnsNotOnOtherBranch := make([]T, 0)
	newDetectedButOnOtherBranchExisting := make([]T, 0)
	existingEvents := make([][]models.VulnEvent, 0)

	// Create a map of existing vulnerabilities by hash for quick lookup
	existingVulnsMap := make(map[string][]T)
	for _, vuln := range existingVulns {
		hash := vuln.AssetVersionIndependentHash()
		existingVulnsMap[hash] = append(existingVulnsMap[hash], vuln)
	}

	for _, newDetectedVuln := range foundVulnerabilities {
		hash := newDetectedVuln.AssetVersionIndependentHash()
		if existingVulns, ok := existingVulnsMap[hash]; ok {

			newDetectedButOnOtherBranchExisting = append(newDetectedButOnOtherBranchExisting, newDetectedVuln)

			existingVulnEventsOnOtherBranch := make([]models.VulnEvent, 0)
			for _, existingVuln := range existingVulns {

				events := utils.Filter(existingVuln.GetEvents(), func(ev models.VulnEvent) bool {
					return ev.OriginalAssetVersionName == nil && ev.Type != dtos.EventTypeRawRiskAssessmentUpdated
				})

				existingVulnEventsOnOtherBranch = append(existingVulnEventsOnOtherBranch, utils.Map(events, func(event models.VulnEvent) models.VulnEvent {
					event.OriginalAssetVersionName = utils.Ptr(existingVuln.GetAssetVersionName())
					return event
				})...)
			}
			existingEvents = append(existingEvents, existingVulnEventsOnOtherBranch)
		} else {
			newDetectedVulnsNotOnOtherBranch = append(newDetectedVulnsNotOnOtherBranch, newDetectedVuln)
		}
	}

	return newDetectedVulnsNotOnOtherBranch, newDetectedButOnOtherBranchExisting, existingEvents
}

func (s *assetVersionService) migrateToPurlsWithQualifiers(newVulns []models.DependencyVuln, existingVulns []models.DependencyVuln, existingVulnsOnOtherBranch []models.DependencyVuln) ([]models.DependencyVuln, []models.DependencyVuln, error) {

	vulnsToUpdate := make([]models.DependencyVuln, 0)

	for _, newVuln := range newVulns {
		if newVuln.ComponentPurl == nil {
			continue
		}
		fullPurl := newVuln.ComponentPurl
		purl := strings.SplitN(*fullPurl, "?", 2)[0]

		for i, existingVuln := range existingVulns {
			if existingVuln.ComponentPurl != nil && *existingVuln.ComponentPurl == purl &&
				existingVuln.CVEID != nil && newVuln.CVEID != nil && *existingVuln.CVEID == *newVuln.CVEID {
				existingVulns[i].ComponentPurl = fullPurl
				vulnsToUpdate = append(vulnsToUpdate, existingVulns[i])
			}

		}

		for i, existingVuln := range existingVulnsOnOtherBranch {
			if existingVuln.ComponentPurl != nil && *existingVuln.ComponentPurl == purl &&
				existingVuln.CVEID != nil && newVuln.CVEID != nil && *existingVuln.CVEID == *newVuln.CVEID {
				existingVulnsOnOtherBranch[i].ComponentPurl = fullPurl
				vulnsToUpdate = append(vulnsToUpdate, existingVulnsOnOtherBranch[i])
			}

		}
	}

	if len(vulnsToUpdate) == 0 {
		return existingVulns, existingVulnsOnOtherBranch, nil
	}

	db := s.dependencyVulnRepository.GetDB(nil)

	//save all updated vulns back to the database
	for _, dependencyVuln := range vulnsToUpdate {
		oldHash := dependencyVuln.ID
		newHash := dependencyVuln.CalculateHash()

		if oldHash == newHash {
			continue
		}

		// Update the hash in the database
		err := db.Model(&models.DependencyVuln{}).Where("id = ?", oldHash).UpdateColumn("id", newHash).Error
		if err != nil {
			slog.Info("could not update dependencyVuln hash, trying to merge", "err", err)
			// Handle duplicate key error by merging
			var otherVuln models.DependencyVuln
			err = db.Model(&models.DependencyVuln{}).Where("id = ?", newHash).First(&otherVuln).Error
			if err != nil {
				slog.Error("could not fetch other dependencyVuln", "err", err)
				return existingVulns, existingVulnsOnOtherBranch, err
			}

			// Update all vuln events BEFORE deleting the old record
			err = db.Model(&models.VulnEvent{}).Where("vuln_id = ?", oldHash).UpdateColumn("vuln_id", newHash).Error
			if err != nil {
				slog.Error("could not update vuln events", "err", err)
				return existingVulns, existingVulnsOnOtherBranch, err
			}

			// Update artifact dependency vulns BEFORE deleting the old record
			err = db.Table("artifact_dependency_vulns").Where("dependency_vuln_id = ?", oldHash).UpdateColumn("dependency_vuln_id", newHash).Error
			if err != nil {
				slog.Error("could not update artifact dependency vulns", "err", err)
				return existingVulns, existingVulnsOnOtherBranch, err
			}

			// Now delete the old record after all references are updated
			err = db.Model(&models.DependencyVuln{}).Where("id = ?", oldHash).Delete(&dependencyVuln).Error
			if err != nil {
				slog.Error("could not delete old dependencyVuln during merge", "err", err)
				return existingVulns, existingVulnsOnOtherBranch, err
			}

		}

		err = db.Model(&models.DependencyVuln{}).Where("id = ?", newHash).UpdateColumn("component_purl", dependencyVuln.ComponentPurl).Error
		if err != nil {
			slog.Error("could not update component purl during dependencyVuln merge", "err", err)
			return existingVulns, existingVulnsOnOtherBranch, err
		}

		// Update all vuln events (in case the update succeeded on first try)
		err = db.Model(&models.VulnEvent{}).Where("vuln_id = ?", oldHash).UpdateColumn("vuln_id", newHash).Error
		if err != nil {
			slog.Error("could not update vuln events", "err", err)
			return existingVulns, existingVulnsOnOtherBranch, err
		}

		// update dependencyVuln in artifacts dependencyVuln table (in case the update succeeded on first try)
		err = db.Table("artifact_dependency_vulns").Where("dependency_vuln_id = ?", oldHash).UpdateColumn("dependency_vuln_id", newHash).Error
		if err != nil {
			slog.Error("could not update artifact dependency vulns", "err", err)
			return existingVulns, existingVulnsOnOtherBranch, err
		}

	}

	return existingVulns, existingVulnsOnOtherBranch, nil

}

func (s *assetVersionService) handleScanResult(userID string, artifactName string, assetVersion *models.AssetVersion, sbom *normalize.CdxBom, dependencyVulns []models.DependencyVuln, asset models.Asset, upstream dtos.UpstreamState) ([]models.DependencyVuln, []models.DependencyVuln, []models.DependencyVuln, error) {
	existingDependencyVulns, err := s.dependencyVulnRepository.ListByAssetAndAssetVersion(assetVersion.Name, assetVersion.AssetID)
	if err != nil {
		slog.Error("could not get existing dependencyVulns", "err", err)
		return []models.DependencyVuln{}, []models.DependencyVuln{}, []models.DependencyVuln{}, err
	}
	// get all vulns from other branches
	existingVulnsOnOtherBranch, err := s.dependencyVulnRepository.GetDependencyVulnsByOtherAssetVersions(nil, assetVersion.Name, assetVersion.AssetID)
	if err != nil {
		slog.Error("could not get existing dependencyVulns on default branch", "err", err)
		return []models.DependencyVuln{}, []models.DependencyVuln{}, []models.DependencyVuln{}, err
	}

	// this is just for migration.
	// the call can be removed after all assets were scanned again
	existingDependencyVulns, existingVulnsOnOtherBranch, err = s.migrateToPurlsWithQualifiers(dependencyVulns, existingDependencyVulns, existingVulnsOnOtherBranch)
	if err != nil {
		slog.Error("could not migrate dependencyVulns to purls with qualifiers", "err", err)
		return []models.DependencyVuln{}, []models.DependencyVuln{}, []models.DependencyVuln{}, err
	}

	existingVulnsOnOtherBranch = utils.Filter(existingVulnsOnOtherBranch, func(dependencyVuln models.DependencyVuln) bool {
		return dependencyVuln.State != dtos.VulnStateFixed
	})

	// remove all fixed dependencyVulns from the existing dependencyVulns
	existingDependencyVulns = utils.Filter(existingDependencyVulns, func(dependencyVuln models.DependencyVuln) bool {
		return dependencyVuln.State != dtos.VulnStateFixed
	})

	newDetectedVulns, fixedVulns, firstDetectedOnThisArtifactName, fixedOnThisArtifactName, nothingChanged := diffScanResults(artifactName, dependencyVulns, existingDependencyVulns)
	// remove from fixed vulns and fixed on this artifact name all vulns, that have more than a single path to them
	// this means, that another source is still saying, its part of this artifact
	unfixablePurls := sbom.InformationFromVexOrMultipleSBOMs()
	filterPredicate := func(dv models.DependencyVuln) bool {
		if dv.ComponentPurl == nil {
			return true
		}
		return !slices.Contains(unfixablePurls, *dv.ComponentPurl)
	}

	fixedVulns = utils.Filter(fixedVulns, filterPredicate)
	fixedOnThisArtifactName = utils.Filter(fixedOnThisArtifactName, filterPredicate)

	newDetectedVulnsNotOnOtherBranch, newDetectedButOnOtherBranchExisting, existingEvents := diffVulnsBetweenBranches(newDetectedVulns, existingVulnsOnOtherBranch)

	if err := s.dependencyVulnRepository.Transaction(func(tx shared.DB) error {
		// make sure to first create a user detected event for vulnerabilities with just upstream events
		// this way we preserve the event history
		if err := s.dependencyVulnService.UserDetectedExistingVulnOnDifferentBranch(tx, artifactName, newDetectedButOnOtherBranchExisting, existingEvents, *assetVersion, asset); err != nil {
			slog.Error("error when trying to add events for existing vulnerability on different branch")
			return err // this will cancel the transaction
		}
		// We can create the newly found one without checking anything
		if err := s.dependencyVulnService.UserDetectedDependencyVulns(tx, artifactName, newDetectedVulnsNotOnOtherBranch, *assetVersion, asset, upstream); err != nil {
			return err // this will cancel the transaction
		}

		err = s.dependencyVulnService.UserDetectedDependencyVulnInAnotherArtifact(tx, firstDetectedOnThisArtifactName, artifactName)
		if err != nil {
			slog.Error("error when trying to add events for adding scanner to vulnerability")
			return err
		}

		err := s.dependencyVulnService.UserDidNotDetectDependencyVulnInArtifactAnymore(tx, fixedOnThisArtifactName, artifactName)
		if err != nil {
			slog.Error("error when trying to add events for removing scanner from vulnerability")
			return err
		}

		if err := s.dependencyVulnService.UserFixedDependencyVulns(tx, userID, fixedVulns, *assetVersion, asset, upstream); err != nil {
			slog.Error("error when trying to add fix event")
			return err
		}

		if len(nothingChanged) > 0 {
			var valueClauses []string
			for _, dv := range nothingChanged {
				hash := dv.CalculateHash()
				depth := utils.OrDefault(dv.ComponentDepth, 1)
				valueClauses = append(valueClauses, fmt.Sprintf("('%s', %d)", hash, depth))
			}
			// Join the value clauses with commas
			values := strings.Join(valueClauses, ",")
			// Construct the SQL query
			query := fmt.Sprintf(`
				UPDATE dependency_vulns
				SET component_depth = data.component_depth
				FROM (VALUES %s) AS data(id, component_depth)
				WHERE dependency_vulns.asset_id = ?
				AND dependency_vulns.asset_version_name = ?
				AND dependency_vulns.id = data.id
			`, values)
			// update just the component depth for nothingChanged vulns
			return s.dependencyVulnRepository.GetDB(tx).Exec(query, assetVersion.AssetID, assetVersion.Name).Error
		}
		return nil
	}); err != nil {
		slog.Error("could not save dependencyVulns", "err", err)
		return []models.DependencyVuln{}, []models.DependencyVuln{}, []models.DependencyVuln{}, err
	}

	v, err := s.dependencyVulnRepository.ListUnfixedByAssetAndAssetVersion(assetVersion.Name, assetVersion.AssetID, &artifactName)
	if err != nil {
		slog.Error("could not get existing dependencyVulns", "err", err)
		return []models.DependencyVuln{}, []models.DependencyVuln{}, []models.DependencyVuln{}, err
	}

	return newDetectedVulnsNotOnOtherBranch, fixedVulns, v, nil
}

func buildBomRefMap(bom *normalize.CdxBom) map[string]cdx.Component {
	res := make(map[string]cdx.Component)
	if bom.GetComponents() == nil {
		return res
	}

	for _, component := range *bom.GetComponentsIncludingFakeNodes() {
		res[component.BOMRef] = component
	}
	return res
}

func (s *assetVersionService) UpdateSBOM(org models.Org, project models.Project, asset models.Asset, assetVersion models.AssetVersion, artifactName string, sbom *normalize.CdxBom, upstream dtos.UpstreamState) (*normalize.CdxBom, error) {
	// load the asset components
	assetComponents, err := s.componentRepository.LoadComponents(nil, assetVersion.Name, assetVersion.AssetID, &artifactName)
	if err != nil {
		return nil, errors.Wrap(err, "could not load asset components")
	}

	existingComponentPurls := make(map[string]bool)
	for _, currentComponent := range assetComponents {
		existingComponentPurls[currentComponent.Component.Purl] = true
	}

	// we need to check if the SBOM is new or if it already exists.
	// if it already exists, we need to update the existing SBOM
	// update the sbom for the asset in the database.
	components := make(map[string]models.Component)
	dependencies := make([]models.ComponentDependency, 0)
	// if the sbom only represents a subtree of the actual asset, we cannot update the whole asset.
	// first we need to replace the subtree.

	wholeAssetSBOM, err := s.BuildSBOM(asset, assetVersion, artifactName, org.Name, assetComponents)
	if err != nil {
		return nil, errors.Wrap(err, "could not build whole asset sbom")
	}

	for _, informationSource := range sbom.GetInformationSourceNodes() {
		wholeAssetSBOM.ReplaceOrAddInformationSourceNode(informationSource)
	}

	// build a map of all components
	bomRefMap := buildBomRefMap(wholeAssetSBOM)

	depExistMap := make(map[string]bool)
	// create all direct dependencies
	for _, c := range *wholeAssetSBOM.GetDirectDependencies() {
		component := bomRefMap[c.Ref]
		// the sbom of a container image does not contain the scope. In a container image, we do not have
		// anything like a deep nested dependency tree. Everything is a direct dependency.
		componentPackageURL := normalize.Purl(component)
		// create the direct dependency edge.
		if _, ok := depExistMap["nil->"+componentPackageURL]; ok {
			continue
		}
		depExistMap["nil->"+componentPackageURL] = true
		dependencies = append(dependencies,
			models.ComponentDependency{
				ComponentPurl:  nil, // direct dependency - therefore set it to nil
				DependencyPurl: componentPackageURL,
			},
		)
	}

	transitiveDependencies := *wholeAssetSBOM.GetTransitiveDependencies()
	for _, c := range transitiveDependencies {
		comp := bomRefMap[c.Ref]
		compPackageURL := normalize.Purl(comp)
		for _, d := range *c.Dependencies {
			dep := bomRefMap[d]
			depPurlOrName := normalize.Purl(dep)
			if _, ok := depExistMap[compPackageURL+"->"+depPurlOrName]; ok {
				continue
			}
			depExistMap[compPackageURL+"->"+depPurlOrName] = true
			dependencies = append(dependencies,
				models.ComponentDependency{
					ComponentPurl:  utils.Ptr(compPackageURL),
					DependencyPurl: depPurlOrName,
				},
			)
		}
	}

	for _, c := range *wholeAssetSBOM.GetComponentsIncludingFakeNodes() {
		componentPackageURL := normalize.Purl(c)
		if _, ok := existingComponentPurls[componentPackageURL]; !ok {
			components[componentPackageURL] = models.Component{
				Purl:          componentPackageURL,
				ComponentType: dtos.ComponentType(c.Type),
				Version:       c.Version,
			}
		}
	}

	componentsSlice := make([]models.Component, 0, len(components))
	for _, c := range components {
		componentsSlice = append(componentsSlice, c)
	}

	// make sure, that the components exist
	if err := s.componentRepository.CreateBatch(nil, componentsSlice); err != nil {
		return nil, err
	}

	_, err = s.componentRepository.HandleStateDiff(nil, assetVersion.Name, assetVersion.AssetID, assetComponents, dependencies, artifactName)
	if err != nil {
		return nil, err
	}

	// update the license information in the background
	s.FireAndForget(func() {
		slog.Info("updating license information in background", "asset", assetVersion.Name, "assetID", assetVersion.AssetID)
		_, err := s.componentService.GetAndSaveLicenseInformation(assetVersion, utils.Ptr(artifactName), false, upstream)
		if err != nil {
			slog.Error("could not update license information", "asset", assetVersion.Name, "assetID", assetVersion.AssetID, "err", err)
		} else {
			slog.Info("license information updated", "asset", assetVersion.Name, "assetID", assetVersion.AssetID)
		}
	})

	if assetVersion.DefaultBranch || assetVersion.Type == models.AssetVersionTag {
		s.FireAndForget(func() {
			if err = s.thirdPartyIntegration.HandleEvent(shared.SBOMCreatedEvent{
				AssetVersion: shared.ToAssetVersionObject(assetVersion),
				Asset:        shared.ToAssetObject(asset),
				Project:      shared.ToProjectObject(project),
				Org:          shared.ToOrgObject(org),
				Artifact: shared.ArtifactObject{
					ArtifactName: artifactName,
				},
				SBOM: sbom.EjectSBOM(nil),
			}); err != nil {
				slog.Error("could not handle SBOM updated event", "err", err)
			} else {
				slog.Info("handled SBOM updated event", "assetVersion", assetVersion.Name, "assetID", assetVersion.AssetID)
			}
		})
	}

	return wholeAssetSBOM, nil
}

func (s *assetVersionService) BuildSBOM(asset models.Asset, assetVersion models.AssetVersion, artifactName string, organizationName string, components []models.ComponentDependency) (*normalize.CdxBom, error) {
	licenseRisks, err := s.licenseRiskRepository.GetAllOverwrittenLicensesForAssetVersion(assetVersion.AssetID, assetVersion.Name)
	if err != nil {
		return nil, err
	}
	componentLicenseOverwrites := make(map[string]string, len(licenseRisks))
	for i := range licenseRisks {
		if licenseRisks[i].FinalLicenseDecision != nil {
			componentLicenseOverwrites[licenseRisks[i].ComponentPurl] = *licenseRisks[i].FinalLicenseDecision
		}
	}

	return normalize.FromComponents(asset.Slug, artifactName, assetVersion.Name, utils.MapType[normalize.CdxComponent](components), componentLicenseOverwrites), nil
}

func dependencyVulnToOpenVexStatus(dependencyVuln models.DependencyVuln) vex.Status {
	switch dependencyVuln.State {
	case dtos.VulnStateOpen:
		return vex.StatusUnderInvestigation
	case dtos.VulnStateFixed:
		return vex.StatusFixed
	case dtos.VulnStateFalsePositive:
		return vex.StatusNotAffected
	case dtos.VulnStateAccepted:
		return vex.StatusAffected
	case dtos.VulnStateMarkedForTransfer:
		return vex.StatusAffected
	default:
		return vex.StatusUnderInvestigation
	}
}

func (s *assetVersionService) BuildOpenVeX(asset models.Asset, assetVersion models.AssetVersion, organizationSlug string, dependencyVulns []models.DependencyVuln) vex.VEX {
	doc := vex.New()

	doc.Author = organizationSlug
	doc.Timestamp = utils.Ptr(time.Now())
	doc.Statements = make([]vex.Statement, 0)

	appPurl := fmt.Sprintf("pkg:oci/%s/%s@%s", organizationSlug, asset.Slug, assetVersion.Slug)
	for _, dependencyVuln := range dependencyVulns {
		if dependencyVuln.CVE == nil {
			continue
		}

		statement := vex.Statement{
			ID:              dependencyVuln.CVE.CVE,
			Status:          dependencyVulnToOpenVexStatus(dependencyVuln),
			ImpactStatement: utils.OrDefault(getJustification(dependencyVuln), ""),
			Vulnerability: vex.Vulnerability{
				ID:          fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", dependencyVuln.CVE.CVE),
				Name:        vex.VulnerabilityID(dependencyVuln.CVE.CVE),
				Description: dependencyVuln.CVE.Description,
			},
			Products: []vex.Product{{
				Component: vex.Component{
					ID: appPurl,
					Identifiers: map[vex.IdentifierType]string{
						vex.PURL: appPurl,
					},
				},
			}},
		}

		doc.Statements = append(doc.Statements, statement)
	}

	doc.GenerateCanonicalID() // nolint:errcheck
	return doc
}

func (s *assetVersionService) BuildVeX(asset models.Asset, assetVersion models.AssetVersion, artifactName, organizationName string, dependencyVulns []models.DependencyVuln) *normalize.CdxBom {

	vulnerabilities := make([]cdx.Vulnerability, 0)
	for _, dependencyVuln := range dependencyVulns {
		// check if cve
		cve := dependencyVuln.CVE
		if cve != nil {
			firstIssued, lastUpdated, firstResponded := getDatesForVulnerabilityEvent(dependencyVuln.Events)
			vuln := cdx.Vulnerability{
				ID: cve.CVE,
				Source: &cdx.Source{
					Name: "NVD",
					URL:  fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", utils.OrDefault(dependencyVuln.CVEID, "")),
				},
				Affects: &[]cdx.Affects{{
					Ref: utils.OrDefault(dependencyVuln.ComponentPurl, ""),
				}},
				Analysis: &cdx.VulnerabilityAnalysis{
					State:       dependencyVulnStateToImpactAnalysisState(dependencyVuln.State),
					FirstIssued: firstIssued.UTC().Format(time.RFC3339),
					LastUpdated: lastUpdated.UTC().Format(time.RFC3339),
				},
			}
			if !firstResponded.IsZero() {
				vuln.Properties = &[]cdx.Property{{Name: "firstResponded", Value: firstResponded.UTC().Format(time.RFC3339)}}
			}

			response := dependencyVulnStateToResponseStatus(dependencyVuln.State)
			if response != "" {
				vuln.Analysis.Response = &[]cdx.ImpactAnalysisResponse{response}
			}

			justification := getJustification(dependencyVuln)
			if justification != nil {
				vuln.Analysis.Detail = *justification
			} else if response == cdx.IARUpdate {
				vuln.Analysis.Detail = "Update available! Please update to the fixed version."
			}

			cvss := math.Round(float64(cve.CVSS)*100) / 100

			risk := vulndb.RawRisk(*cve, shared.GetEnvironmentalFromAsset(asset), utils.OrDefault(dependencyVuln.ComponentDepth, 1))

			vuln.Ratings = &[]cdx.VulnerabilityRating{
				{
					Vector:   cve.Vector,
					Method:   vectorToCVSSScoringMethod(cve.Vector),
					Score:    &cvss,
					Severity: scoreToSeverity(cvss),
				},
				{
					Vector:        risk.Vector,
					Method:        "DevGuard",
					Score:         &risk.Risk,
					Severity:      scoreToSeverity(risk.Risk),
					Justification: risk.String(),
				},
			}

			vulnerabilities = append(vulnerabilities, vuln)
		}
	}

	return normalize.FromVulnerabilities(asset.Slug, artifactName, assetVersion.Name, vulnerabilities)
}

func scoreToSeverity(score float64) cdx.Severity {
	if score >= 9.0 {
		return cdx.SeverityCritical
	} else if score >= 7.0 {
		return cdx.SeverityHigh
	} else if score >= 4.0 {
		return cdx.SeverityMedium
	}
	return cdx.SeverityLow
}

func vectorToCVSSScoringMethod(vector string) cdx.ScoringMethod {
	if strings.Contains(vector, "CVSS:3.0") {
		return cdx.ScoringMethodCVSSv3
	} else if strings.Contains(vector, "CVSS:2.0") {
		return cdx.ScoringMethodCVSSv2
	} else if strings.Contains(vector, "CVSS:3.1") {
		return cdx.ScoringMethodCVSSv31
	}
	return cdx.ScoringMethodCVSSv4
}

func dependencyVulnStateToImpactAnalysisState(state dtos.VulnState) cdx.ImpactAnalysisState {
	switch state {
	case dtos.VulnStateOpen:
		return cdx.IASInTriage
	case dtos.VulnStateFixed:
		return cdx.IASExploitable
	case dtos.VulnStateAccepted:
		return cdx.IASExploitable
	case dtos.VulnStateFalsePositive:
		return cdx.IASFalsePositive
	case dtos.VulnStateMarkedForTransfer:
		return cdx.IASInTriage
	default:
		return cdx.IASInTriage
	}
}

func getJustification(dependencyVuln models.DependencyVuln) *string {
	// check if we have any event
	if len(dependencyVuln.Events) > 0 {
		// look for the last event which has a justification
		for i := len(dependencyVuln.Events) - 1; i >= 0; i-- {
			if dependencyVuln.Events[i].Type != dtos.EventTypeRawRiskAssessmentUpdated && dependencyVuln.Events[i].Type != dtos.EventTypeComment && dependencyVuln.Events[i].Justification != nil {
				return dependencyVuln.Events[i].Justification
			}
		}
	}
	return nil
}

func dependencyVulnStateToResponseStatus(state dtos.VulnState) cdx.ImpactAnalysisResponse {
	switch state {
	case dtos.VulnStateOpen:
		return ""
	case dtos.VulnStateFixed:
		return cdx.IARUpdate
	case dtos.VulnStateAccepted:
		return cdx.IARWillNotFix
	case dtos.VulnStateFalsePositive:
		return cdx.IARWillNotFix
	case dtos.VulnStateMarkedForTransfer:
		return ""
	default:
		return ""
	}
}

func getDatesForVulnerabilityEvent(vulnEvents []models.VulnEvent) (time.Time, time.Time, time.Time) {
	firstIssued := time.Time{}
	lastUpdated := time.Time{}
	firstResponded := time.Time{}
	if len(vulnEvents) > 0 {
		firstIssued = time.Now()
		// find the date when the vulnerability was detected/created in the database
		for _, event := range vulnEvents {
			if event.Type == dtos.EventTypeDetected {
				firstIssued = event.CreatedAt
				break
			}
		}

		// in case no manual events are available we need to set the default to the firstIssued date
		lastUpdated = firstIssued

		// find the newest/latest event that was triggered through a human / manual interaction
		for _, event := range vulnEvents {
			// only manual events
			if event.Type == dtos.EventTypeFixed ||
				event.Type == dtos.EventTypeReopened ||
				event.Type == dtos.EventTypeAccepted ||
				event.Type == dtos.EventTypeMitigate ||
				event.Type == dtos.EventTypeFalsePositive ||
				event.Type == dtos.EventTypeMarkedForTransfer ||
				event.Type == dtos.EventTypeComment {
				if event.UpdatedAt.After(lastUpdated) {
					lastUpdated = event.UpdatedAt
				}
				if firstResponded.IsZero() {
					firstResponded = event.UpdatedAt
				} else if event.UpdatedAt.Before(firstResponded) {
					firstResponded = event.UpdatedAt
				}
			}
		}
	}

	return firstIssued, lastUpdated, firstResponded
}

// write the components from bom to the output file following the template
func MarkdownTableFromSBOM(outputFile *bytes.Buffer, bom *cdx.BOM) error {

	type componentData struct {
		Package  string
		Version  string
		Licenses []string
	}

	ecosystemCounts := make(map[string]int)
	licenseCounts := make(map[string]int)
	totalComponents := 0

	var templateValues []componentData
	for _, component := range *bom.Components {
		packageName := component.BOMRef

		// parse PURL to extract ecosystem for counting, but keep original packageName intact
		packageurlParsed, err := packageurl.FromString(component.PackageURL)
		if err != nil {
			continue
		}

		// count ecosystem
		ecosystemCounts[packageurlParsed.Type]++
		totalComponents++

		// count licenses
		if component.Licenses != nil && len(*component.Licenses) > 0 {
			for _, licenseChoice := range *component.Licenses {
				if licenseChoice.License != nil {
					if licenseChoice.License.ID != "" {
						licenseCounts[licenseChoice.License.ID]++
					}
				}
			}
		} else {
			licenseCounts["Unknown"]++
		}

		var licenseIDs []string
		if component.Licenses != nil && len(*component.Licenses) > 0 {
			for _, licenseChoice := range *component.Licenses {
				if licenseChoice.License != nil && licenseChoice.License.ID != "" {
					licenseIDs = append(licenseIDs, licenseChoice.License.ID)
				}
			}
		}
		if len(licenseIDs) == 0 {
			licenseIDs = []string{" Unknown"}
		}

		templateValues = append(templateValues, componentData{
			Package:  packageName,
			Version:  component.Version,
			Licenses: licenseIDs,
		})
	}

	// create template data with statistics
	type statEntry struct {
		Name  string
		Count int
	}

	type templateData struct {
		Components      []componentData
		EcosystemStats  []statEntry
		LicenseStats    []statEntry
		TotalComponents int
		ArtifactName    string
		AssetVersion    string
		CreationDate    string
		Publisher       string
	}

	// convert maps to sorted slices
	ecosystemSlice := make([]statEntry, 0, len(ecosystemCounts))
	for name, count := range ecosystemCounts {
		ecosystemSlice = append(ecosystemSlice, statEntry{Name: name, Count: count})
	}

	licenseSlice := make([]statEntry, 0, len(licenseCounts))
	for name, count := range licenseCounts {
		licenseSlice = append(licenseSlice, statEntry{Name: name, Count: count})
	}

	// sort by count descending (highest first)
	slices.SortStableFunc(ecosystemSlice, func(a, b statEntry) int {
		return b.Count - a.Count
	})
	slices.SortStableFunc(licenseSlice, func(a, b statEntry) int {
		return b.Count - a.Count
	})

	data := templateData{
		Components:      templateValues,
		EcosystemStats:  ecosystemSlice,
		LicenseStats:    licenseSlice,
		TotalComponents: totalComponents,
		ArtifactName:    bom.Metadata.Component.Name,
		AssetVersion:    bom.Metadata.Component.Version,
		CreationDate:    bom.Metadata.Timestamp,
		Publisher:       bom.Metadata.Component.Publisher,
	}

	//create template for the sbom markdown table
	sbomTmpl, err := template.New("sbomTmpl").Funcs(template.FuncMap{
		"percentage": func(count, total int) float64 {
			if total == 0 {
				return 0
			}
			return float64(count) / float64(total) * 100.0
		},
	}).Parse(
		`# SBOM

## Overview

- **Artifact Name:** {{ .ArtifactName }}
- **Version:** {{ .AssetVersion }}
- **Created:** {{ .CreationDate }}
- **Publisher:** {{ .Publisher }}

## Statistics

### Ecosystem Distribution
Total Components: {{ .TotalComponents }}

| Ecosystem | Count | Percentage |
|-----------|-------|------------|
{{range .EcosystemStats}}| {{ .Name }} | {{ .Count }} | {{ printf "%.1f%%" (percentage .Count $.TotalComponents) }} |
{{end}}

### License Distribution
| License | Count | Percentage |
|---------|-------|------------|
{{range .LicenseStats}}| {{ .Name }} | {{ .Count }} | {{ printf "%.1f%%" (percentage .Count $.TotalComponents) }} |
{{end}}

\newpage
## Components

| Package 						  | Version | Licenses  |
|---------------------------------|---------|-------|
{{range .Components}}| {{ .Package }} | {{ .Version }} | {{if gt (len .Licenses) 0 }}{{ range .Licenses }}{{.}} {{end}}{{ else }} Unknown {{ end }} |
{{end}}`,
	)
	if err != nil {
		return err
	}
	//filling the template with data from the parsed components and write that to the outputFile
	return sbomTmpl.Execute(outputFile, data)
}

// generate the metadata used to generate the sbom-pdf and return it as struct
func CreateYAMLMetadata(organizationName string, assetName string, assetVersionName string) dtos.YamlMetadata {
	today := time.Now()
	title1, title2 := createTitles(assetName + "@" + assetVersionName)

	if organizationName == "opencode" {
		organizationName = "openCode"
	}

	// TO-DO: add sha hash to test the integrity
	return dtos.YamlMetadata{
		Vars: dtos.YamlVars{
			DocumentTitle:    "DevGuard Report",
			PrimaryColor:     "\"#FF5733\"",
			Version:          assetVersionName,
			TimeOfGeneration: fmt.Sprintf("%s. %s %s", strconv.Itoa(today.Day()), today.Month().String(), strconv.Itoa(today.Year())),
			ProjectTitle1:    title1,
			ProjectTitle2:    title2,
			OrganizationName: organizationName,
			Integrity:        "",
		},
	}
}

// Divide and/or crop the project name into two, max 14 characters long, strings, there is probably a more elegant way to do this
func createTitles(name string) (string, string) {
	const maxTitleLength = 14 //make the length easy changeable
	title1 := ""
	title2 := ""
	title1Full := false            //once a field has exceeded the length of title1 we can ignore title1 from there on
	fields := strings.Fields(name) //separate the words divided by white spaces
	for _, field := range fields {
		if title1 == "" { //we have to differentiate if A tittle is empty or not before using, because of the white spaces between words in a title
			if len(field) <= maxTitleLength { //if it fits the 14 char limit we can just write it and move to the next
				title1 = field
			} else { //if not we know it won't fit the second one as well so we break the word up using "-"
				title1 = field[:maxTitleLength-1] + "-"
				title1Full = true                                    //we flag title1 as full
				if len(field[maxTitleLength-1:]) <= maxTitleLength { //now we need to append the rest of the word after "-"
					title2 = field[maxTitleLength-1:] //if the rest fits into the 14 char limit we just write it there
				} else {
					title2 = field[maxTitleLength-1:2*maxTitleLength-3] + ".." //if not we need to truncate the last 2 chars and put a .. to symbolize the ending
					break                                                      //then we are done since we know nothing fits anymore
				}
			}
		} else { //title1 is not empty so we now work with whitespaces
			if !title1Full && len(title1)+1+len(field) <= maxTitleLength { //add +1 because we need to account for an inserted white space
				title1 = title1 + " " + field
			} else { //if the field does not fit we move to the second title2 and here we again have to first check if its empty
				if title2 == "" {
					if len(field) <= maxTitleLength { //same as above
						title2 = field
					} else {
						title2 = field[:maxTitleLength-2] + ".." //same as above
						break
					}
				} else { //if its not empty we again try to put new fields into title2 until we are full
					if len(title2)+1+len(field) <= maxTitleLength { //it fits so we just write it in the title
						title2 = title2 + " " + field
					} else {
						if maxTitleLength-len(title2)-1 >= 4 { //if it doesn't fit we can only truncate like before if there are more than 3 remaining chars because we need 2 for the .. and 1 whitespace
							title2 = title2 + " " + field[:(maxTitleLength-3-len(title2))] + ".."
						}
						break //in either case we are done after this field
					}
				}
			}
		}
	}
	//now we return the two titles formatted correctly for the yaml file
	return title1, title2
}
