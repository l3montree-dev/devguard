package artifact

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/core/normalize"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/labstack/echo/v4"
)

type service struct {
	artifactRepository       core.ArtifactRepository
	cveRepository            core.CveRepository
	componentRepository      core.ComponentRepository
	dependencyVulnRepository core.DependencyVulnRepository
	assetRepository          core.AssetRepository
	assetVersionRepository   core.AssetVersionRepository
	assetVersionService      core.AssetVersionService
	dependencyVulnService    core.DependencyVulnService
}

func NewService(artifactRepository core.ArtifactRepository, cveRepository core.CveRepository, componentRepository core.ComponentRepository, dependencyVulnRepository core.DependencyVulnRepository, assetRepository core.AssetRepository, assetVersionRepository core.AssetVersionRepository, assetVersionService core.AssetVersionService, dependencyVulnService core.DependencyVulnService) *service {
	return &service{
		artifactRepository:       artifactRepository,
		cveRepository:            cveRepository,
		componentRepository:      componentRepository,
		dependencyVulnRepository: dependencyVulnRepository,
		assetRepository:          assetRepository,
		assetVersionRepository:   assetVersionRepository,
		assetVersionService:      assetVersionService,
		dependencyVulnService:    dependencyVulnService,
	}
}

func (s *service) GetArtifactNamesByAssetIDAndAssetVersionName(assetID uuid.UUID, assetVersionName string) ([]models.Artifact, error) {
	artifacts, err := s.artifactRepository.GetByAssetIDAndAssetVersionName(assetID, assetVersionName)
	if err != nil {
		return nil, err
	}

	return artifacts, nil
}

func (s *service) SaveArtifact(artifact *models.Artifact) error {
	return s.artifactRepository.Save(nil, artifact)
}

func (s *service) DeleteArtifact(assetID uuid.UUID, assetVersionName string, artifactName string) error {
	return s.artifactRepository.DeleteArtifact(assetID, assetVersionName, artifactName)
}

func (s *service) ReadArtifact(name string, assetVersionName string, assetID uuid.UUID) (models.Artifact, error) {
	return s.artifactRepository.ReadArtifact(name, assetVersionName, assetID)
}

func (s *service) FetchBomsFromUpstream(artifactName string, upstreamURLs []string) ([]*normalize.CdxBom, []string, []string) {
	var boms []*normalize.CdxBom

	var validURLs []string
	var invalidURLs []string

	client := &http.Client{}

	//check if the upstream urls are valid urls
	for _, url := range upstreamURLs {
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
		validURLs = append(validURLs, url)
		boms = append(boms, normalize.FromCdxBom(&bom, artifactName, url))

	}

	return boms, validURLs, invalidURLs
}

// helper to extract cve id from CycloneDX vulnerability id or source url
func extractCVE(s string) string {
	if s == "" {
		return ""
	}
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "http") {
		parts := strings.Split(s, "/")
		return parts[len(parts)-1]
	}
	return s
}

func (s *service) SyncUpstreamBoms(boms []*normalize.CdxBom, org models.Org, project models.Project, asset models.Asset, assetVersion models.AssetVersion, artifact models.Artifact, userID string) ([]models.DependencyVuln, error) {

	upstream := models.UpstreamStateExternalAccepted
	if asset.ParanoidMode {
		upstream = models.UpstreamStateExternal
	}

	notFound := 0

	type VulnEvent struct {
		eventType     models.VulnEventType
		purl          string
		justification string
	}

	// keyed by CVE-ID
	expectedMap := make(map[string]VulnEvent)

	// iterate vulnerabilities in the CycloneDX BOM
	cveIDs := make([]string, 0)

	allVulns := make([]models.DependencyVuln, 0)
	for _, bom := range boms {
		vulns := bom.GetVulnerabilities()
		if vulns != nil {
			for _, vuln := range *vulns {
				cveID := extractCVE(vuln.ID)
				if cveID == "" && vuln.Source != nil && vuln.Source.URL != "" {
					cveID = extractCVE(vuln.Source.URL)
				}
				if cveID == "" {
					notFound++
					continue
				}

				cveID = strings.ToUpper(strings.TrimSpace(cveID))
				cveIDs = append(cveIDs, cveID)

				eventType := normalize.MapCDXToEventType(vuln.Analysis)
				if eventType == "" {
					// skip unknown/unspecified statuses
					continue
				}

				justification := ""
				if vuln.Analysis != nil && vuln.Analysis.Detail != "" {
					justification = vuln.Analysis.Detail
				}

				if vuln.Affects == nil || len(*vuln.Affects) == 0 || (*vuln.Affects)[0].Ref == "" {
					continue
				}
				ref := (*vuln.Affects)[0].Ref

				componentPurl := ref

				expectedMap[cveID] = VulnEvent{eventType: models.VulnEventType(eventType), justification: justification,
					purl: componentPurl}
			}

		}

		cves, err := s.cveRepository.FindCVEs(nil, cveIDs)
		// convert to map
		if err != nil {
			slog.Error("could not load cves", "err", err)
			return nil, echo.NewHTTPError(500, "could not load cves").WithInternal(err)
		}
		cvesMap := make(map[string]models.CVE)
		for _, cve := range cves {
			cvesMap[cve.CVE] = cve
		}

		// convert the expected vuln state into vuln in package to reuse the handle scan result function
		vulnsInPackage := []models.VulnInPackage{}
		for cveID, state := range expectedMap {
			if cve, exists := cvesMap[cveID]; exists {
				// skip CVEs that do not exist in the database
				vulnInPackage := models.VulnInPackage{
					CVE:   cve,
					Purl:  state.purl,
					CVEID: cveID,
				}
				vulnsInPackage = append(vulnsInPackage, vulnInPackage)
			}
		}

		_, _, newState, err := s.assetVersionService.HandleScanResult(org, project, asset, &assetVersion, vulnsInPackage, artifact.ArtifactName, userID, asset.UpstreamState())
		if err != nil {
			slog.Error("could not handle scan result", "err", err)
			return nil, echo.NewHTTPError(500, "could not handle scan result").WithInternal(err)
		}

		_, err = s.assetVersionService.UpdateSBOM(org, project, asset, assetVersion, artifact.ArtifactName, bom, upstream)
		if err != nil {
			slog.Error("could not update sbom", "err", err)
			return nil, echo.NewHTTPError(500, "could not update sbom").WithInternal(err)
		}

	outer:
		for i := range newState {
			if expected, ok := expectedMap[*newState[i].CVEID]; ok {

				expectedEventType, err := models.EventTypeToVulnState(expected.eventType)
				if err != nil {
					slog.Error("could not map event type to vuln state", "err", err, "cve", *newState[i].CVEID)
					continue
				}
				// check if we already have seen this event from upstream
				for j := len(newState[i].Events) - 1; j >= 0; j-- {
					event := newState[i].Events[j]
					eventType, err := models.EventTypeToVulnState(event.Type)
					if err != nil {
						slog.Error("could not map event type to vuln state", "err", err, "cve", *newState[i].CVEID)
						continue
					}
					// only consider non-internal upstream events
					if event.Upstream != models.UpstreamStateInternal {
						// the last event
						if eventType == expectedEventType && event.Justification != nil && *event.Justification == expected.justification {
							// we already have seen this event
							continue outer
						} else {
							// we need todo it
							break
						}
					}
				}

				if newState[i].State != models.VulnStateOpen && expected.eventType == models.EventTypeAccepted {
					// map the event to a reopen event if the vuln is not open yet
					expected.eventType = models.EventTypeReopened
				}

				_, err = s.dependencyVulnService.CreateVulnEventAndApply(nil, asset.ID, userID, &newState[i], expected.eventType, expected.justification, models.MechanicalJustificationType(""), assetVersion.Name, upstream)
				if err != nil {
					slog.Error("could not update dependency vuln state", "err", err, "cve", *newState[i].CVEID)
					continue
				}
			}
		}

		allVulns = append(allVulns, newState...)
	}

	return allVulns, nil
}
