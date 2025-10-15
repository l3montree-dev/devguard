package artifact

import (
	"encoding/json"
	"log/slog"
	"os"
	"strings"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/core/normalize"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/utils"
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

func (s *service) AddUpstreamURLs(artifact *models.Artifact, upstreamURLs []string) error {
	return s.artifactRepository.AddUpstreamURLs(artifact, upstreamURLs)
}

func (s *service) RemoveUpstreamURLs(artifact *models.Artifact, upstreamURLs []string) error {
	return s.artifactRepository.RemoveUpstreamURLs(artifact, upstreamURLs)
}

func (s *service) ReadArtifact(name string, assetVersionName string, assetID uuid.UUID) (models.Artifact, error) {
	return s.artifactRepository.ReadArtifact(name, assetVersionName, assetID)
}

func (s *service) CheckVexURLs(upstreamURLs []string) ([]cyclonedx.BOM, []string, []string) {
	var boms []cyclonedx.BOM

	var validURLs []string
	var invalidURLs []string

	//check if the upstream urls are valid urls
	for _, url := range upstreamURLs {
		var bom cyclonedx.BOM
		// download the url and check if it is a valid vex file
		file, err := os.ReadFile(url)
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
		boms = append(boms, bom)
	}

	return boms, validURLs, invalidURLs
}

func (s *service) SyncVexReports(boms []cyclonedx.BOM, org models.Org, project models.Project, asset models.Asset, assetVersion models.AssetVersion, artifact models.Artifact, userID string) error {

	// load existing dependency vulns for this asset version
	existingVulns, err := s.dependencyVulnRepository.GetDependencyVulnsByAssetVersion(nil, assetVersion.Name, assetVersion.AssetID, nil)
	if err != nil {
		slog.Error("could not load dependency vulns", "err", err)
		return echo.NewHTTPError(500, "could not load dependency vulns").WithInternal(err)
	}

	// index by CVE id
	vulnsByCVE := make(map[string][]models.DependencyVuln)
	for _, v := range existingVulns {
		if v.CVE != nil && v.CVE.CVE != "" {
			vulnsByCVE[v.CVE.CVE] = append(vulnsByCVE[v.CVE.CVE], v)
		} else if v.CVEID != nil && *v.CVEID != "" {
			vulnsByCVE[*v.CVEID] = append(vulnsByCVE[*v.CVEID], v)
		}
	}

	updated := 0
	notFound := 0

	// helper to extract cve id from CycloneDX vulnerability id or source url
	extractCVE := func(s string) string {
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

	notExistingVulnsList := []models.DependencyVuln{}
	type VulnState struct {
		state         string
		justification string
	}
	notExistingVulnsState := make(map[int]VulnState)

	components := make(map[string]models.Component)
	dependencies := make([]models.ComponentDependency, 0)

	// iterate vulnerabilities in the CycloneDX BOM
	for _, bom := range boms {
		if bom.Vulnerabilities != nil {
			for _, vuln := range *bom.Vulnerabilities {
				cveID := extractCVE(vuln.ID)
				if cveID == "" && vuln.Source != nil && vuln.Source.URL != "" {
					cveID = extractCVE(vuln.Source.URL)
				}
				if cveID == "" {
					notFound++
					continue
				}

				cveID = strings.ToUpper(strings.TrimSpace(cveID))
				cve, err := s.cveRepository.FindCVE(nil, cveID)
				if err != nil {
					slog.Error("could not load cve", "err", err, "cve", cveID)
					notFound++
					continue
				}

				statusType := normalize.MapCDXToStatus(vuln.Analysis)
				justification := ""
				if vuln.Analysis != nil && vuln.Analysis.Detail != "" {
					justification = vuln.Analysis.Detail
				}

				vulnsList, ok := vulnsByCVE[cveID]
				if !ok || len(vulnsList) == 0 {
					var componentPurl *string
					if vuln.Affects != nil && len(*vuln.Affects) > 0 && (*vuln.Affects)[0].Ref != "" {
						ref := (*vuln.Affects)[0].Ref
						componentPurl = &ref
						if _, ok := components[ref]; !ok {
							c := models.Component{
								Purl: ref,
							}
							components[ref] = c
						}

					}
					dependencyVuln := models.DependencyVuln{
						Vulnerability: models.Vulnerability{
							AssetVersionName: assetVersion.Name,
							AssetID:          asset.ID,
						},
						Artifacts: []models.Artifact{
							artifact,
						},
						CVEID:                 &cveID,
						ComponentPurl:         componentPurl,
						ComponentFixedVersion: nil,
						ComponentDepth:        utils.Ptr(0), //TODO: it's unknown
						CVE:                   &cve,
					}

					notExistingVulnsList = append(notExistingVulnsList, dependencyVuln)
					notExistingVulnsState[len(notExistingVulnsList)-1] = VulnState{state: statusType, justification: justification}

					notFound++
					continue
				}

				if statusType == "" {
					// skip unknown/unspecified statuses
					continue
				}

				for i := range vulnsList {
					_, err := s.dependencyVulnService.UpdateDependencyVulnState(nil, asset.ID, userID, &vulnsList[i], statusType, justification, models.MechanicalJustificationType(""), assetVersion.Name, 1) // mechanical justification is not part of cyclonedx spec.
					if err != nil {
						slog.Error("could not update dependency vuln state", "err", err, "cve", cveID)
						continue
					}
					updated++
				}
			}
		}
	}

	// create missing component and dependencies
	if len(components) > 0 {
		rootComponentPurl, err := s.componentRepository.GetRootComponentPurl(nil, artifact.ArtifactName, assetVersion.Name, asset.ID)
		if err != nil {
			slog.Error("could not determine root component purl", "err", err, "artifact", artifact.ArtifactName, "assetVersion", assetVersion.Name, "assetID", asset.ID)
			return echo.NewHTTPError(500, "could not determine root component purl").WithInternal(err)
		}

		if rootComponentPurl == "" {
			rootComponentPurl = artifact.ArtifactName
		}

		for purl := range components {
			componentDependency := models.ComponentDependency{
				DependencyPurl: purl,
				ComponentPurl:  &rootComponentPurl,
			}
			dependencies = append(dependencies, componentDependency)
		}
	}

	//build a sbom
	sbom, err := s.assetVersionService.BuildSBOM(assetVersion, artifact.ArtifactName, "vex-upload", org.Name, dependencies)
	if err != nil {
		slog.Error("could not build sbom", "err", err)
		return echo.NewHTTPError(500, "could not build sbom").WithInternal(err)
	}

	err = s.assetVersionService.UpdateSBOM(org, project, asset, assetVersion, artifact.ArtifactName, normalize.FromCdxBom(sbom, false), 1)
	if err != nil {
		slog.Error("could not update sbom", "err", err)
		return echo.NewHTTPError(500, "could not update sbom").WithInternal(err)
	}

	if len(notExistingVulnsList) > 0 {

		assetVersion, err := s.assetVersionRepository.Read(assetVersion.Name, asset.ID)
		if err != nil {
			slog.Error("could not find asset version", "err", err, "assetVersion", assetVersion.Name, "assetID", asset.ID)
			return echo.NewHTTPError(404, "could not find asset version").WithInternal(err)
		}

		err = s.dependencyVulnService.UserDetectedDependencyVulns(nil, artifact.ArtifactName, notExistingVulnsList, assetVersion, asset, 1)
		if err != nil {
			slog.Error("could not create dependency vulns", "err", err)
			return echo.NewHTTPError(500, "could not create dependency vulns").WithInternal(err)
		}

		//update the stats for dependency vulns
		for i, v := range notExistingVulnsList {
			_, err := s.dependencyVulnService.UpdateDependencyVulnState(nil, asset.ID, userID, &v, notExistingVulnsState[i].state, notExistingVulnsState[i].justification, models.MechanicalJustificationType(""), assetVersion.Name, 1)
			if err != nil {
				slog.Error("could not update dependency vuln state", "err", err, "cve", v.CVEID)
				continue
			}

		}
	}

	return nil
}
