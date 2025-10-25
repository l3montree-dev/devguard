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

func (s *service) FetchBomsFromUpstream(upstreamURLs []string) ([]normalize.BomWithOrigin, []string, []string) {
	var boms []normalize.BomWithOrigin

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
		boms = append(boms, normalize.BomWithOrigin{
			BOM:    bom,
			Origin: url,
		})
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

func (s *service) SyncUpstreamBoms(boms []normalize.BomWithOrigin, org models.Org, project models.Project, asset models.Asset, assetVersion models.AssetVersion, artifact models.Artifact, userID string) ([]models.DependencyVuln, error) {

	allVulns := []models.DependencyVuln{}

	// load existing dependency vulns for this asset version
	existingVulns, err := s.dependencyVulnRepository.GetDependencyVulnsByAssetVersion(nil, assetVersion.Name, assetVersion.AssetID, nil)
	if err != nil {
		slog.Error("could not load dependency vulns", "err", err)
		return allVulns, echo.NewHTTPError(500, "could not load dependency vulns").WithInternal(err)
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

	upstream := models.UpstreamStateExternalAccepted
	if asset.ParanoidMode {
		upstream = models.UpstreamStateExternal
	}

	updated := 0
	notFound := 0

	notExistingVulnsList := []models.DependencyVuln{}
	type VulnState struct {
		state         string
		justification string
	}
	notExistingVulnsState := make(map[int]VulnState)

	// iterate vulnerabilities in the CycloneDX BOM
	for _, bom := range boms {
		linkSbom := cyclonedx.BOM{}
		linkSbom.Metadata = &cyclonedx.Metadata{
			Component: &cyclonedx.Component{
				BOMRef: artifact.ArtifactName,
				Name:   artifact.ArtifactName,
				Type:   cyclonedx.ComponentTypeApplication,
			}}
		linkSbom.Components = &[]cyclonedx.Component{}
		linkSbom.Dependencies = &[]cyclonedx.Dependency{}
		// create artificial ROOT -> Origin -> Components structure
		linkSbom.Components = utils.Ptr(append(*linkSbom.Components, cyclonedx.Component{
			BOMRef: artifact.ArtifactName,
			Name:   artifact.ArtifactName,
			Type:   cyclonedx.ComponentTypeApplication,
		}, cyclonedx.Component{
			BOMRef: bom.Origin,
			Name:   bom.Origin,
		}))
		linkSbom.Dependencies = utils.Ptr(append(*linkSbom.Dependencies, cyclonedx.Dependency{
			Ref:          linkSbom.Metadata.Component.BOMRef,
			Dependencies: &[]string{bom.Origin},
		}))
		originDependencies := []string{}
		if bom.Components != nil {
			linkSbom.Components = utils.Ptr(append(*linkSbom.Components, *bom.Components...))
			ref := bom.Metadata.Component.BOMRef
			linkSbom.Components = utils.Ptr(append(*linkSbom.Components, cyclonedx.Component{
				BOMRef:     ref,
				PackageURL: ref,
				Name:       ref,
			}))
			originDependencies = append(originDependencies, ref)
		}
		if bom.Dependencies != nil {
			linkSbom.Dependencies = utils.Ptr(append(*linkSbom.Dependencies, *bom.Dependencies...))
		}

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
				if statusType == "" {
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

				linkSbom.Components = utils.Ptr(append(*linkSbom.Components, cyclonedx.Component{
					BOMRef:     ref,
					PackageURL: ref,
					Name:       ref,
				}))

				originDependencies = append(originDependencies, ref)

				vulnsList, ok := vulnsByCVE[cveID]
				if !ok || len(vulnsList) == 0 {

					componentPurl := &ref

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

				for i := range vulnsList {

					//check if we should update the state
					events := vulnsList[i].Events
					update := true
					for j := len(events) - 1; j >= 0; j-- {

						if events[j].Upstream == upstream {
							justificationValue := ""
							if events[j].Justification != nil {
								justificationValue = *events[j].Justification
							}
							if statusType == string(events[j].Type) && justification == justificationValue {
								update = false
								break
							}

						}
					}
					if !update {
						continue
					}
					_, err := s.dependencyVulnService.UpdateDependencyVulnState(nil, asset.ID, userID, &vulnsList[i], statusType, justification, models.MechanicalJustificationType(""), assetVersion.Name, upstream) // mechanical justification is not part of cyclonedx spec.
					if err != nil {
						slog.Error("could not update dependency vuln state", "err", err, "cve", cveID)
						continue
					}
					updated++
				}

				allVulns = append(allVulns, vulnsList...)
			}
		}

		allVulns = append(allVulns, notExistingVulnsList...)

		// set origin dependencies
		linkSbom.Dependencies = utils.Ptr(append(*linkSbom.Dependencies, cyclonedx.Dependency{
			Ref:          bom.Origin,
			Dependencies: &originDependencies,
		}))

		err = s.assetVersionService.UpdateSBOM(org, project, asset, assetVersion, artifact.ArtifactName, normalize.CdxBom(&linkSbom), bom.Origin, upstream)
		if err != nil {
			slog.Error("could not update sbom", "err", err)
			return allVulns, echo.NewHTTPError(500, "could not update sbom").WithInternal(err)
		}
	}

	if len(notExistingVulnsList) > 0 {
		err = s.dependencyVulnService.UserDetectedDependencyVulns(nil, artifact.ArtifactName, notExistingVulnsList, assetVersion, asset, upstream, true)
		if err != nil {
			slog.Error("could not create dependency vulns", "err", err)
			return allVulns, echo.NewHTTPError(500, "could not create dependency vulns").WithInternal(err)
		}

		//update the stats for dependency vulns
		for i, v := range notExistingVulnsList {
			_, err := s.dependencyVulnService.UpdateDependencyVulnState(nil, asset.ID, userID, &v, notExistingVulnsState[i].state, notExistingVulnsState[i].justification, models.MechanicalJustificationType(""), assetVersion.Name, upstream)
			if err != nil {
				slog.Error("could not update dependency vuln state", "err", err, "cve", v.CVEID)
				continue
			}

		}
	}

	return allVulns, nil
}
