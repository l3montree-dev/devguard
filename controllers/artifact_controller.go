// Copyright 2025 l3montree GmbH.
// SPDX-License-Identifier: 	AGPL-3.0-or-later

package controllers

import (
	"archive/zip"
	"bytes"
	"embed"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"os"
	"strings"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/normalize"
	"github.com/l3montree-dev/devguard/services"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/transformer"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/labstack/echo/v4"
	"github.com/openvex/go-vex/pkg/vex"
	"go.yaml.in/yaml/v2"
)

type ArtifactController struct {
	artifactRepository       shared.ArtifactRepository
	artifactService          shared.ArtifactService
	dependencyVulnService    shared.DependencyVulnService
	dependencyVulnRepository shared.DependencyVulnRepository
	statisticsService        shared.StatisticsService
	componentService         shared.ComponentService
	assetVersionService      shared.AssetVersionService
	vexRuleService           shared.VEXRuleService
	thirdPartyIntegration    shared.IntegrationAggregate
	// mark public to let it be overridden in tests
	utils.FireAndForgetSynchronizer
	shared.ScanService
}

func NewArtifactController(artifactRepository shared.ArtifactRepository, artifactService shared.ArtifactService, assetVersionService shared.AssetVersionService, dependencyVulnService shared.DependencyVulnService, statisticsService shared.StatisticsService, componentService shared.ComponentService, scanService shared.ScanService, synchronizer utils.FireAndForgetSynchronizer, dependencyVulnRepository shared.DependencyVulnRepository, vexRuleService shared.VEXRuleService, thirdPartyIntegration shared.IntegrationAggregate) *ArtifactController {
	return &ArtifactController{
		artifactRepository:        artifactRepository,
		artifactService:           artifactService,
		dependencyVulnService:     dependencyVulnService,
		statisticsService:         statisticsService,
		FireAndForgetSynchronizer: synchronizer,
		componentService:          componentService,
		assetVersionService:       assetVersionService,
		dependencyVulnRepository:  dependencyVulnRepository,
		ScanService:               scanService,
		vexRuleService:            vexRuleService,
		thirdPartyIntegration:     thirdPartyIntegration,
	}
}

type informationSource struct {
	URL  string  `json:"url"`
	Purl *string `json:"purl"`
	// type can be "csaf", "vex", "sbom"
	Type string `json:"type,omitempty"`
}

func informationSourceToString(source informationSource) string {
	r := source.URL
	if source.Purl != nil && *source.Purl != "" {
		r = *source.Purl + ":" + r
	}
	if source.Type != "" {
		r = source.Type + ":" + r
	}
	return r
}

// @Summary Create artifact
// @Tags Artifacts
// @Security CookieAuth
// @Security PATAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Param assetSlug path string true "Asset slug"
// @Param assetVersionSlug path string true "Asset version slug"
// @Param body body object true "Artifact data"
// @Success 201 {object} models.Artifact
// @Router /organizations/{organization}/projects/{projectSlug}/assets/{assetSlug}/refs/{assetVersionSlug}/artifacts [post]
func (c *ArtifactController) Create(ctx shared.Context) error {
	asset := shared.GetAsset(ctx)

	assetVersion := shared.GetAssetVersion(ctx)
	org := shared.GetOrg(ctx)

	project := shared.GetProject(ctx)

	type requestBody struct {
		ArtifactName       string              `json:"artifactName"`
		InformationSources []informationSource `json:"informationSources"`
	}

	var body requestBody

	if err := ctx.Bind(&body); err != nil {
		return err
	}

	artifact := models.Artifact{
		ArtifactName:     body.ArtifactName,
		AssetVersionName: assetVersion.Name,
		AssetID:          asset.ID,
	}

	tx := c.artifactRepository.GetDB(nil).Begin()
	//save the artifact
	err := c.artifactRepository.Create(tx, &artifact)
	if err != nil {
		tx.Rollback()
		return err
	}

	//check if the upstream urls are valid urls
	boms, _, invalid := c.FetchSbomsFromUpstream(artifact.ArtifactName, artifact.AssetVersionName, utils.Map(body.InformationSources, informationSourceToString), asset.KeepOriginalSbomRootComponent)
	if len(invalid) > 0 {
		tx.Rollback()
		return ctx.JSON(400, invalid)
	}

	// merge all boms
	newGraph := normalize.NewSBOMGraph()
	for _, bom := range boms {
		newGraph.MergeGraph(bom) // we dont care for the diff
	}

	bom, err := c.assetVersionService.UpdateSBOM(tx, org, project, asset, assetVersion, artifact.ArtifactName, newGraph)

	if err != nil {
		tx.Rollback()
		slog.Error("could not update sbom", "err", err)
		return echo.NewHTTPError(500, "could not update sbom").WithInternal(err)
	}
	currentUserID := shared.GetSession(ctx).GetUserID()

	_, _, newState, err := c.ScanNormalizedSBOM(tx, org, project, asset, assetVersion, artifact, bom, currentUserID)

	if err != nil {
		tx.Rollback()
		slog.Error("could not scan sbom after creating artifact", "err", err)
		return echo.NewHTTPError(500, "could not scan sbom after creating artifact").WithInternal(err)
	}

	// update the license information in the background
	c.FireAndForget(func() {
		slog.Info("updating license information in background", "asset", assetVersion.Name, "assetID", assetVersion.AssetID)
		_, err := c.componentService.GetAndSaveLicenseInformation(nil, assetVersion, utils.Ptr(artifact.ArtifactName), false)
		if err != nil {
			slog.Error("could not update license information", "asset", assetVersion.Name, "assetID", assetVersion.AssetID, "err", err)
		} else {
			slog.Info("license information updated", "asset", assetVersion.Name, "assetID", assetVersion.AssetID)
		}
	})

	if assetVersion.DefaultBranch || assetVersion.Type == models.AssetVersionTag {
		c.FireAndForget(func() {
			// Export the updated graph back to CycloneDX format for the event
			exportedBOM := bom.ToCycloneDX(normalize.BOMMetadata{
				RootName: artifact.ArtifactName,
			})
			if err = c.thirdPartyIntegration.HandleEvent(shared.SBOMCreatedEvent{
				AssetVersion: shared.ToAssetVersionObject(assetVersion),
				Asset:        shared.ToAssetObject(asset),
				Project:      shared.ToProjectObject(project),
				Org:          shared.ToOrgObject(org),
				Artifact: shared.ArtifactObject{
					ArtifactName: artifact.ArtifactName,
				},
				SBOM: exportedBOM,
			}); err != nil {
				slog.Error("could not handle SBOM updated event", "err", err)
			} else {
				slog.Info("handled SBOM updated event", "assetVersion", assetVersion.Name, "assetID", assetVersion.AssetID)
			}
		})
	}

	c.FireAndForget(func() {
		err := c.dependencyVulnService.SyncIssues(org, project, asset, assetVersion, newState)
		if err != nil {
			slog.Error("could not create issues for vulnerabilities", "err", err)
		}
	})

	c.FireAndForget(func() {
		slog.Info("recalculating risk history for asset", "asset version", assetVersion.Name, "assetID", asset.ID)
		if err := c.statisticsService.UpdateArtifactRiskAggregation(&artifact, asset.ID, utils.OrDefault(artifact.LastHistoryUpdate, assetVersion.CreatedAt), time.Now()); err != nil {
			slog.Error("could not recalculate risk history", "err", err)
		}
	})

	return ctx.JSON(201, transformer.ArtifactModelToDTO(artifact))
}

// @Summary Delete artifact
// @Tags Artifacts
// @Security CookieAuth
// @Security PATAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Param assetSlug path string true "Asset slug"
// @Param assetVersionSlug path string true "Asset version slug"
// @Param artifactName path string true "Artifact name"
// @Success 200
// @Router /organizations/{organization}/projects/{projectSlug}/assets/{assetSlug}/refs/{assetVersionSlug}/artifacts/{artifactName} [delete]
func (c *ArtifactController) DeleteArtifact(ctx shared.Context) error {

	asset := shared.GetAsset(ctx)

	assetVersion := shared.GetAssetVersion(ctx)

	artifact := shared.GetArtifact(ctx)

	// Extract org and project before FireAndForget since Echo contexts are not goroutine-safe
	org := shared.GetOrg(ctx)
	project := shared.GetProject(ctx)

	// we need to sync the vulnerabilities after deleting the artifact
	// maybe we need to close some: https://github.com/l3montree-dev/devguard/issues/1496
	// fetch all vulnerabilities which ONLY belong to this artifact
	vulns, err := c.dependencyVulnRepository.GetAllVulnsByArtifact(nil, artifact)
	if err != nil {
		return echo.NewHTTPError(500, "could not fetch vulnerabilities").WithInternal(err)
	}
	syncVulns := make([]models.DependencyVuln, 0)
	// check which vulns will be removed completely
	for _, vuln := range vulns {
		if len(vuln.Artifacts) <= 1 {
			// mark it as fixed so it gets closed in the issue tracker
			vuln.State = dtos.VulnStateFixed
			syncVulns = append(syncVulns, vuln)
		}
	}

	if len(syncVulns) > 0 {
		c.FireAndForget(func() {
			err := c.dependencyVulnService.SyncIssues(org, project, asset, assetVersion, syncVulns)
			if err != nil {
				slog.Error("could not sync issues for vulnerabilities after artifact deletion", "err", err)
			}
		})
	}

	// DeleteArtifact now handles depth recalculation internally
	err = c.artifactService.DeleteArtifact(asset.ID, assetVersion.Name, artifact.ArtifactName)

	if err != nil {
		return err
	}

	return ctx.NoContent(200)
}

// @Summary Update artifact
// @Tags Artifacts
// @Security CookieAuth
// @Security PATAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Param assetSlug path string true "Asset slug"
// @Param assetVersionSlug path string true "Asset version slug"
// @Param artifactName path string true "Artifact name"
// @Param body body object true "Artifact data"
// @Success 200 {object} object
// @Router /organizations/{organization}/projects/{projectSlug}/assets/{assetSlug}/refs/{assetVersionSlug}/artifacts/{artifactName} [put]
func (c *ArtifactController) UpdateArtifact(ctx shared.Context) error {

	asset := shared.GetAsset(ctx)
	assetVersion := shared.GetAssetVersion(ctx)
	org := shared.GetOrg(ctx)
	project := shared.GetProject(ctx)
	artifactName, err := shared.GetArtifactName(ctx)
	if err != nil {
		return err
	}

	artifact, err := c.artifactService.ReadArtifact(artifactName, assetVersion.Name, asset.ID)
	if err != nil {
		return err
	}

	type requestBody struct {
		ArtifactName       string              `json:"artifactName"`
		InformationSources []informationSource `json:"informationSources"`
	}

	var body requestBody

	if err := ctx.Bind(&body); err != nil {
		return err
	}

	oldSources, err := c.componentService.FetchInformationSources(&artifact)
	if err != nil {
		return echo.NewHTTPError(500, "could not fetch artifact root nodes").WithInternal(err)
	}

	comparison := utils.CompareSlices(utils.Map(body.InformationSources, informationSourceToString), utils.Map(oldSources, func(el models.ComponentDependency) string {
		return el.DependencyID
	}), func(e string) string { return e })

	toAdd := comparison.OnlyInA
	toDelete := comparison.OnlyInB

	// we just need to remove those root nodes.
	if err := c.componentService.RemoveInformationSources(&artifact, toDelete); err != nil {
		return echo.NewHTTPError(500, "could not remove root nodes").WithInternal(err)
	}

	// make sure we remove the prefix before fetching the sbom
	toAddUrls := utils.Map(toAdd, func(e string) string {
		_, u := normalize.RemoveInformationSourcePrefixIfExists(e)
		return u
	})

	//check if the upstream urls are valid urls
	boms, _, invalidURLs := c.FetchSbomsFromUpstream(artifactName, artifact.AssetVersionName, toAddUrls, asset.KeepOriginalSbomRootComponent)
	var vulns []models.DependencyVuln

	graph := normalize.NewSBOMGraph()
	for _, bom := range boms {
		graph.MergeGraph(bom)
	}

	tx := c.artifactRepository.Begin()

	// make sure that we at least update the sbom once if there were deletions
	// updating with nil, will just renormalize the sbom and remove all components which are not
	// reachable anymore from the root nodes - we might have removed some root nodes above
	sbom, err := c.assetVersionService.UpdateSBOM(tx, org, project, asset, assetVersion, artifact.ArtifactName, graph)
	if err != nil {
		slog.Error("could not update sbom", "err", err)
		return echo.NewHTTPError(500, "could not update sbom").WithInternal(err)
	}

	_, _, vulns, err = c.ScanNormalizedSBOM(tx, org, project, asset, assetVersion, artifact, sbom, shared.GetSession(ctx).GetUserID())
	if err != nil {
		slog.Error("could not scan sbom after updating it", "err", err)
		return echo.NewHTTPError(500, "could not scan sbom after updating it").WithInternal(err)
	}

	tx.Commit()

	// update the license information in the background
	c.FireAndForget(func() {
		slog.Info("updating license information in background", "asset", assetVersion.Name, "assetID", assetVersion.AssetID)
		_, err := c.componentService.GetAndSaveLicenseInformation(nil, assetVersion, utils.Ptr(artifactName), false)
		if err != nil {
			slog.Error("could not update license information", "asset", assetVersion.Name, "assetID", assetVersion.AssetID, "err", err)
		} else {
			slog.Info("license information updated", "asset", assetVersion.Name, "assetID", assetVersion.AssetID)
		}
	})

	if assetVersion.DefaultBranch || assetVersion.Type == models.AssetVersionTag {
		c.FireAndForget(func() {
			// Export the updated graph back to CycloneDX format for the event
			exportedBOM := sbom.ToCycloneDX(normalize.BOMMetadata{
				RootName: artifactName,
			})
			if err = c.thirdPartyIntegration.HandleEvent(shared.SBOMCreatedEvent{
				AssetVersion: shared.ToAssetVersionObject(assetVersion),
				Asset:        shared.ToAssetObject(asset),
				Project:      shared.ToProjectObject(project),
				Org:          shared.ToOrgObject(org),
				Artifact: shared.ArtifactObject{
					ArtifactName: artifactName,
				},
				SBOM: exportedBOM,
			}); err != nil {
				slog.Error("could not handle SBOM updated event", "err", err)
			} else {
				slog.Info("handled SBOM updated event", "assetVersion", assetVersion.Name, "assetID", assetVersion.AssetID)
			}
		})
	}

	c.FireAndForget(func() {
		err := c.dependencyVulnService.SyncIssues(org, project, asset, assetVersion, vulns)
		if err != nil {
			slog.Error("could not create issues for vulnerabilities", "err", err)
		}
	})

	c.FireAndForget(func() {
		slog.Info("recalculating risk history for asset", "asset version", assetVersion.Name, "assetID", asset.ID)
		if err := c.statisticsService.UpdateArtifactRiskAggregation(&artifact, asset.ID, utils.OrDefault(artifact.LastHistoryUpdate, assetVersion.CreatedAt), time.Now()); err != nil {
			slog.Error("could not recalculate risk history", "err", err)
		}
	})

	type responseBody struct {
		Artifact    models.Artifact               `json:"artifact"`
		InvalidURLs []dtos.ExternalReferenceError `json:"invalidURLs"`
	}
	response := responseBody{
		Artifact:    artifact,
		InvalidURLs: invalidURLs,
	}
	return ctx.JSON(200, response)

}

// @Summary Get SBOM in JSON format
// @Tags Artifacts
// @Security CookieAuth
// @Security PATAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Param assetSlug path string true "Asset slug"
// @Param assetVersionSlug path string true "Asset version slug"
// @Param artifactName path string true "Artifact name"
// @Success 200 {object} object
// @Router /organizations/{organization}/projects/{projectSlug}/assets/{assetSlug}/refs/{assetVersionSlug}/artifacts/{artifactName}/sbom.json [get]
func (c *ArtifactController) SBOMJSON(ctx shared.Context) error {
	assetVersion := shared.GetAssetVersion(ctx)

	sbom, err := c.assetVersionService.LoadFullSBOMGraph(assetVersion)
	if err != nil {
		return err
	}

	ctx.Response().Header().Set("Content-Type", "application/json")

	encoder := cdx.NewBOMEncoder(ctx.Response().Writer, cdx.BOMFileFormatJSON).SetPretty(true).SetEscapeHTML(false)

	return encoder.Encode(sbom.ToCycloneDX(ctxToBOMMetadata(ctx)))
}

func (c *ArtifactController) SBOMXML(ctx shared.Context) error {
	assetVersion := shared.GetAssetVersion(ctx)
	sbom, err := c.assetVersionService.LoadFullSBOMGraph(assetVersion)
	if err != nil {
		return err
	}
	// scope to artifact
	artifact := shared.GetArtifact(ctx)
	sbom.ScopeToArtifact(artifact.ArtifactName)
	encoder := cdx.NewBOMEncoder(ctx.Response().Writer, cdx.BOMFileFormatXML).SetPretty(true).SetEscapeHTML(false)
	return encoder.Encode(sbom.ToCycloneDX(ctxToBOMMetadata(ctx)))
}

func (c *ArtifactController) VEXXML(ctx shared.Context) error {
	sbom, err := c.buildVeX(ctx)
	if err != nil {
		return err
	}

	encoder := cdx.NewBOMEncoder(ctx.Response().Writer, cdx.BOMFileFormatXML).SetPretty(true).SetEscapeHTML(false)

	return encoder.Encode(sbom.ToCycloneDX(ctxToBOMMetadata(ctx)))
}

// @Summary Get VEX in JSON format
// @Tags Artifacts
// @Security CookieAuth
// @Security PATAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Param assetSlug path string true "Asset slug"
// @Param assetVersionSlug path string true "Asset version slug"
// @Param artifactName path string true "Artifact name"
// @Success 200 {object} object
// @Router /organizations/{organization}/projects/{projectSlug}/assets/{assetSlug}/refs/{assetVersionSlug}/artifacts/{artifactName}/vex.json [get]
func (c *ArtifactController) VEXJSON(ctx shared.Context) error {
	sbom, err := c.buildVeX(ctx)
	if err != nil {
		return err
	}

	ctx.Response().Header().Set("Content-Type", "application/json")

	encoder := cdx.NewBOMEncoder(ctx.Response().Writer, cdx.BOMFileFormatJSON).SetPretty(true).SetEscapeHTML(false)
	return encoder.Encode(sbom.ToCycloneDX(ctxToBOMMetadata(ctx)))
}

func (c *ArtifactController) OpenVEXJSON(ctx shared.Context) error {
	vex, err := c.buildOpenVeX(ctx)
	if err != nil {
		return err
	}

	return vex.ToJSON(ctx.Response().Writer)
}

func (c *ArtifactController) buildOpenVeX(ctx shared.Context) (vex.VEX, error) {
	asset := shared.GetAsset(ctx)
	assetVersion := shared.GetAssetVersion(ctx)
	org := shared.GetOrg(ctx)
	artifact := shared.GetArtifact(ctx)

	dependencyVulns, err := c.gatherVexInformationIncludingResolvedMarking(assetVersion, &artifact.ArtifactName)
	if err != nil {
		return vex.VEX{}, err
	}

	return c.assetVersionService.BuildOpenVeX(asset, assetVersion, org.Slug, dependencyVulns), nil
}

func (c *ArtifactController) gatherVexInformationIncludingResolvedMarking(assetVersion models.AssetVersion, artifactName *string) ([]models.DependencyVuln, error) {
	// get all associated dependencyVulns
	dependencyVulns, err := c.dependencyVulnRepository.ListUnfixedByAssetAndAssetVersion(nil, assetVersion.Name, assetVersion.AssetID, artifactName)

	if err != nil {
		return nil, err
	}

	var defaultVulns []models.DependencyVuln
	if assetVersion.DefaultBranch {
		return dependencyVulns, nil
	}

	// get the dependency vulns for the default asset version to check if any are resolved already
	defaultVulns, err = c.dependencyVulnRepository.GetDependencyVulnsByDefaultAssetVersion(nil, assetVersion.AssetID, artifactName)
	if err != nil {
		return nil, err
	}

	// create a map to mark all defaultFixed vulns as fixed in the dependency vulns slice - this will lead to the vex containing a resolved key
	m := make(map[string]bool)
	for _, v := range defaultVulns {
		if v.State == dtos.VulnStateFixed {
			m[fmt.Sprintf("%s/%s", v.CVEID, v.ComponentPurl)] = true
		}
	}

	// mark all vulns as fixed if they are in the map
	for i := range dependencyVulns {
		if m[fmt.Sprintf("%s/%s", dependencyVulns[i].CVEID, dependencyVulns[i].ComponentPurl)] {
			dependencyVulns[i].State = dtos.VulnStateFixed
		}
	}
	return dependencyVulns, nil
}

func (c *ArtifactController) buildVeX(ctx shared.Context) (*normalize.SBOMGraph, error) {
	project := shared.GetProject(ctx)
	asset := shared.GetAsset(ctx)
	assetVersion := shared.GetAssetVersion(ctx)
	org := shared.GetOrg(ctx)
	artifact := shared.GetArtifact(ctx)

	frontendURL := os.Getenv("FRONTEND_URL")
	if frontendURL == "" {
		return nil, fmt.Errorf("FRONTEND_URL environment variable is not set")
	}

	dependencyVulns, err := c.gatherVexInformationIncludingResolvedMarking(assetVersion, &artifact.ArtifactName)
	if err != nil {
		return nil, err
	}

	return c.assetVersionService.BuildVeX(frontendURL, org.Name, org.Slug, project.Slug, asset, assetVersion, artifact.ArtifactName, dependencyVulns), nil
}

func (c *ArtifactController) BuildVulnerabilityReportPDF(ctx shared.Context) error {
	assetVersion := shared.GetAssetVersion(ctx)
	org := shared.GetOrg(ctx)
	project := shared.GetProject(ctx)
	asset := shared.GetAsset(ctx)
	artifact := shared.GetArtifact(ctx).ArtifactName

	// check if external entity provider
	templateName := "default"
	if asset.ExternalEntityProviderID != nil {
		templateName = strings.ToLower(*asset.ExternalEntityProviderID)
	}
	// read the template
	markdownTemplate, err := resourceFiles.ReadFile("report-templates/" + templateName + "/vulnerability-report/markdown/markdown.gotmpl")
	if err != nil {
		slog.Warn("could not read embedded resource files for vulnerability report template", "error", err)
		templateName = "default"
		markdownTemplate, err = resourceFiles.ReadFile("report-templates/" + templateName + "/vulnerability-report/markdown/markdown.gotmpl")
		if err != nil {
			return echo.NewHTTPError(500, fmt.Sprintf("could not read embedded resource files for vulnerability report template: %v", err))
		}
	}

	// parse the template
	parsedTemplate, err := template.New("markdown").Parse(string(markdownTemplate))
	if err != nil {
		return echo.NewHTTPError(500, fmt.Sprintf("could not parse template: %v", err))
	}

	result := utils.Concurrently(
		func() (any, error) {
			// get the vex from the asset version
			dependencyVulns, err := c.gatherVexInformationIncludingResolvedMarking(assetVersion, utils.EmptyThenNil(artifact))
			if err != nil {
				return nil, err
			}
			frontendURL := os.Getenv("FRONTEND_URL")
			if frontendURL == "" {
				return nil, fmt.Errorf("FRONTEND_URL is not set")
			}

			vex := c.assetVersionService.BuildVeX(frontendURL, org.Name, org.Slug, project.Slug, asset, assetVersion, artifact, dependencyVulns)

			// convert to vulnerability
			result := make([]dtos.VulnerabilityInReport, 0, len(dependencyVulns))

			// create a map of all dependency vulns by vuln ID for easy lookup
			m := make(map[string]models.DependencyVuln)
			for _, dv := range dependencyVulns {
				m[dv.CVEID] = dv
			}

			for v := range vex.Vulnerabilities() {
				dv, ok := m[v.ID]
				if !ok {
					continue
				}

				response := ""
				if v.Analysis != nil && v.Analysis.Response != nil && len(*v.Analysis.Response) > 0 {
					response = string((*v.Analysis.Response)[0])
				}
				result = append(result, dtos.VulnerabilityInReport{
					CVEID:               escapeLatex(v.ID),
					SourceName:          escapeLatex(v.Source.Name),
					SourceURL:           escapeLatex(v.Source.URL),
					AffectedComponent:   escapeLatex(dv.ComponentPurl),
					CveDescription:      escapeLatex(dv.CVE.Description),
					AnalysisState:       escapeLatex(string(v.Analysis.State)),
					AnalysisResponse:    escapeLatex(response),
					AnalysisDetail:      escapeLatex(v.Analysis.Detail),
					AnalysisFirstIssued: escapeLatex(v.Analysis.FirstIssued),
					AnalysisLastUpdated: escapeLatex(v.Analysis.LastUpdated),
					CVSS:                *(*v.Ratings)[0].Score,
					Severity:            escapeLatex(string((*v.Ratings)[0].Severity)),
					Vector:              escapeLatex((*v.Ratings)[0].Vector),
					CVSSMethod:          escapeLatex(string((*v.Ratings)[0].Method)),
					DevguardScore:       *(*v.Ratings)[1].Score,
					DevguardSeverity:    escapeLatex(string((*v.Ratings)[1].Severity)),
					DevguardVector:      escapeLatex((*v.Ratings)[1].Vector),
				})
			}

			return result, nil
		},
		func() (any, error) {
			distribution, err := c.statisticsService.GetArtifactRiskHistory(utils.EmptyThenNil(artifact), assetVersion.Name, assetVersion.AssetID, time.Now(), time.Now()) // only the last entry
			if len(distribution) == 0 {
				return models.Distribution{}, nil
			}

			return distribution[0].Distribution, err
		},
		func() (any, error) {
			return c.statisticsService.GetAverageFixingTime(utils.EmptyThenNil(artifact), assetVersion.Name, assetVersion.AssetID, "critical")
		},
		func() (any, error) {
			return c.statisticsService.GetAverageFixingTime(utils.EmptyThenNil(artifact), assetVersion.Name, assetVersion.AssetID, "high")
		},
		func() (any, error) {
			return c.statisticsService.GetAverageFixingTime(utils.EmptyThenNil(artifact), assetVersion.Name, assetVersion.AssetID, "medium")
		},
		func() (any, error) {
			return c.statisticsService.GetAverageFixingTime(utils.EmptyThenNil(artifact), assetVersion.Name, assetVersion.AssetID, "low")
		},
	)

	if result.HasErrors() {
		return echo.NewHTTPError(500, fmt.Sprintf("could not get average fixing times: %v", result.Errors()))
	}

	vulns := result.GetValue(0).([]dtos.VulnerabilityInReport)
	// group the vulns by severity
	vulnsBySeverity := make(map[string][]dtos.VulnerabilityInReport)
	for _, v := range vulns {
		vulnsBySeverity[v.Severity] = append(vulnsBySeverity[v.Severity], v)
	}

	distribution := result.GetValue(1).(models.Distribution)
	avgCritical := result.GetValue(2).(time.Duration)
	avgHigh := result.GetValue(3).(time.Duration)
	avgMedium := result.GetValue(4).(time.Duration)
	avgLow := result.GetValue(5).(time.Duration)

	markdown := bytes.Buffer{}
	err = parsedTemplate.Execute(&markdown, dtos.VulnerabilityReport{
		AppTitle:           fmt.Sprintf("%s@%s", escapeLatex(asset.Slug), escapeLatex(assetVersion.Slug)),
		AppVersion:         escapeLatex(assetVersion.Name),
		ReportCreationDate: escapeLatex(time.Now().Format("2006-01-02 15:04")),

		AmountCritical: distribution.CVEPurlCriticalCVSS,
		AmountHigh:     distribution.CVEPurlHighCVSS,
		AmountMedium:   distribution.CVEPurlMediumCVSS,
		AmountLow:      distribution.CVEPurlLowCVSS,

		AvgFixTimeCritical: fmt.Sprintf("%d Tage", int(avgCritical.Hours()/24)),
		AvgFixTimeHigh:     fmt.Sprintf("%d Tage", int(avgHigh.Hours()/24)),
		AvgFixTimeMedium:   fmt.Sprintf("%d Tage", int(avgMedium.Hours()/24)),
		AvgFixTimeLow:      fmt.Sprintf("%d Tage", int(avgLow.Hours()/24)),

		CriticalVulns: vulnsBySeverity["critical"],
		HighVulns:     vulnsBySeverity["high"],
		MediumVulns:   vulnsBySeverity["medium"],
		LowVulns:      vulnsBySeverity["low"],
	})
	if err != nil {
		return echo.NewHTTPError(500, fmt.Sprintf("could not execute template: %v", err))
	}

	// create the metadata for the pdf and writing it into a buffer
	metaDataFile := bytes.Buffer{}
	metaData := services.CreateYAMLMetadata(shared.GetOrg(ctx).Name, shared.GetAsset(ctx).Name, shared.GetAssetVersion(ctx).Name)
	parsedYAML, err := yaml.Marshal(metaData)
	if err != nil {
		return err
	}
	_, err = metaDataFile.Write(parsedYAML)
	if err != nil {
		return err
	}

	//build the multipart form data for the http request
	var multipartBuffer bytes.Buffer
	multipartWriter := multipart.NewWriter(&multipartBuffer)
	zipFileWriter, err := multipartWriter.CreateFormFile("file", "archive.zip")
	if err != nil {
		return err
	}
	//Create zip of all the necessary files
	err = buildVulnReportZipInMemory(zipFileWriter, templateName, &metaDataFile, &markdown)
	if err != nil {
		return err
	}

	err = multipartWriter.Close()
	if err != nil {
		return err
	}

	//build the rest of the http request
	pdfAPIURL := os.Getenv("PDF_GENERATION_API")
	if pdfAPIURL == "" {
		return fmt.Errorf("missing env variable 'PDF_GENERATION_API'")
	}
	req, err := http.NewRequest(http.MethodPost, pdfAPIURL, &multipartBuffer)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", multipartWriter.FormDataContentType())

	client := &http.Client{}
	client.Timeout = 10 * time.Minute

	//process http response
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		// return the rendered markdown as well for easier debugging
		ctx.Response().Header().Set(echo.HeaderContentType, "text/markdown ; charset=utf-8")
		ctx.Response().WriteHeader(http.StatusInternalServerError)
		_, _ = io.Copy(ctx.Response().Writer, &markdown)
		return fmt.Errorf("http request to %s was unsuccessful (Code %d)", req.URL, resp.StatusCode)
	}

	// construct the http response header
	// ctx.Response().Header().Set(echo.HeaderContentDisposition, `attachment; filename="sbom.pdf"`)
	ctx.Response().Header().Set(echo.HeaderContentType, "application/pdf")
	ctx.Response().WriteHeader(http.StatusOK)

	_, err = io.Copy(ctx.Response().Writer, resp.Body)

	return err
}

func (c *ArtifactController) BuildPDFFromSBOM(ctx shared.Context) error {
	assetVersion := shared.GetAssetVersion(ctx)
	sbom, err := c.assetVersionService.LoadFullSBOMGraph(assetVersion)
	if err != nil {
		return err
	}

	asset := shared.GetAsset(ctx)

	//write the components as markdown table to the buffer
	markdownFile := bytes.Buffer{}
	err = services.MarkdownTableFromSBOM(&markdownFile, sbom.ToCycloneDX(ctxToBOMMetadata(ctx)))
	if err != nil {
		return err
	}

	// create the metadata for the pdf and writing it into a buffer
	metaDataFile := bytes.Buffer{}
	metaData := services.CreateYAMLMetadata(shared.GetOrg(ctx).Name, shared.GetAsset(ctx).Name, shared.GetAssetVersion(ctx).Name)
	parsedYAML, err := yaml.Marshal(metaData)
	if err != nil {
		return err
	}
	_, err = metaDataFile.Write(parsedYAML)
	if err != nil {
		return err
	}
	// check if external entity provider
	templateName := "default"
	if asset.ExternalEntityProviderID != nil {
		templateName = strings.ToLower(*asset.ExternalEntityProviderID)
	}

	//build the multipart form data for the http request
	var multipartBuffer bytes.Buffer
	multipartWriter := multipart.NewWriter(&multipartBuffer)
	zipFileWriter, err := multipartWriter.CreateFormFile("file", "archive.zip")
	if err != nil {
		return err
	}
	//Create zip of all the necessary files
	err = buildSbomZipInMemory(zipFileWriter, templateName, &metaDataFile, &markdownFile)
	if err != nil {
		return err
	}

	err = multipartWriter.Close()
	if err != nil {
		return err
	}

	//build the rest of the http request
	pdfAPIURL := os.Getenv("PDF_GENERATION_API")
	if pdfAPIURL == "" {
		return fmt.Errorf("missing env variable 'PDF_GENERATION_API'")
	}
	req, err := http.NewRequest(http.MethodPost, pdfAPIURL, &multipartBuffer)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", multipartWriter.FormDataContentType())

	client := &http.Client{}
	client.Timeout = 10 * time.Minute

	//process http response
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("http request to %s was unsuccessful (Code %d)", req.URL, resp.StatusCode)
	}

	// construct the http response header
	ctx.Response().Header().Set(echo.HeaderContentDisposition, `attachment; filename="sbom.pdf"`)
	ctx.Response().Header().Set(echo.HeaderContentType, "application/pdf")
	ctx.Response().WriteHeader(http.StatusOK)

	_, err = io.Copy(ctx.Response().Writer, resp.Body)

	return err
}

//go:embed report-templates/*
var resourceFiles embed.FS

func buildSbomZipInMemory(writer io.Writer, templateName string, metadata, markdown *bytes.Buffer) error {

	if _, err := resourceFiles.ReadDir(fmt.Sprintf("report-templates/%s/sbom", templateName)); err != nil {
		slog.Warn("could not read embedded resource files for sbom report template", "error", err)
		templateName = "default"
	}

	path := fmt.Sprintf("report-templates/%s/sbom/", templateName)
	zipWriter := zip.NewWriter(writer)
	defer zipWriter.Close()

	// set of all the static files which are embedded
	fileNames := []string{
		path + "template/template.tex", path + "template/assets/background.png", path + "template/assets/qr.png",
		path + "template/assets/font/Inter-Bold.ttf", path + "template/assets/font/Inter-BoldItalic.ttf", path + "template/assets/font/Inter-Italic-VariableFont_opsz,wght.ttf", path + "template/assets/font/Inter-Italic.ttf", path + "template/assets/font/Inter-Regular.ttf", path + "template/assets/font/Inter-VariableFont_opsz,wght.ttf",
	}

	// manually add the two generated files to the zip archive
	zipFileDescriptor, err := zipWriter.Create("template/metadata.yaml")
	if err != nil {
		return err
	}
	_, err = zipFileDescriptor.Write(metadata.Bytes())
	if err != nil {
		zipWriter.Close()
		return err
	}

	zipFileDescriptor, err = zipWriter.Create("markdown/sbom.md")
	if err != nil {
		zipWriter.Close()
		return err
	}
	_, err = zipFileDescriptor.Write(markdown.Bytes())
	if err != nil {
		zipWriter.Close()
		return err
	}

	// then loop over every static file and write it at the respective relative position in the directory
	for _, filePath := range fileNames {
		fileContent, err := resourceFiles.ReadFile(filePath)
		if err != nil {
			zipWriter.Close()
			return err
		}
		localFilePath, _ := strings.CutPrefix(filePath, path)
		zipFileDescriptor, err := zipWriter.Create(localFilePath)
		if err != nil {
			zipWriter.Close()
			return err
		}
		_, err = zipFileDescriptor.Write(fileContent)
		if err != nil {
			zipWriter.Close()
			return err
		}
	}

	//finalize the zip-archive and return it
	zipWriter.Close()
	return nil
}

func buildVulnReportZipInMemory(writer io.Writer, templateName string, metadata, markdown *bytes.Buffer) error {

	if _, err := resourceFiles.ReadDir(fmt.Sprintf("report-templates/%s/vulnerability-report", templateName)); err != nil {
		slog.Warn("could not read embedded resource files for vulnerability report template", "error", err)
		templateName = "default"
	}

	path := fmt.Sprintf("report-templates/%s/vulnerability-report/", templateName)
	zipWriter := zip.NewWriter(writer)
	defer zipWriter.Close()

	// set of all the static files which are embedded
	fileNames := []string{
		path + "template/template.tex", path + "template/assets/background.png", path + "template/assets/qr.png",
		path + "template/assets/font/Inter-Bold.ttf", path + "template/assets/font/Inter-BoldItalic.ttf", path + "template/assets/font/Inter-Italic-VariableFont_opsz,wght.ttf", path + "template/assets/font/Inter-Italic.ttf", path + "template/assets/font/Inter-Regular.ttf", path + "template/assets/font/Inter-VariableFont_opsz,wght.ttf",

		path + "template/assets/by-cvss.png",
	}

	// manually add the two generated files to the zip archive
	zipFileDescriptor, err := zipWriter.Create("template/metadata.yaml")
	if err != nil {
		return err
	}
	_, err = zipFileDescriptor.Write(metadata.Bytes())
	if err != nil {
		zipWriter.Close()
		return err
	}

	zipFileDescriptor, err = zipWriter.Create("markdown/sbom.md")
	if err != nil {
		zipWriter.Close()
		return err
	}
	_, err = zipFileDescriptor.Write(markdown.Bytes())
	if err != nil {
		zipWriter.Close()
		return err
	}

	// then loop over every static file and write it at the respective relative position in the directory
	for _, filePath := range fileNames {
		fileContent, err := resourceFiles.ReadFile(filePath)
		if err != nil {
			zipWriter.Close()
			return err
		}
		localFilePath, _ := strings.CutPrefix(filePath, path)
		zipFileDescriptor, err := zipWriter.Create(localFilePath)
		if err != nil {
			zipWriter.Close()
			return err
		}
		_, err = zipFileDescriptor.Write(fileContent)
		if err != nil {
			zipWriter.Close()
			return err
		}
	}

	//finalize the zip-archive and return it
	zipWriter.Close()
	return nil
}
