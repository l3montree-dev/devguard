// Copyright (C) 2023 Tim Bastin, l3montree GmbH
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
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package controllers

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/normalize"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/transformer"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/labstack/echo/v4"
	"github.com/ory/client-go"
)

type ProjectController struct {
	projectRepository      shared.ProjectRepository
	assetRepository        shared.AssetRepository
	assetVersionRepository shared.AssetVersionRepository
	artifactRepository     shared.ArtifactRepository
	assetVersionService    shared.AssetVersionService
	assetService           shared.AssetService
	releaseService         shared.ReleaseService
	projectService         shared.ProjectService
	webhookRepository      shared.WebhookIntegrationRepository
	scanService            shared.ScanService
}

func NewProjectController(repository shared.ProjectRepository, assetRepository shared.AssetRepository, assetVersionRepository shared.AssetVersionRepository, artifactRepository shared.ArtifactRepository, assetVersionService shared.AssetVersionService, assetService shared.AssetService, releaseService shared.ReleaseService, projectService shared.ProjectService, webhookRepository shared.WebhookIntegrationRepository, scanService shared.ScanService) *ProjectController {
	return &ProjectController{
		projectRepository:      repository,
		assetRepository:        assetRepository,
		assetVersionRepository: assetVersionRepository,
		artifactRepository:     artifactRepository,
		assetVersionService:    assetVersionService,
		assetService:           assetService,
		releaseService:         releaseService,
		projectService:         projectService,
		webhookRepository:      webhookRepository,
		scanService:            scanService,
	}
}

// @Summary Create project
// @Tags Projects
// @Security CookieAuth
// @Security PATAuth
// @Security BearerAuth
// @Param organization path string true "Organization slug"
// @Param body body dtos.ProjectCreateRequest true "Request body"
// @Success 200 {object} models.Project
// @Router /organizations/{organization}/projects [post]
func (projectController *ProjectController) Create(ctx shared.Context) error {
	var req dtos.ProjectCreateRequest
	if err := ctx.Bind(&req); err != nil {
		return echo.NewHTTPError(400, "unable to process request").WithInternal(err)
	}

	if err := shared.V.Struct(req); err != nil {
		return echo.NewHTTPError(400, fmt.Sprintf("could not validate request: %s", err.Error()))
	}

	newProject := transformer.ProjectCreateRequestToModel(req)

	// add the organization id
	newProject.OrganizationID = shared.GetOrg(ctx).GetID()

	err := projectController.projectService.CreateProject(ctx, &newProject)
	if err != nil {
		return echo.NewHTTPError(409, "could not create project").WithInternal(err)
	}

	return ctx.JSON(200, newProject)
}

func FetchMembersOfProject(ctx shared.Context) ([]dtos.UserDTO, error) {
	project := shared.GetProject(ctx)
	// get rbac
	rbac := shared.GetRBAC(ctx)

	members, err := rbac.GetAllMembersOfProject(project.ID.String())
	if err != nil {
		return nil, echo.NewHTTPError(500, "could not get members of project").WithInternal(err)
	}
	if len(members) == 0 {
		return []dtos.UserDTO{}, nil
	}
	// get the auth admin client from the context
	authAdminClient := shared.GetAuthAdminClient(ctx)
	// fetch the users from the auth service
	m, err := authAdminClient.ListUser(client.IdentityAPIListIdentitiesRequest{}.Ids(members))

	if err != nil {
		return nil, echo.NewHTTPError(500, "could not get members").WithInternal(err)
	}

	users := utils.Map(m, func(i client.Identity) dtos.UserDTO {
		name := shared.IdentityName(i.Traits)
		role, err := rbac.GetProjectRole(i.Id, project.ID.String())
		if err != nil {
			return dtos.UserDTO{
				ID:   i.Id,
				Name: name,
			}
		}
		return dtos.UserDTO{
			ID:   i.Id,
			Name: name,
			Role: string(role),
		}
	})

	return users, nil
}

// @Summary List project members
// @Tags Projects
// @Security CookieAuth
// @Security PATAuth
// @Security BearerAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Success 200 {array} dtos.UserDTO
// @Router /organizations/{organization}/projects/{projectSlug}/members [get]
func (projectController *ProjectController) Members(c shared.Context) error {
	members, err := FetchMembersOfProject(c)
	if err != nil {
		return err
	}

	return c.JSON(200, members)
}

// @Summary Invite members to project
// @Tags Projects
// @Security CookieAuth
// @Security PATAuth
// @Security BearerAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Param body body dtos.ProjectInviteRequest true "Request body"
// @Success 200
// @Router /organizations/{organization}/projects/{projectSlug}/members [post]
func (projectController *ProjectController) InviteMembers(c shared.Context) error {
	project := shared.GetProject(c)

	// get rbac
	rbac := shared.GetRBAC(c)

	var req dtos.ProjectInviteRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(400, "unable to process request").WithInternal(err)
	}

	if err := shared.V.Struct(req); err != nil {
		return echo.NewHTTPError(400, fmt.Sprintf("could not validate request: %s", err.Error()))
	}

	members, err := rbac.GetAllMembersOfOrganization()
	if err != nil {
		return echo.NewHTTPError(500, "could not get members of organization").WithInternal(err)
	}

	for _, newMemberID := range req.Ids {
		if !utils.Contains(members, newMemberID) {
			return echo.NewHTTPError(400, "user is not a member of the organization")
		}

		if err := rbac.GrantRoleInProject(c.Request().Context(), newMemberID, shared.RoleMember, project.ID.String()); err != nil {
			return err
		}
	}
	return c.NoContent(200)
}

// @Summary Remove member from project
// @Tags Projects
// @Security CookieAuth
// @Security PATAuth
// @Security BearerAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Param userID path string true "User ID"
// @Success 200
// @Router /organizations/{organization}/projects/{projectSlug}/members/{userID}/ [delete]
func (projectController *ProjectController) RemoveMember(c shared.Context) error {
	reqCtx := c.Request().Context()
	project := shared.GetProject(c)

	// get rbac
	rbac := shared.GetRBAC(c)

	userID := c.Param("userID")
	if userID == "" {
		return echo.NewHTTPError(400, "userID is required")
	}

	// revoke admin and member role
	rbac.RevokeRoleInProject(reqCtx, userID, shared.RoleAdmin, project.ID.String())  // nolint:errcheck // we don't care if the user is not an admin
	rbac.RevokeRoleInProject(reqCtx, userID, shared.RoleMember, project.ID.String()) // nolint:errcheck // we don't care if the user is not a member

	return c.NoContent(200)
}

// @Summary Change member role in project
// @Tags Projects
// @Security CookieAuth
// @Security PATAuth
// @Security BearerAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Param userID path string true "User ID"
// @Param body body dtos.ProjectChangeRoleRequest true "Request body"
// @Success 200
// @Router /organizations/{organization}/projects/{projectSlug}/members/{userID}/ [put]
func (projectController *ProjectController) ChangeRole(c shared.Context) error {
	reqCtx := c.Request().Context()
	project := shared.GetProject(c)

	// get rbac
	rbac := shared.GetRBAC(c)

	var req dtos.ProjectChangeRoleRequest

	userID := c.Param("userID")
	if userID == "" {
		return echo.NewHTTPError(400, "userID is required")
	}

	if userID == shared.GetSession(c).GetUserID() {
		return echo.NewHTTPError(400, "cannot change your own role")
	}

	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(400, "unable to process request").WithInternal(err)
	}

	if err := shared.V.Struct(req); err != nil {
		return echo.NewHTTPError(400, fmt.Sprintf("could not validate request: %s", err.Error()))
	}

	members, err := rbac.GetAllMembersOfOrganization()
	if err != nil {
		return echo.NewHTTPError(500, "could not get members of organization").WithInternal(err)
	}

	if !utils.Contains(members, userID) {
		return echo.NewHTTPError(400, "user is not a member of the organization")
	}

	rbac.RevokeRoleInProject(reqCtx, userID, shared.RoleAdmin, project.ID.String()) // nolint:errcheck // we don't care if the user is not an admin

	rbac.RevokeRoleInProject(reqCtx, userID, shared.RoleMember, project.ID.String()) // nolint:errcheck // we don't care if the user is not a member

	if err := rbac.GrantRoleInProject(reqCtx, userID, shared.Role(req.Role), project.ID.String()); err != nil {
		return err
	}

	return c.NoContent(200)
}

// @Summary Delete project
// @Tags Projects
// @Security CookieAuth
// @Security PATAuth
// @Security BearerAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Success 200
// @Router /organizations/{organization}/projects/{projectSlug} [delete]
func (projectController *ProjectController) Delete(c shared.Context) error {
	project := shared.GetProject(c)
	ctx := c.Request().Context()

	// take care of all rbac rules associated with the project and delete those as well
	childProjects, err := projectController.projectRepository.RecursivelyGetChildProjects(ctx, nil, project.ID)
	if err != nil {
		return err
	}
	// map projects to their ids
	projectIDs := append([]uuid.UUID{project.ID}, utils.Map(childProjects, func(p models.Project) uuid.UUID {
		return p.ID
	})...)

	// then collect all assets associated with the affected projects
	assets, err := projectController.assetRepository.GetByProjectIDs(ctx, nil, projectIDs)
	if err != nil {
		return err
	}

	err = projectController.projectRepository.Delete(ctx, nil, project.ID)
	if err != nil {
		return err
	}

	// lastly iterate over all projects and assets and remove all roles associated with them
	rbac := shared.GetRBAC(c)
	for _, projectID := range projectIDs {
		if err := rbac.RevokeAllRolesInProject(ctx, projectID.String()); err != nil {
			return err
		}
	}
	for _, asset := range assets {
		if err := rbac.RevokeAllRolesInAsset(ctx, asset.ID.String()); err != nil {
			return err
		}
	}

	return c.NoContent(200)
}

// @Summary Get project details
// @Tags Projects
// @Security CookieAuth
// @Security PATAuth
// @Security BearerAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Success 200 {object} dtos.ProjectDetailsDTO
// @Router /organizations/{organization}/projects/{projectSlug} [get]
func (projectController *ProjectController) Read(c shared.Context) error {
	// just get the project from the context
	project := shared.GetProject(c)
	rbac := shared.GetRBAC(c)
	allowedAssetIDs, err := rbac.GetAllAssetsForUser(shared.GetSession(c).GetUserID())
	if err != nil {
		return err
	}
	// lets fetch the assets related to this project
	assets, err := projectController.assetRepository.GetAllowedAssetsByProjectID(c.Request().Context(), nil, allowedAssetIDs, project.ID)
	if err != nil {
		return err
	}

	project.Assets = assets

	// lets fetch the members of the project
	members, err := FetchMembersOfProject(c)
	if err != nil {
		return err
	}

	//get the webhooks
	webhooks, err := projectController.getWebhooks(c)
	if err != nil {
		return echo.NewHTTPError(500, "could not fetch webhooks").WithInternal(err)
	}

	resp := dtos.ProjectDetailsDTO{
		ProjectDTO: transformer.ProjectModelToDTO(project),
		Members:    members,
		Webhooks:   webhooks,
	}

	return c.JSON(200, resp)
}

func (projectController *ProjectController) getWebhooks(c shared.Context) ([]dtos.WebhookIntegrationDTO, error) {

	orgID := shared.GetOrg(c).GetID()
	projectID := shared.GetProject(c).GetID()

	webhooks, err := projectController.webhookRepository.GetProjectWebhooks(c.Request().Context(), nil, orgID, projectID)
	if err != nil {
		return nil, fmt.Errorf("could not fetch webhooks: %w", err)
	}

	return utils.Map(webhooks, func(w models.WebhookIntegration) dtos.WebhookIntegrationDTO {
		return dtos.WebhookIntegrationDTO{
			ID:          w.ID.String(),
			Name:        *w.Name,
			Description: *w.Description,
			URL:         w.URL,
			SbomEnabled: w.SbomEnabled,
			VulnEnabled: w.VulnEnabled,
		}
	}), nil
}

// @Summary List sub-projects and assets
// @Tags Projects
// @Security CookieAuth
// @Security PATAuth
// @Security BearerAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Param search query string false "Search query for filtering sub-projects and assets"
// @Success 200 {array} dtos.ProjectAssetDTO
// @Router /organizations/{organization}/projects/{projectSlug}/resources [get]

func (projectController *ProjectController) ListSubProjectsAndAssets(c shared.Context) error {

	results, err := projectController.projectService.ListAllowedSubProjectsAndAssetsPaged(c)
	if err != nil {
		return err
	}

	return c.JSON(200, results)
}

// @Summary List projects
// @Tags Projects
// @Security CookieAuth
// @Security PATAuth
// @Security BearerAuth
// @Param organization path string true "Organization slug"
// @Success 200 {array} models.Project
// @Router /organizations/{organization}/projects [get]
func (projectController *ProjectController) List(c shared.Context) error {
	// get all projects the user has at least read access to - might be public projects as well
	projects, err := projectController.projectService.ListAllowedProjectsPaged(c)

	if err != nil {
		return err
	}

	return c.JSON(200, projects)
}

// @Summary Search projects with sub-projects and assets
// @Tags Projects
// @Security CookieAuth
// @Security PATAuth
// @Security BearerAuth
// @Param organization path string true "Organization slug"
// @Param search query string false "Search query"
// @Success 200 {array} dtos.ProjectDTO
// @Router /organizations/{organization}/projects/search/ [get]
func (projectController *ProjectController) SearchProjectsWithSubProjectsAndAssets(c shared.Context) error {

	results, err := projectController.projectService.SearchProjectsWithSubProjectsAndAssetsPaged(c)
	if err != nil {
		return err
	}

	return c.JSON(200, results)
}

// @Summary Update project
// @Tags Projects
// @Security CookieAuth
// @Security PATAuth
// @Security BearerAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Param body body dtos.ProjectPatchRequest true "Request body"
// @Success 200 {object} dtos.ProjectDetailsDTO
// @Router /organizations/{organization}/projects/{projectSlug} [patch]
func (projectController *ProjectController) Update(c shared.Context) error {
	reqCtx := c.Request().Context()
	req := c.Request().Body
	defer req.Close()
	var patchRequest dtos.ProjectPatchRequest
	err := json.NewDecoder(req).Decode(&patchRequest)
	if err != nil {
		return fmt.Errorf("could not decode request: %w", err)
	}

	project := shared.GetProject(c)

	updated := transformer.ApplyProjectPatchRequestToModel(patchRequest, &project)

	if project.Name == "" || project.Slug == "" {
		return echo.NewHTTPError(409, "projects with an empty name or an empty slug are not allowed").WithInternal(fmt.Errorf("projects with an empty name or an empty slug are not allowed"))
	}

	if updated {
		err = projectController.projectRepository.Update(reqCtx, nil, &project)
		if err != nil {
			return fmt.Errorf("could not update project: %w", err)
		}
	}
	// get rbac
	rbac := shared.GetRBAC(c)
	allowedAssetIDs, err := rbac.GetAllAssetsForUser(shared.GetSession(c).GetUserID())
	if err != nil {
		return err
	}

	// lets fetch the assets related to this project
	assets, err := projectController.assetRepository.GetAllowedAssetsByProjectID(reqCtx, nil, allowedAssetIDs, project.ID)
	if err != nil {
		return err
	}

	// lets fetch the members of the project
	members, err := FetchMembersOfProject(c)
	if err != nil {
		return err
	}

	project.Assets = assets

	resp := dtos.ProjectDetailsDTO{
		ProjectDTO: transformer.ProjectModelToDTO(project),
		Members:    members,
	}
	return c.JSON(200, resp)
}

// @Summary Get project config file
// @Tags Projects
// @Security CookieAuth
// @Security PATAuth
// @Security BearerAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Param config-file path string true "Config file ID"
// @Produce text/plain
// @Success 200 {string} string "Config file content"
// @Router /organizations/{organization}/projects/{projectSlug}/config-files/{config-file}/ [get]
func (projectController *ProjectController) GetConfigFile(ctx shared.Context) error {
	organization := shared.GetOrg(ctx)
	project := shared.GetProject(ctx)
	configID := ctx.Param("config-file")

	configContent, ok := project.ConfigFiles[configID]
	if !ok { //if we have no config files in this project we want to look in the corresponding organization
		configContent, ok = organization.ConfigFiles[configID]
		if !ok {
			return ctx.NoContent(404)
		}
		return ctx.String(200, configContent.(string))
	}
	return ctx.String(200, configContent.(string))
}

// @Summary Update project config file
// @Tags Projects
// @Security CookieAuth
// @Security PATAuth
// @Security BearerAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Param config-file path string true "Config file ID"
// @Param body body string true "Config file content"
// @Produce text/plain
// @Success 200 {string} string "Updated config file content"
// @Router /organizations/{organization}/projects/{projectSlug}/config-files/{config-file}/ [put]
func (projectController *ProjectController) UpdateConfigFile(ctx shared.Context) error {
	project := shared.GetProject(ctx)
	configID := ctx.Param("config-file")

	if configID == "" {
		return echo.NewHTTPError(400, "config file id is required")
	}

	body, err := io.ReadAll(ctx.Request().Body)
	if err != nil {
		return echo.NewHTTPError(400, "could not read request body").WithInternal(err)
	}

	configContent := string(body)

	if project.ConfigFiles == nil {
		project.ConfigFiles = make(map[string]any)
	}

	if configContent == "" {
		// if the content is empty, we want to delete the config file
		delete(project.ConfigFiles, configID)
	} else {
		project.ConfigFiles[configID] = configContent
	}
	err = projectController.projectRepository.Update(ctx.Request().Context(), nil, &project)
	if err != nil {
		return echo.NewHTTPError(500, "could not update config file").WithInternal(err)
	}
	return ctx.String(200, configContent)
}

// @Summary Sync or delete an externally managed project/asset tree
// @Description Called by external inventory providers (e.g. k8s-devguard-image-inventory) to upsert or delete a dynamically managed project hierarchy. On verb=update, creates or updates the project, sub-project, asset, asset version and artifact, then processes the supplied CycloneDX SBOM and triggers a vulnerability scan. On verb=delete, removes the artifact/asset-version/asset/project entries cascading upward as long as no other data references them.
// @Tags Projects
// @Security CookieAuth
// @Security PATAuth
// @Security BearerAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Param providerID path string true "External provider ID"
// @Param body body dtos.ExternalSubprojectRequestDTO true "Request body"
// @Success 200
// @Router /organizations/{organization}/projects/{projectSlug}/external/{providerID} [post]
func (projectController *ProjectController) HandleExternalSubprojectRequest(ctx shared.Context) error {

	body, err := io.ReadAll(ctx.Request().Body)
	if err != nil {
		return echo.NewHTTPError(400, fmt.Sprintf("could not read request body: %s", err.Error())).WithInternal(err)
	}

	var probe dtos.ExternalSubprojectRequestDTO
	if err := json.Unmarshal(body, &probe); err != nil {
		return echo.NewHTTPError(400, fmt.Sprintf("could not parse request body: %s", err.Error())).WithInternal(err)
	}

	if err := shared.V.Struct(probe); err != nil {
		return echo.NewHTTPError(400, fmt.Sprintf("could not validate request: %s", err.Error()))
	}

	providerID := shared.GetProviderID(ctx)
	organization := shared.GetOrg(ctx)
	parentProject := shared.GetProject(ctx)
	userID := shared.GetSession(ctx).GetUserID()

	if probe.Verb == "delete" {
		proExternalEntityID := probe.ProjectExternalEntityID
		if probe.SubProjectExternalEntityID != "" {
			proExternalEntityID = probe.SubProjectExternalEntityID
		}
		if err := projectController.projectRepository.CleanupExternalProjectAssetVersion(ctx.Request().Context(), nil, organization.GetID(), providerID, proExternalEntityID, probe.AssetExternalEntityID, probe.AssetVersionName, probe.Artifact); err != nil {
			return echo.NewHTTPError(500, fmt.Sprintf("could not delete project: %s", err.Error())).WithInternal(err)
		}

		return ctx.JSON(200, map[string]string{"message": "project and asset deleted successfully"})
	}

	bom := new(cdx.BOM)

	if probe.Sbom == nil {
		return echo.NewHTTPError(400, "sbom is required")
	}
	if err := json.Unmarshal(probe.Sbom, bom); err != nil {
		return echo.NewHTTPError(400, fmt.Sprintf("could not parse CycloneDX BOM: %s", err.Error())).WithInternal(err)
	}

	project, err := projectController.projectService.FindOrCreateProject(ctx, providerID, organization.GetID(), probe.ProjectName, probe.ProjectExternalEntityID, parentProject.ID, probe.ProjectDescription)
	if err != nil {
		return echo.NewHTTPError(500, fmt.Sprintf("could not create project: %s", err.Error())).WithInternal(err)
	}

	pID := project.ID

	if probe.SubProjectExternalEntityID != "" {
		subProject, err := projectController.projectService.FindOrCreateProject(ctx, providerID, organization.GetID(), probe.SubProjectName, probe.SubProjectExternalEntityID, project.ID, probe.SubProjectDescription)
		if err != nil {
			return echo.NewHTTPError(500, fmt.Sprintf("could not create sub-project: %s", err.Error())).WithInternal(err)
		}
		pID = subProject.ID
	}

	rbac := shared.GetRBAC(ctx)
	asset, err := projectController.assetService.FindOrCreateAsset(ctx.Request().Context(), rbac, providerID, organization.GetID(), pID, probe.AssetName, probe.AssetExternalEntityID, userID, probe.AssetDescription)
	if err != nil {
		return echo.NewHTTPError(500, fmt.Sprintf("could not create asset: %s", err.Error())).WithInternal(err)
	}

	assetVersion, err := projectController.assetVersionRepository.FindOrCreate(ctx.Request().Context(), nil, probe.AssetVersionName, asset.ID, false, nil)
	if err != nil {
		return echo.NewHTTPError(500, fmt.Sprintf("could not create asset version: %s", err.Error())).WithInternal(err)
	}

	artifact := models.Artifact{
		ArtifactName:     probe.Artifact,
		AssetVersionName: assetVersion.Name,
		AssetID:          asset.ID,
	}
	if err := projectController.artifactRepository.Save(ctx.Request().Context(), nil, &artifact); err != nil {
		slog.Error("trivy operator: could not save artifact", "err", err)
		return ctx.JSON(500, map[string]string{"error": "could not save artifact"})
	}

	release, err := projectController.releaseService.FindOrCreate(ctx.Request().Context(), parentProject.ID, providerID)
	if err != nil {
		return echo.NewHTTPError(500, fmt.Sprintf("could not create release: %s", err.Error())).WithInternal(err)
	}

	//add or update release item
	releaseItem := models.ReleaseItem{
		ReleaseID:        release.ID,
		ArtifactName:     &artifact.ArtifactName,
		AssetID:          &asset.ID,
		AssetVersionName: &assetVersion.Name,
	}

	err = projectController.releaseService.AddItem(ctx.Request().Context(), &releaseItem)
	if err != nil {
		slog.Error("could not add release item", "err", err)
		return ctx.JSON(500, map[string]string{"error": "could not add release item"})
	}

	normalized, err := normalize.SBOMGraphFromCycloneDX(bom, probe.Artifact, "operator", asset.KeepOriginalSbomRootComponent)
	if err != nil {
		slog.Error("trivy operator: failed to normalize BOM", "err", err)
		return ctx.JSON(400, map[string]string{"error": "could not normalize SBOM"})
	}

	wholeSBOM, err := projectController.assetVersionService.UpdateSBOM(ctx.Request().Context(), nil, organization, *project, *asset, assetVersion, probe.Artifact, normalized)
	if err != nil {
		slog.Error("trivy operator: could not update SBOM", "err", err)
		return ctx.JSON(500, map[string]string{"error": "could not update SBOM"})
	}

	tx := projectController.artifactRepository.GetDB(ctx.Request().Context(), nil).Begin()
	defer tx.Rollback()

	userAgent := ctx.Request().UserAgent()
	_, _, _, err = projectController.scanService.ScanNormalizedSBOM(ctx.Request().Context(), tx, organization, *project, *asset, assetVersion, artifact, wholeSBOM, userID, &userAgent)
	if err != nil {
		slog.Error("trivy operator: scan failed", "err", err)
		return ctx.JSON(500, map[string]string{"error": "scan failed"})
	}

	tx.Commit()
	return ctx.JSON(200, map[string]string{"message": "project and asset created, SBOM processed and scan started successfully"})
}

// @Summary List externally managed project/asset tree
// @Description Returns the full tree of projects, sub-projects, assets, asset versions and artifacts that were dynamically created by an external inventory provider (e.g. k8s-devguard-image-inventory) for the given providerID.
// @Tags Projects
// @Security CookieAuth
// @Security PATAuth
// @Security BearerAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Param providerID path string true "External provider ID"
// @Success 200 {array} dtos.ProjectExternalEntityTree
// @Router /organizations/{organization}/projects/{projectSlug}/external/{providerID} [get]
func (projectController *ProjectController) ListExternalSubprojects(ctx shared.Context) error {
	reqCtx := ctx.Request().Context()
	parentProject := shared.GetProject(ctx)
	providerID := shared.GetProviderID(ctx)

	// Query 1: direct child projects filtered by providerID
	projects, err := projectController.projectRepository.GetDirectChildProjectsWithProviderID(reqCtx, nil, parentProject.ID, providerID)
	if err != nil {
		return echo.NewHTTPError(500, "could not list projects").WithInternal(err)
	}
	if len(projects) == 0 {
		return ctx.JSON(200, []dtos.ProjectExternalEntityTree{})
	}

	projectIDs := make([]uuid.UUID, len(projects))
	for i, p := range projects {
		projectIDs[i] = p.ID
	}

	// Query 2: all sub-projects for all parent projects in one shot
	subProjects, err := projectController.projectRepository.GetChildProjectsForParents(reqCtx, nil, projectIDs, providerID)
	if err != nil {
		return echo.NewHTTPError(500, "could not list sub-projects").WithInternal(err)
	}

	subProjectIDs := make([]uuid.UUID, len(subProjects))
	for i, sp := range subProjects {
		subProjectIDs[i] = sp.ID
	}

	// Query 3: all assets for projects + sub-projects, filtered by providerID
	allProjectIDs := append(projectIDs, subProjectIDs...)
	allAssets, err := projectController.assetRepository.GetByProjectIDsWithProviderID(reqCtx, nil, allProjectIDs, providerID)
	if err != nil {
		return echo.NewHTTPError(500, "could not list assets").WithInternal(err)
	}

	allAssetIDs := make([]uuid.UUID, len(allAssets))
	for i, a := range allAssets {
		allAssetIDs[i] = a.ID
	}

	// Query 4: all asset versions for all assets
	allAssetVersions, err := projectController.assetVersionRepository.GetAssetVersionsByAssetIDs(reqCtx, nil, allAssetIDs)
	if err != nil {
		return echo.NewHTTPError(500, "could not list asset versions").WithInternal(err)
	}

	// Query 5: all artifacts for all assets
	allArtifacts, err := projectController.artifactRepository.GetByAssetIDs(reqCtx, nil, allAssetIDs)
	if err != nil {
		return echo.NewHTTPError(500, "could not list artifacts").WithInternal(err)
	}

	return ctx.JSON(200, transformer.BuildExternalProjectTree(projects, subProjects, allAssets, allAssetVersions, allArtifacts))
}
