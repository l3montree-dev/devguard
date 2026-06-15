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
	projectService         shared.ProjectService
	webhookRepository      shared.WebhookIntegrationRepository
	scanService            shared.ScanService
}

func NewProjectController(repository shared.ProjectRepository, assetRepository shared.AssetRepository, assetVersionRepository shared.AssetVersionRepository, artifactRepository shared.ArtifactRepository, assetVersionService shared.AssetVersionService, assetService shared.AssetService, projectService shared.ProjectService, webhookRepository shared.WebhookIntegrationRepository, scanService shared.ScanService) *ProjectController {
	return &ProjectController{
		projectRepository:      repository,
		assetRepository:        assetRepository,
		assetVersionRepository: assetVersionRepository,
		artifactRepository:     artifactRepository,
		assetVersionService:    assetVersionService,
		assetService:           assetService,
		projectService:         projectService,
		webhookRepository:      webhookRepository,
		scanService:            scanService,
	}
}

// @Summary Create project
// @Tags Projects
// @Security CookieAuth
// @Security PATAuth
// @Param organization path string true "Organization slug"
// @Param body body dtos.ProjectCreateRequest true "Request body"
// @Success 200 {object} models.Project
// @Router /organizations/{organization}/projects [post]
func (ProjectController *ProjectController) Create(ctx shared.Context) error {
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

	err := ProjectController.projectService.CreateProject(ctx, &newProject)
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
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Success 200 {array} dtos.UserDTO
// @Router /organizations/{organization}/projects/{projectSlug}/members [get]
func (ProjectController *ProjectController) Members(c shared.Context) error {
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
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Param body body dtos.ProjectInviteRequest true "Request body"
// @Success 200
// @Router /organizations/{organization}/projects/{projectSlug}/members [post]
func (ProjectController *ProjectController) InviteMembers(c shared.Context) error {
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

func (ProjectController *ProjectController) RemoveMember(c shared.Context) error {
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

func (ProjectController *ProjectController) ChangeRole(c shared.Context) error {
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

	// check if role is valid
	if role := req.Role; role != "admin" && role != "member" {
		return echo.NewHTTPError(400, "invalid role")
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
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Success 200
// @Router /organizations/{organization}/projects/{projectSlug} [delete]
func (ProjectController *ProjectController) Delete(c shared.Context) error {
	project := shared.GetProject(c)

	err := ProjectController.projectRepository.Delete(c.Request().Context(), nil, project.ID)
	if err != nil {
		return err
	}

	return c.NoContent(200)
}

// @Summary Get project details
// @Tags Projects
// @Security CookieAuth
// @Security PATAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Success 200 {object} dtos.ProjectDetailsDTO
// @Router /organizations/{organization}/projects/{projectSlug} [get]
func (ProjectController *ProjectController) Read(c shared.Context) error {
	// just get the project from the context
	project := shared.GetProject(c)
	rbac := shared.GetRBAC(c)
	allowedAssetIDs, err := rbac.GetAllAssetsForUser(shared.GetSession(c).GetUserID())
	if err != nil {
		return err
	}
	// lets fetch the assets related to this project
	assets, err := ProjectController.assetRepository.GetAllowedAssetsByProjectID(c.Request().Context(), nil, allowedAssetIDs, project.ID)
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
	webhooks, err := ProjectController.getWebhooks(c)
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

func (ProjectController *ProjectController) getWebhooks(c shared.Context) ([]dtos.WebhookIntegrationDTO, error) {

	orgID := shared.GetOrg(c).GetID()
	projectID := shared.GetProject(c).GetID()

	webhooks, err := ProjectController.webhookRepository.GetProjectWebhooks(c.Request().Context(), nil, orgID, projectID)
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
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Param search query string false "Search query for filtering sub-projects and assets"
// @Success 200 {array} dtos.ProjectAssetDTO
// @Router /organizations/{organization}/projects/{projectSlug}/resources [get]

func (ProjectController *ProjectController) ListSubProjectsAndAssets(c shared.Context) error {

	results, err := ProjectController.projectService.ListAllowedSubProjectsAndAssetsPaged(c)
	if err != nil {
		return err
	}

	return c.JSON(200, results)
}

// @Summary List projects
// @Tags Projects
// @Security CookieAuth
// @Security PATAuth
// @Param organization path string true "Organization slug"
// @Success 200 {array} models.Project
// @Router /organizations/{organization}/projects [get]
func (ProjectController *ProjectController) List(c shared.Context) error {
	// get all projects the user has at least read access to - might be public projects as well
	projects, err := ProjectController.projectService.ListAllowedProjectsPaged(c)

	if err != nil {
		return err
	}

	return c.JSON(200, projects)
}

func (ProjectController *ProjectController) SearchProjectsWithSubProjectsAndAssets(c shared.Context) error {

	results, err := ProjectController.projectService.SearchProjectsWithSubProjectsAndAssetsPaged(c)
	if err != nil {
		return err
	}

	return c.JSON(200, results)
}

// @Summary Update project
// @Tags Projects
// @Security CookieAuth
// @Security PATAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Param body body dtos.ProjectPatchRequest true "Request body"
// @Success 200 {object} dtos.ProjectDetailsDTO
// @Router /organizations/{organization}/projects/{projectSlug} [patch]
func (ProjectController *ProjectController) Update(c shared.Context) error {
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
		err = ProjectController.projectRepository.Update(reqCtx, nil, &project)
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
	assets, err := ProjectController.assetRepository.GetAllowedAssetsByProjectID(reqCtx, nil, allowedAssetIDs, project.ID)
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
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Param config-file path string true "Config file ID"
// @Produce text/plain
// @Success 200 {string} string "Config file content"
// @Router /organizations/{organization}/projects/{projectSlug}/config-files/{config-file}/ [get]
func (ProjectController *ProjectController) GetConfigFile(ctx shared.Context) error {
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
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Param config-file path string true "Config file ID"
// @Param body body string true "Config file content"
// @Produce text/plain
// @Success 200 {string} string "Updated config file content"
// @Router /organizations/{organization}/projects/{projectSlug}/config-files/{config-file}/ [put]
func (ProjectController *ProjectController) UpdateConfigFile(ctx shared.Context) error {
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
	err = ProjectController.projectRepository.Update(ctx.Request().Context(), nil, &project)
	if err != nil {
		return echo.NewHTTPError(500, "could not update config file").WithInternal(err)
	}
	return ctx.String(200, configContent)
}

type dynamicProjectRequest struct {
	Verb         string          `json:"verb"`
	ProjectName  string          `json:"projectName"`
	AssetName    string          `json:"assetName"`
	AssetVersion string          `json:"assetVersion"`
	Sbom         json.RawMessage `json:"sbom,omitempty"`
}

func (ProjectController *ProjectController) HandleDynamicProject(ctx shared.Context) error {

	body, err := io.ReadAll(ctx.Request().Body)
	if err != nil {
		return echo.NewHTTPError(400, fmt.Sprintf("could not read request body: %s", err.Error())).WithInternal(err)
	}

	var probe dynamicProjectRequest
	if err := json.Unmarshal(body, &probe); err != nil {
		return echo.NewHTTPError(400, fmt.Sprintf("could not parse request body: %s", err.Error())).WithInternal(err)
	}

	if probe.ProjectName == "" || probe.AssetName == "" {
		return echo.NewHTTPError(400, "verb, projectName, and assetName are required")
	}

	action := probe.Verb
	projectName := probe.ProjectName
	assetName := probe.AssetName
	assetVersionName := probe.AssetVersion

	organization := shared.GetOrg(ctx)
	parentProject := shared.GetProject(ctx)
	userID := shared.GetSession(ctx).GetUserID()

	if action == "delete" {
		err := ProjectController.projectRepository.CleanupDynamicProject(ctx.Request().Context(), nil, organization.GetID(), parentProject.ID, projectName, assetName, assetVersionName)
		if err != nil {
			return echo.NewHTTPError(500, fmt.Sprintf("could not delete project: %s", err.Error())).WithInternal(err)
		}

		return ctx.JSON(200, map[string]string{"message": "project and asset deleted successfully"})
	} else if action != "update" {
		return echo.NewHTTPError(400, "invalid verb, only 'update' and 'delete' are allowed")
	}

	bom := new(cdx.BOM)

	if probe.Sbom == nil {
		return echo.NewHTTPError(400, "sbom is required")
	}
	if err := json.Unmarshal(probe.Sbom, bom); err != nil {
		return echo.NewHTTPError(400, fmt.Sprintf("could not parse CycloneDX BOM: %s", err.Error())).WithInternal(err)
	}

	project, err := ProjectController.projectService.FindOrCreateProject(ctx, organization.GetID(), projectName, parentProject.ID)

	rbac := shared.GetRBAC(ctx)
	asset, err := ProjectController.assetService.FindOrCreateAsset(ctx.Request().Context(), rbac, organization.GetID(), project.ID, assetName, userID)
	if err != nil {
		return echo.NewHTTPError(500, fmt.Sprintf("could not create asset: %s", err.Error())).WithInternal(err)
	}

	assetVersion, err := ProjectController.assetVersionRepository.FindOrCreate(ctx.Request().Context(), nil, assetVersionName, asset.ID, false, nil)
	if err != nil {
		return echo.NewHTTPError(500, fmt.Sprintf("could not create asset version: %s", err.Error())).WithInternal(err)
	}

	artifactName := normalize.ArtifactPurl("operator", fmt.Sprintf("%s/%s/%s", organization.Slug, project.Slug, asset.Name))

	artifact := models.Artifact{
		ArtifactName:     artifactName,
		AssetVersionName: assetVersion.Name,
		AssetID:          asset.ID,
	}
	if err := ProjectController.artifactRepository.Save(ctx.Request().Context(), nil, &artifact); err != nil {
		slog.Error("trivy operator: could not save artifact", "err", err)
		return ctx.JSON(500, map[string]string{"error": "could not save artifact"})
	}

	normalized, err := normalize.SBOMGraphFromCycloneDX(bom, artifactName, "operator", asset.KeepOriginalSbomRootComponent)
	if err != nil {
		slog.Error("trivy operator: failed to normalize BOM", "err", err)
		return ctx.JSON(400, map[string]string{"error": "could not normalize SBOM"})
	}

	wholeSBOM, err := ProjectController.assetVersionService.UpdateSBOM(ctx.Request().Context(), nil, organization, *project, *asset, assetVersion, artifactName, normalized)
	if err != nil {
		slog.Error("trivy operator: could not update SBOM", "err", err)
		return ctx.JSON(500, map[string]string{"error": "could not update SBOM"})
	}

	tx := ProjectController.artifactRepository.GetDB(ctx.Request().Context(), nil).Begin()
	defer tx.Rollback()

	userAgent := ctx.Request().UserAgent()
	_, _, _, err = ProjectController.scanService.ScanNormalizedSBOM(ctx.Request().Context(), tx, organization, *project, *asset, assetVersion, artifact, wholeSBOM, userID, &userAgent)
	if err != nil {
		slog.Error("trivy operator: scan failed", "err", err)
		return ctx.JSON(500, map[string]string{"error": "scan failed"})
	}

	tx.Commit()
	return ctx.JSON(200, map[string]string{"message": "project and asset created, SBOM processed and scan started successfully"})
}

type devGuardAsset struct {
	ProjectName string `json:"projectName"`
	Assets      []struct {
		Name     string   `json:"name"`
		Versions []string `json:"versions"`
	} `json:"assets"`
}

func (ProjectController *ProjectController) ListDynamicProjects(ctx shared.Context) error {
	reqCtx := ctx.Request().Context()
	parentProject := shared.GetProject(ctx)

	//TOD:: we should optimize this by doing it in a single query.
	projects, err := ProjectController.projectRepository.GetDirectChildProjects(reqCtx, nil, parentProject.ID)
	if err != nil {
		return echo.NewHTTPError(500, "could not list projects").WithInternal(err)
	}

	result := make([]devGuardAsset, 0, len(projects))
	for _, project := range projects {
		assets, err := ProjectController.assetRepository.GetByProjectID(reqCtx, nil, project.ID)
		if err != nil {
			return echo.NewHTTPError(500, "could not list assets").WithInternal(err)
		}

		entry := devGuardAsset{ProjectName: project.Name}
		for _, asset := range assets {
			versions, err := ProjectController.assetVersionRepository.GetAssetVersionsByAssetID(reqCtx, nil, asset.ID)
			if err != nil {
				return echo.NewHTTPError(500, "could not list asset versions").WithInternal(err)
			}

			assetEntry := struct {
				Name     string   `json:"name"`
				Versions []string `json:"versions"`
			}{Name: asset.Name}

			for _, v := range versions {
				assetEntry.Versions = append(assetEntry.Versions, v.Name)
			}
			entry.Assets = append(entry.Assets, assetEntry)
		}
		result = append(result, entry)
	}

	return ctx.JSON(200, result)
}
