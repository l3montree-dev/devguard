package controllers

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/services"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/transformer"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/labstack/echo/v4"
)

type AssetController struct {
	assetRepository        shared.AssetRepository
	assetVersionRepository shared.AssetVersionRepository
	assetService           shared.AssetService
	dependencyVulnService  shared.DependencyVulnService
	statisticsService      shared.StatisticsService
	thirdPartyIntegration  shared.IntegrationAggregate
	utils.FireAndForgetSynchronizer
}

func NewAssetController(repository shared.AssetRepository, assetVersionRepository shared.AssetVersionRepository, assetService shared.AssetService, dependencyVulnService shared.DependencyVulnService, statisticsService shared.StatisticsService, thirdPartyIntegration shared.IntegrationAggregate, synchronizer utils.FireAndForgetSynchronizer) *AssetController {
	return &AssetController{
		assetRepository:           repository,
		assetVersionRepository:    assetVersionRepository,
		assetService:              assetService,
		dependencyVulnService:     dependencyVulnService,
		statisticsService:         statisticsService,
		thirdPartyIntegration:     thirdPartyIntegration,
		FireAndForgetSynchronizer: synchronizer,
	}
}

func (a *AssetController) HandleLookup(ctx shared.Context) error {
	provider := ctx.QueryParam("provider")
	if provider == "" {
		return echo.NewHTTPError(400, "missing provider")
	}

	id := ctx.QueryParam("id")
	if id == "" {
		return echo.NewHTTPError(400, "missing repository id ('id')")
	}

	asset, err := a.assetRepository.FindAssetByExternalProviderID(provider, id)

	if err != nil {
		return echo.NewHTTPError(404, "asset not found").WithInternal(err)
	}

	assetFqn, err := a.assetRepository.GetFQNByID(asset.ID)

	// split the fqn into organization, project and asset
	if err != nil {
		return echo.NewHTTPError(500, "could not get asset FQN").WithInternal(err)
	}
	parts := strings.Split(assetFqn, "/")
	if len(parts) != 3 {
		return echo.NewHTTPError(500, "invalid asset FQN format")
	}

	response := dtos.LookupResponse{
		Org:     parts[0],
		Project: parts[1],
		Asset:   parts[2],
		Link:    fmt.Sprintf("/api/v1/organizations/%s/projects/%s/assets/%s", parts[0], parts[1], parts[2]),
	}

	return ctx.JSON(200, response)
}

func (a *AssetController) List(ctx shared.Context) error {
	project := shared.GetProject(ctx)
	rbac := shared.GetRBAC(ctx)
	allowedAssetIDs, err := rbac.GetAllAssetsForUser(shared.GetSession(ctx).GetUserID())
	if err != nil {
		return echo.NewHTTPError(500, "could not get allowed assets for user").WithInternal(err)
	}

	apps, err := a.assetRepository.GetAllowedAssetsByProjectID(allowedAssetIDs, project.GetID())
	if err != nil {
		return err
	}

	return ctx.JSON(200, transformer.AssetModelsToDTOs(apps))
}

func (a *AssetController) AttachSigningKey(ctx shared.Context) error {
	asset := shared.GetAsset(ctx)

	// read the fingerprint from request body
	var req struct {
		PubKey string `json:"publicKey"`
	}

	if err := ctx.Bind(&req); err != nil {
		return echo.NewHTTPError(400, "unable to process request").WithInternal(err)
	}

	asset.SigningPubKey = &req.PubKey
	// save the asset
	err := a.assetRepository.Update(nil, &asset)
	if err != nil {
		return echo.NewHTTPError(500, "could not attach signing key").WithInternal(err)
	}

	return nil
}

func (a *AssetController) Delete(ctx shared.Context) error {
	asset := shared.GetAsset(ctx)
	err := a.assetRepository.Delete(nil, asset.GetID())
	if err != nil {
		return err
	}
	return ctx.NoContent(200)
}

func (a *AssetController) GetSecrets(ctx shared.Context) error {
	asset := shared.GetAsset(ctx)

	secrets := map[string]string{}

	if asset.BadgeSecret != nil {
		secrets["badgeSecret"] = asset.BadgeSecret.String()
	}

	if asset.WebhookSecret != nil {
		secrets["webhookSecret"] = asset.WebhookSecret.String()
	}

	return ctx.JSON(200, secrets)
}

func (a *AssetController) Create(ctx shared.Context) error {
	var req dtos.AssetCreateRequest
	if err := ctx.Bind(&req); err != nil {
		return echo.NewHTTPError(400, "unable to process request").WithInternal(err)
	}

	if err := shared.V.Struct(req); err != nil {
		return echo.NewHTTPError(400, fmt.Sprintf("could not validate request: %s", err.Error()))
	}

	project := shared.GetProject(ctx)

	newAsset := transformer.AssetCreateRequestToModel(req, project.GetID())
	newAsset.ProjectID = project.GetID()

	asset, err := a.assetService.CreateAsset(shared.GetRBAC(ctx), shared.GetSession(ctx).GetUserID(), newAsset)
	if err != nil {
		return err
	}

	return ctx.JSON(200, transformer.AssetModelToDTO(*asset))
}

func (a *AssetController) Read(ctx shared.Context) error {
	app := shared.GetAsset(ctx)
	// fetch the members of the asset
	members, err := services.FetchMembersOfAsset(ctx)
	if err != nil {
		return err
	}

	return ctx.JSON(200, transformer.AssetModelToDetailsDTO(app, members))
}

func (a *AssetController) Update(ctx shared.Context) error {
	asset := shared.GetAsset(ctx)

	req := ctx.Request().Body
	defer req.Close()

	var patchRequest dtos.AssetPatchRequest

	err := json.NewDecoder(req).Decode(&patchRequest)
	if err != nil {
		return fmt.Errorf("error decoding request: %v", err)
	}

	var justification = ""
	if patchRequest.ConfidentialityRequirement != nil && *patchRequest.ConfidentialityRequirement != asset.ConfidentialityRequirement {
		justification += "Confidentiality Requirement updated: " + string(asset.ConfidentialityRequirement) + " -> " + string(*patchRequest.ConfidentialityRequirement)
		asset.ConfidentialityRequirement = *patchRequest.ConfidentialityRequirement
	}

	if patchRequest.IntegrityRequirement != nil && *patchRequest.IntegrityRequirement != asset.IntegrityRequirement {
		if justification != "" {
			justification += ", "
		}
		justification += "Integrity Requirement updated: " + string(asset.IntegrityRequirement) + " -> " + string(*patchRequest.IntegrityRequirement)
		asset.IntegrityRequirement = *patchRequest.IntegrityRequirement
	}

	if patchRequest.AvailabilityRequirement != nil && *patchRequest.AvailabilityRequirement != asset.AvailabilityRequirement {
		if justification != "" {
			justification += ", "
		}
		justification += "Availability Requirement updated: " + string(asset.AvailabilityRequirement) + " -> " + string(*patchRequest.AvailabilityRequirement)
		asset.AvailabilityRequirement = *patchRequest.AvailabilityRequirement
	}

	if justification != "" {
		err = a.assetService.UpdateAssetRequirements(asset, shared.GetSession(ctx).GetUserID(), justification)
		if err != nil {
			return fmt.Errorf("error updating requirements: %v", err)
		}
	}

	enableTicketRangeUpdated := false

	if patchRequest.EnableTicketRange != nil && *patchRequest.EnableTicketRange {
		if patchRequest.CVSSAutomaticTicketThreshold != nil {
			if asset.CVSSAutomaticTicketThreshold != nil {
				if !utils.CompareFirstTwoDecimals(*patchRequest.CVSSAutomaticTicketThreshold, *asset.CVSSAutomaticTicketThreshold) {
					enableTicketRangeUpdated = true
					asset.CVSSAutomaticTicketThreshold = patchRequest.CVSSAutomaticTicketThreshold
				}
			} else {
				enableTicketRangeUpdated = true
				asset.CVSSAutomaticTicketThreshold = patchRequest.CVSSAutomaticTicketThreshold
			}
		} else {
			if asset.CVSSAutomaticTicketThreshold != nil {
				enableTicketRangeUpdated = true
				asset.CVSSAutomaticTicketThreshold = nil
			}
		}

		if patchRequest.RiskAutomaticTicketThreshold != nil {
			if asset.RiskAutomaticTicketThreshold != nil {
				if !utils.CompareFirstTwoDecimals(*patchRequest.RiskAutomaticTicketThreshold, *asset.RiskAutomaticTicketThreshold) {
					enableTicketRangeUpdated = true
					asset.RiskAutomaticTicketThreshold = patchRequest.RiskAutomaticTicketThreshold
				}
			} else {
				enableTicketRangeUpdated = true
				asset.RiskAutomaticTicketThreshold = patchRequest.RiskAutomaticTicketThreshold
			}
		} else {
			if asset.RiskAutomaticTicketThreshold != nil {
				enableTicketRangeUpdated = true
				asset.RiskAutomaticTicketThreshold = nil
			}
		}

	} else if patchRequest.EnableTicketRange != nil && !*patchRequest.EnableTicketRange {
		// if the enableTicketRange is set to false, we do need to call the ticket sync
		asset.CVSSAutomaticTicketThreshold = nil
		asset.RiskAutomaticTicketThreshold = nil

		enableTicketRangeUpdated = true
	}

	org := shared.GetOrg(ctx)
	project := shared.GetProject(ctx)
	if enableTicketRangeUpdated || justification != "" {
		//check if we have already created the labels in gitlab, if not create them
		// do NOT update the asset in the database yet, we do this after the ticket sync
		//we can't do this in the background task, because we need this before we save the asset
		if asset.Metadata == nil {
			asset.Metadata = map[string]any{}
		}
		if asset.Metadata["gitlabLabels"] == nil {
			err = a.thirdPartyIntegration.CreateLabels(ctx.Request().Context(), asset)
			if err != nil {
				slog.Error("could not create labels in gitlab", "err", err)
			} else {
				asset.Metadata["gitlabLabels"] = true
			}
		}

		a.FireAndForget(func() {
			defaultAssetVersion, err := a.assetVersionRepository.GetDefaultAssetVersion(asset.ID)
			if err != nil {
				slog.Error("could not get default asset version", "err", err)
				return
			}

			if err := a.dependencyVulnService.SyncAllIssues(org, project, asset, defaultAssetVersion); err != nil {
				slog.Warn("could not sync tickets", "err", err)
			}
		})
	}

	updated := transformer.ApplyAssetPatchRequestToModel(patchRequest, &asset)
	if asset.Name == "" || asset.Slug == "" {
		return echo.NewHTTPError(409, "assets with an empty name or an empty slug are not allowed").WithInternal(fmt.Errorf("assets with an empty name or an empty slug are not allowed"))
	}

	if updated || enableTicketRangeUpdated {
		err = a.assetRepository.Update(nil, &asset)
		if err != nil {
			return fmt.Errorf("error updating asset: %v", err)
		}
	}

	members, err := services.FetchMembersOfAsset(ctx)
	if err != nil {
		return err
	}

	return ctx.JSON(200, transformer.AssetModelToDetailsWithSecretsDTO(asset, members))
}

func (a *AssetController) GetConfigFile(ctx shared.Context) error {
	organization := shared.GetOrg(ctx)
	project := shared.GetProject(ctx)
	asset := shared.GetAsset(ctx)
	configID := ctx.Param("config-file")

	configContent, ok := asset.ConfigFiles[configID]
	if !ok { //if we have no config files in this asset we want to look in the corresponding project and then in the organization
		configContent, ok = project.ConfigFiles[configID]
		if !ok {
			configContent, ok = organization.ConfigFiles[configID]
			if !ok {
				return ctx.NoContent(404)
			}
			return ctx.JSON(200, configContent)
		}
		return ctx.JSON(200, configContent)
	}
	return ctx.JSON(200, configContent)
}

func (a *AssetController) GetBadges(ctx shared.Context) error {

	badgeSecret := ctx.Param("badgeSecret")
	if badgeSecret == "" {
		return echo.NewHTTPError(400, "missing badge secret")
	}

	badge := ctx.Param("badge")
	if badge == "" {
		return echo.NewHTTPError(400, "missing badge")
	}

	//delete the slashes from the badge secret
	badgeSecret = strings.ReplaceAll(badgeSecret, "/", "")

	badgeSecretUUID, err := uuid.Parse(badgeSecret)
	if err != nil {
		return echo.NewHTTPError(400, "invalid badge secret").WithInternal(err)
	}

	asset, err := a.assetRepository.GetAssetIDByBadgeSecret(badgeSecretUUID)
	if err != nil {
		return echo.NewHTTPError(404, "asset not found").WithInternal(err)
	}

	assetVersion, err := a.assetVersionRepository.GetDefaultAssetVersion(asset.ID)
	if err != nil {
		slog.Error("Error getting default asset version", "error", err)
	}

	svg := ""

	if badge == "cvss" {
		results, err := a.statisticsService.GetArtifactRiskHistory(nil, assetVersion.Name, asset.ID, time.Now(), time.Now()) // only the last entry
		if err != nil {
			return err
		}
		svg = a.assetService.GetCVSSBadgeSVG(results)

		if svg == "" {
			return echo.NewHTTPError(404, "badge not found")
		}
	} else {
		return echo.NewHTTPError(400, "invalid badge type")
	}

	ctx.Response().Header().Set(echo.HeaderContentType, "image/svg+xml")
	ctx.Response().Header().Set(echo.HeaderCacheControl, "no-cache, no-store")

	return ctx.String(200, svg)
}
func (a *AssetController) Members(c shared.Context) error {
	members, err := services.FetchMembersOfAsset(c)
	if err != nil {
		return err
	}

	return c.JSON(200, members)
}

func (a *AssetController) InviteMembers(c shared.Context) error {
	asset := shared.GetAsset(c)

	// get rbac
	rbac := shared.GetRBAC(c)

	var req dtos.AssetInviteToAssetRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(400, "unable to process request").WithInternal(err)
	}

	if err := shared.V.Struct(req); err != nil {
		return echo.NewHTTPError(400, fmt.Sprintf("could not validate request: %s", err.Error()))
	}

	members, err := rbac.GetAllMembersOfProject(asset.ProjectID.String())
	if err != nil {
		return echo.NewHTTPError(500, "could not get members of asset").WithInternal(err)
	}

	for _, newMemberID := range req.Ids {
		if !utils.Contains(members, newMemberID) {
			return echo.NewHTTPError(400, "user is not a member of the asset")
		}

		// log the invitation for audit
		slog.Info("adding member to asset",
			"addedBy", shared.GetSession(c).GetUserID(),
			"addedUser", newMemberID,
			"assetID", asset.ID.String())

		if err := rbac.GrantRoleInAsset(newMemberID, shared.RoleMember, asset.ID.String()); err != nil {
			return err
		}
	}
	return c.NoContent(200)
}

func (a *AssetController) RemoveMember(c shared.Context) error {
	asset := shared.GetAsset(c)

	// get rbac
	rbac := shared.GetRBAC(c)

	userID := c.Param("userID")
	if userID == "" {
		return echo.NewHTTPError(400, "userID is required")
	}
	// Log the removal for audit
	slog.Info("removing member from asset",
		"removedBy", shared.GetSession(c).GetUserID(),
		"removedUser", userID,
		"assetID", asset.ID.String())

	// revoke admin and member role
	rbac.RevokeRoleInAsset(userID, shared.RoleAdmin, asset.ID.String())  // nolint:errcheck // we don't care if the user is not an admin
	rbac.RevokeRoleInAsset(userID, shared.RoleMember, asset.ID.String()) // nolint:errcheck // we don't care if the user is not a member

	return c.NoContent(200)
}

func (a *AssetController) ChangeRole(c shared.Context) error {
	asset := shared.GetAsset(c)

	// get rbac
	rbac := shared.GetRBAC(c)

	var req dtos.AssetChangeRoleRequest

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

	members, err := rbac.GetAllMembersOfProject(asset.ProjectID.String())
	if err != nil {
		return echo.NewHTTPError(500, "could not get members of project").WithInternal(err)
	}

	if !utils.Contains(members, userID) {
		return echo.NewHTTPError(400, "user is not a member of the project")
	}

	// log for audit
	slog.Info("changing role of member in asset",
		"changedBy", shared.GetSession(c).GetUserID(),
		"changedUser", userID,
		"assetID", asset.ID.String(),
		"newRole", req.Role)

	rbac.RevokeRoleInAsset(userID, shared.RoleAdmin, asset.ID.String())  // nolint:errcheck // we don't care if the user is not an admin
	rbac.RevokeRoleInAsset(userID, shared.RoleMember, asset.ID.String()) // nolint:errcheck // we don't care if the user is not a member

	if err := rbac.GrantRoleInAsset(userID, shared.Role(req.Role), asset.ID.String()); err != nil {
		return err
	}

	return c.NoContent(200)
}
