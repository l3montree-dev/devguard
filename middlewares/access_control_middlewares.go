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

package middleware

import (
	"fmt"
	"log/slog"
	"strings"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/accesscontrol"
	"github.com/l3montree-dev/devguard/internal/core/integrations/gitlabint"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/utils"
	"github.com/labstack/echo/v4"
)

func organizationAccessControlMiddleware(obj shared.Object, act shared.Action) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(ctx echo.Context) error {
			// get the rbac
			rbac := shared.GetRBAC(ctx)
			org := shared.GetOrg(ctx)
			// get the user
			user := shared.GetSession(ctx).GetUserID()

			allowed, err := rbac.IsAllowed(user, obj, act)
			if err != nil {
				ctx.Response().WriteHeader(500)
				return echo.NewHTTPError(500, "could not determine if the user has access").WithInternal(err)
			}

			// check if the user has the required role
			if !allowed {
				if org.IsPublic && act == shared.ActionRead {
					shared.SetIsPublicRequest(ctx)
				} else {
					slog.Error("access denied in accessControlMiddleware", "user", user, "object", obj, "action", act)
					ctx.Response().WriteHeader(404)
					return echo.NewHTTPError(404, "could not find organization")
				}
			}

			return next(ctx)
		}
	}
}

func neededScope(neededScopes []string) shared.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c shared.Context) error {
			userScopes := shared.GetSession(c).GetScopes()

			ok := utils.ContainsAll(userScopes, neededScopes)
			if !ok {
				slog.Error("user does not have the required scopes", "neededScopes", neededScopes, "userScopes", userScopes)
				return echo.NewHTTPError(403, fmt.Sprintf("your personal access token does not have the required scope, needed scopes: %s", strings.Join(neededScopes, ", ")))
			}

			return next(c)

		}
	}
}

func assetAccessControlFactory(assetRepository shared.AssetRepository) shared.RBACMiddleware {
	return func(obj shared.Object, act shared.Action) shared.MiddlewareFunc {
		return func(next echo.HandlerFunc) echo.HandlerFunc {
			return func(ctx shared.Context) error {
				// get the rbac
				rbac := shared.GetRBAC(ctx)
				// get the user
				user := shared.GetSession(ctx).GetUserID()
				// get the project
				project := shared.GetProject(ctx)
				// get the asset slug
				assetSlug, err := shared.GetAssetSlug(ctx)
				if err != nil {
					return echo.NewHTTPError(400, "invalid asset slug")
				}
				var asset models.Asset
				// check if asset is already set in the context
				if a, ok := ctx.Get("asset").(models.Asset); ok {
					asset = a
				} else {
					// get the asset by slug and project
					asset, err = assetRepository.ReadBySlug(project.ID, assetSlug)
					if err != nil {
						return echo.NewHTTPError(404, "could not find asset")
					}
				}

				allowed, err := rbac.IsAllowedInAsset(&asset, user, obj, act)
				if err != nil {
					return echo.NewHTTPError(500, "could not determine if the user has access")
				}
				// check if the user has the required role
				if !allowed {
					if asset.IsPublic && act == shared.ActionRead {
						// allow READ on all objects in the project - if access is public
						shared.SetIsPublicRequest(ctx)
					} else {
						slog.Warn("access denied in AssetAccess", "user", user, "object", obj, "action", act, "assetSlug", assetSlug)
						return echo.NewHTTPError(404, "could not find asset")
					}
				}
				shared.SetAsset(ctx, asset)
				return next(ctx)
			}
		}
	}
}

func projectAccessControlFactory(projectRepository shared.ProjectRepository) shared.RBACMiddleware {
	return func(obj shared.Object, act shared.Action) shared.MiddlewareFunc {
		return func(next echo.HandlerFunc) echo.HandlerFunc {
			return func(ctx shared.Context) error {
				// get the rbac
				rbac := shared.GetRBAC(ctx)

				// get the user
				user := shared.GetSession(ctx).GetUserID()

				// get the project id
				projectSlug, err := shared.GetProjectSlug(ctx)
				if err != nil {
					return echo.NewHTTPError(500, "could not get project id")
				}

				var project models.Project
				// check if project is already set in the context
				if p, ok := ctx.Get("project").(models.Project); ok {
					project = p
				} else {
					// get the project by slug and organization.
					project, err = projectRepository.ReadBySlug(shared.GetOrg(ctx).GetID(), projectSlug)
				}

				if err != nil {
					return echo.NewHTTPError(404, "could not find project")
				}

				allowed, err := rbac.IsAllowedInProject(&project, user, obj, act)

				if err != nil {
					return echo.NewHTTPError(500, "could not determine if the user has access")
				}

				// check if the user has the required role
				if !allowed {
					if project.IsPublic && act == shared.ActionRead {
						// allow READ on all objects in the project - if access is public
						shared.SetIsPublicRequest(ctx)
					} else {
						slog.Warn("access denied in ProjectAccess", "user", user, "object", obj, "action", act, "projectSlug", projectSlug)
						return echo.NewHTTPError(404, "could not find project")
					}
				}

				ctx.Set("project", project)

				return next(ctx)
			}
		}
	}
}

func multiOrganizationMiddlewareRBAC(rbacProvider shared.RBACProvider, organizationService shared.OrgService, oauth2Config map[string]*gitlabint.GitlabOauth2Config) shared.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(ctx shared.Context) (err error) {
			// get the organization from the provided context
			organization, err := shared.GetURLDecodedParam(ctx, "organization")
			if err != nil {
				slog.Error("could not get organization from url", "err", err)
				return echo.NewHTTPError(400, "invalid organization")
			}
			if organization == "" {
				// if no organization is provided, we can't continue
				slog.Error("no organization provided")
				return ctx.JSON(400, map[string]string{"error": "no organization"})
			}

			// get the organization
			org, err := organizationService.ReadBySlug(organization)
			if err != nil {
				return echo.NewHTTPError(404, "organization not found").WithInternal(err)
			}

			// check what kind of RBAC we need
			domainRBAC := rbacProvider.GetDomainRBAC(org.ID.String())
			if org.IsExternalEntity() {
				// check if there is an admin token defined
				conf, ok := oauth2Config[*org.ExternalEntityProviderID]
				if !ok {
					slog.Error("no oauth2 config found for external entity provider", "provider", *org.ExternalEntityProviderID)
					return ctx.JSON(500, map[string]string{"error": "no oauth2 config found for external entity provider"})
				}

				domainRBAC = accesscontrol.NewExternalEntityProviderRBAC(ctx, rbacProvider.GetDomainRBAC(org.ID.String()), shared.GetThirdPartyIntegration(ctx), *org.ExternalEntityProviderID, conf.AdminToken)
			}

			// check if the user is allowed to access the organization
			session := shared.GetSession(ctx)
			allowed, err := domainRBAC.HasAccess(session.GetUserID())
			if err != nil {
				slog.Info("asking user to reauthorize", "err", err)
				return ctx.JSON(401, map[string]string{"error": err.Error()})
			}

			if !allowed {
				if org.IsPublic {
					shared.SetIsPublicRequest(ctx)
				} else {
					// not allowed and not a public organization
					slog.Error("access denied in multiOrganizationMiddleware", "user", session.GetUserID(), "organization", organization)
					return ctx.JSON(404, map[string]string{"error": "could not find organization"})
				}
			}

			shared.SetOrg(ctx, *org)
			shared.SetRBAC(ctx, domainRBAC)
			shared.SetOrgSlug(ctx, organization)
			// continue to the request
			return next(ctx)
		}
	}
}

func shareMiddleware(orgRepository shared.OrganizationRepository, projectRepository shared.ProjectRepository, assetRepository shared.AssetRepository, assetVersionRepository shared.AssetVersionRepository, artifactRepository shared.ArtifactRepository) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(ctx shared.Context) error {
			// get the assetID from the url
			assetID, err := shared.GetURLDecodedParam(ctx, "assetID")
			if err != nil {
				slog.Error("could not get assetID from url", "err", err)
				return echo.NewHTTPError(400, "invalid assetID")
			}

			assetUUID, err := uuid.Parse(assetID)
			if err != nil {
				slog.Error("invalid assetID format", "assetID", assetID, "err", err)
				return echo.NewHTTPError(400, "invalid assetID format")
			}
			// get the asset
			asset, err := assetRepository.Read(assetUUID)
			if err != nil {
				slog.Error("could not find asset in shareMiddleware", "assetID", assetID, "err", err)
				return echo.NewHTTPError(404, "could not find asset")
			}
			// fetch org and project
			project, err := projectRepository.Read(asset.ProjectID)
			if err != nil {
				slog.Error("could not find project in shareMiddleware", "assetID", assetID, "projectID", asset.ProjectID, "err", err)
				return echo.NewHTTPError(404, "could not find asset")
			}
			org, err := orgRepository.Read(project.OrganizationID)
			if err != nil {
				slog.Error("could not find organization in shareMiddleware", "assetID", assetID, "organizationID", project.OrganizationID, "err", err)
				return echo.NewHTTPError(404, "could not find asset")
			}

			// check if sharing is enabled
			if !asset.SharesInformation {
				slog.Warn("access denied in shareMiddleware - sharing not enabled", "assetID", assetID)
				return echo.NewHTTPError(404, "could not find asset")
			}

			var assetVersion models.AssetVersion
			// lets check for ref and artifact name query parameters
			if ref := ctx.QueryParam("ref"); ref != "" {
				// find the ref
				assetVersion, err = assetVersionRepository.ReadBySlug(asset.ID, ref)
				if err != nil {
					slog.Error("could not find asset version by ref in shareMiddleware", "assetID", assetID, "ref", ref, "err", err)
					return echo.NewHTTPError(404, "could not find asset version for the provided ref")
				}
			} else {
				// use the default branch
				assetVersion, err = assetVersionRepository.GetDefaultAssetVersion(asset.ID)
				if err != nil {
					slog.Error("could not find default asset version in shareMiddleware", "assetID", assetID, "err", err)
					return echo.NewHTTPError(404, "could not find default asset version")
				}
			}

			if artifactName := ctx.QueryParam("artifactName"); artifactName != "" {
				artifact, err := artifactRepository.ReadArtifact(artifactName, assetVersion.Name, asset.ID)
				if err != nil {
					slog.Error("could not find artifact in shareMiddleware", "assetID", assetID, "artifactName", artifactName, "err", err)
					return echo.NewHTTPError(404, "could not find artifact for the provided artifact name")
				}
				shared.SetArtifact(ctx, artifact)
			}

			shared.SetOrg(ctx, org)
			shared.SetProject(ctx, project)
			shared.SetAsset(ctx, asset)
			shared.SetAssetVersion(ctx, assetVersion)

			return next(ctx)
		}
	}
}

func CsafMiddleware(orgLevel bool, orgRepository shared.OrganizationRepository, projectRepository shared.ProjectRepository, assetRepository shared.AssetRepository, assetVersionRepository shared.AssetVersionRepository, artifactRepository shared.ArtifactRepository) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(ctx shared.Context) error {
			// get the assetID from the url
			orgSlug, err := shared.GetURLDecodedParam(ctx, "organization")
			if err != nil {
				return echo.NewHTTPError(404, "could not find organization")
			}

			orgs, err := orgRepository.GetOrgsWithVulnSharingAssets()
			if err != nil {
				slog.Error("could not get organizations with vuln sharing assets", "err", err)
				return echo.NewHTTPError(500, "could not get organizations").WithInternal(err)
			}
			// check if the orgID is in the list of organizations with vuln sharing assets
			var orgFound *models.Org
			for _, o := range orgs {
				if o.Slug == orgSlug {
					orgFound = &o
					break
				}
			}
			if orgFound == nil {
				return echo.NewHTTPError(404, "could not find organization")
			}
			if orgLevel {
				shared.SetOrg(ctx, *orgFound)
				return next(ctx)
			}
			// check if project project is set, if so load it
			projectSlug, err := shared.GetURLDecodedParam(ctx, "projectSlug")
			if err != nil {
				return echo.NewHTTPError(404, "could not find project")
			}
			project, err := projectRepository.ReadBySlug(orgFound.ID, projectSlug)
			if err != nil {
				return echo.NewHTTPError(404, "could not find project")
			}

			// read the asset
			assetSlug, err := shared.GetURLDecodedParam(ctx, "assetSlug")
			if err != nil {
				return echo.NewHTTPError(404, "could not find asset")
			}
			asset, err := assetRepository.ReadBySlug(project.ID, assetSlug)
			if err != nil {
				return echo.NewHTTPError(404, "could not find asset")
			}
			if !asset.SharesInformation {
				return echo.NewHTTPError(404, "could not find asset")
			}

			shared.SetOrg(ctx, *orgFound)
			shared.SetProject(ctx, project)
			shared.SetAsset(ctx, asset)
			return next(ctx)
		}
	}
}
