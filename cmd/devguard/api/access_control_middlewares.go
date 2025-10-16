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

package api

import (
	"fmt"
	"log/slog"
	"strings"

	"github.com/l3montree-dev/devguard/internal/accesscontrol"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/core/integrations/gitlabint"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/utils"
	"github.com/labstack/echo/v4"
)

func organizationAccessControlMiddleware(obj core.Object, act core.Action) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(ctx echo.Context) error {
			// get the rbac
			rbac := core.GetRBAC(ctx)
			org := core.GetOrg(ctx)
			// get the user
			user := core.GetSession(ctx).GetUserID()

			allowed, err := rbac.IsAllowed(user, obj, act)
			if err != nil {
				ctx.Response().WriteHeader(500)
				return echo.NewHTTPError(500, "could not determine if the user has access").WithInternal(err)
			}

			// check if the user has the required role
			if !allowed {
				if org.IsPublic && act == core.ActionRead {
					core.SetIsPublicRequest(ctx)
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

func neededScope(neededScopes []string) core.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c core.Context) error {
			userScopes := core.GetSession(c).GetScopes()

			ok := utils.ContainsAll(userScopes, neededScopes)
			if !ok {
				slog.Error("user does not have the required scopes", "neededScopes", neededScopes, "userScopes", userScopes)
				return echo.NewHTTPError(403, fmt.Sprintf("your personal access token does not have the required scope, needed scopes: %s", strings.Join(neededScopes, ", ")))
			}

			return next(c)

		}
	}
}

func assetAccessControlFactory(assetRepository core.AssetRepository) core.RBACMiddleware {
	return func(obj core.Object, act core.Action) core.MiddlewareFunc {
		return func(next echo.HandlerFunc) echo.HandlerFunc {
			return func(ctx core.Context) error {
				// get the rbac
				rbac := core.GetRBAC(ctx)
				// get the user
				user := core.GetSession(ctx).GetUserID()
				// get the project
				project := core.GetProject(ctx)
				// get the asset slug
				assetSlug, err := core.GetAssetSlug(ctx)
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
					if asset.IsPublic && act == core.ActionRead {
						// allow READ on all objects in the project - if access is public
						core.SetIsPublicRequest(ctx)
					} else {
						slog.Warn("access denied in AssetAccess", "user", user, "object", obj, "action", act, "assetSlug", assetSlug)
						return echo.NewHTTPError(404, "could not find asset")
					}
				}
				core.SetAsset(ctx, asset)
				return next(ctx)
			}
		}
	}
}

func projectAccessControlFactory(projectRepository core.ProjectRepository) core.RBACMiddleware {
	return func(obj core.Object, act core.Action) core.MiddlewareFunc {
		return func(next echo.HandlerFunc) echo.HandlerFunc {
			return func(ctx core.Context) error {
				// get the rbac
				rbac := core.GetRBAC(ctx)

				// get the user
				user := core.GetSession(ctx).GetUserID()

				// get the project id
				projectSlug, err := core.GetProjectSlug(ctx)
				if err != nil {
					return echo.NewHTTPError(500, "could not get project id")
				}

				var project models.Project
				// check if project is already set in the context
				if p, ok := ctx.Get("project").(models.Project); ok {
					project = p
				} else {
					// get the project by slug and organization.
					project, err = projectRepository.ReadBySlug(core.GetOrg(ctx).GetID(), projectSlug)
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
					if project.IsPublic && act == core.ActionRead {
						// allow READ on all objects in the project - if access is public
						core.SetIsPublicRequest(ctx)
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

func multiOrganizationMiddlewareRBAC(rbacProvider core.RBACProvider, organizationService core.OrgService, oauth2Config map[string]*gitlabint.GitlabOauth2Config) core.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(ctx core.Context) (err error) {
			// get the organization from the provided context
			organization, err := core.GetURLDecodedParam(ctx, "organization")
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

				domainRBAC = accesscontrol.NewExternalEntityProviderRBAC(ctx, rbacProvider.GetDomainRBAC(org.ID.String()), core.GetThirdPartyIntegration(ctx), *org.ExternalEntityProviderID, conf.AdminToken)
			}

			// check if the user is allowed to access the organization
			session := core.GetSession(ctx)
			allowed, err := domainRBAC.HasAccess(session.GetUserID())
			if err != nil {
				slog.Info("asking user to reauthorize", "err", err)
				return ctx.JSON(401, map[string]string{"error": err.Error()})
			}

			if !allowed {
				if org.IsPublic {
					core.SetIsPublicRequest(ctx)
				} else {
					// not allowed and not a public organization
					slog.Error("access denied in multiOrganizationMiddleware", "user", session.GetUserID(), "organization", organization)
					return ctx.JSON(404, map[string]string{"error": "could not find organization"})
				}
			}

			core.SetOrg(ctx, *org)
			core.SetRBAC(ctx, domainRBAC)
			core.SetOrgSlug(ctx, organization)
			// continue to the request
			return next(ctx)
		}
	}
}
