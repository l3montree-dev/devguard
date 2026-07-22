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

package middlewares

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/labstack/echo/v4"
)

func InstanceAdminMiddleware(pat shared.PersonalAccessTokenService) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(ctx echo.Context) error {
			isAdmin, err := pat.VerifyAdminRequest(ctx.Request())
			if err == nil {
				if isAdmin {
					shared.SetSession(ctx, shared.NewSession("admin", shared.SessionActorUser, dtos.AllowedScopes, true))
					return next(ctx)
				}
			}
			return echo.NewHTTPError(401, "unauthorized")
		}
	}
}

func InstanceSettings(configService shared.ConfigService, disabled func(shared.InstanceSettings) bool) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(ctx echo.Context) error {
			settings, err := configService.GetInstanceSettings(ctx.Request().Context())
			if err != nil {
				slog.Error("could not get instance settings", "err", err)
				// if we can't get the settings, we allow the request to avoid blocking access in case of database issues
				return next(ctx)
			}
			if disabled(settings) {
				return echo.NewHTTPError(403, "this endpoint is disabled by the instance configuration")
			}
			return next(ctx)
		}
	}
}

func OrganizationAccessControlMiddleware(obj shared.Object, act shared.Action) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(ctx echo.Context) error {
			// get the rbac
			rbac := shared.GetRBAC(ctx)
			org := shared.GetOrg(ctx)
			// get the user
			session := shared.GetSession(ctx)
			actorScope := shared.GetActorScope(ctx)

			allowed, err := rbac.IsAllowed(ctx.Request().Context(), session, obj, act, actorScope)
			if err != nil {
				ctx.Response().WriteHeader(500)
				return echo.NewHTTPError(500, "could not determine if the user has access").WithInternal(err)
			}

			// check if the user has the required role
			if !allowed {
				if org.IsPublic && act == shared.ActionRead {
					shared.SetIsPublicRequest(ctx)
				} else {
					slog.Error("access denied in accessControlMiddleware", "actorID", session.GetActorID(), "actorType", session.GetSessionActorType(), "object", obj, "action", act)
					ctx.Response().WriteHeader(404)
					return echo.NewHTTPError(404, "could not find organization")
				}
			}

			return next(ctx)
		}
	}
}

func NeededScope(NeededScopes []string) shared.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c shared.Context) error {
			userScopes := shared.GetSession(c).GetScopes()

			ok := utils.ContainsAll(userScopes, NeededScopes)
			if !ok {
				slog.Error("user does not have the required scopes", "NeededScopes", NeededScopes, "userScopes", userScopes)
				return echo.NewHTTPError(403, fmt.Sprintf("your personal access token does not have the required scope, needed scopes: %s", strings.Join(NeededScopes, ", ")))
			}

			return next(c)

		}
	}
}

func DisallowPublicRequests(next echo.HandlerFunc) echo.HandlerFunc {
	return func(ctx shared.Context) error {
		if shared.IsPublicRequest(ctx) {
			slog.Warn("access denied for public request in DisallowPublicRequests middleware")
			return echo.NewHTTPError(401, "this endpoint is not accessible for public requests")
		}
		return next(ctx)
	}
}

// AssetAccessControl assumes ResourceFetchMiddleware has already resolved the
// asset (and org/project) into the context - it never fetches anything itself,
// it only checks the pre-resolved entity against the session/actor scope. It
// has no captured dependency, so it's a plain shared.RBACMiddleware value, not
// a factory that needs constructing.
func AssetAccessControl(obj shared.Object, act shared.Action) shared.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(ctx shared.Context) error {
			rbac := shared.GetRBAC(ctx)
			session := shared.GetSession(ctx)
			asset := shared.GetAsset(ctx)

			allowed, err := rbac.IsAllowedInAsset(ctx.Request().Context(), &asset, session, obj, act)
			if err != nil {
				return echo.NewHTTPError(500, "could not determine if the user has access")
			}
			// check if the user has the required role
			if !allowed {
				if asset.IsPublic && act == shared.ActionRead {
					// allow READ on all objects in the project - if access is public
					shared.SetIsPublicRequest(ctx)
				} else {
					slog.Warn("access denied in AssetAccess", "actor", session.GetActorID(), "actorType", session.GetSessionActorType(), "object", obj, "action", act, "assetSlug", asset.Slug)
					return echo.NewHTTPError(404, "could not find asset")
				}
			}
			return next(ctx)
		}
	}
}

// ProjectAccessControl assumes ResourceFetchMiddleware has already resolved the
// project (and org) into the context - it never fetches anything itself, it
// only checks the pre-resolved entity against the session/actor scope. It has
// no captured dependency, so it's a plain shared.RBACMiddleware value, not a
// factory that needs constructing.
func ProjectAccessControl(obj shared.Object, act shared.Action) shared.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(ctx shared.Context) error {
			rbac := shared.GetRBAC(ctx)
			session := shared.GetSession(ctx)
			project := shared.GetProject(ctx)
			actorScope := shared.GetActorScope(ctx)

			allowed, err := rbac.IsAllowedInProject(ctx.Request().Context(), &project, session, obj, act, actorScope)
			if err != nil {
				return echo.NewHTTPError(500, "could not determine if the user has access")
			}

			// check if the user has the required role
			if !allowed {
				if project.IsPublic && act == shared.ActionRead {
					// allow READ on all objects in the project - if access is public
					shared.SetIsPublicRequest(ctx)
				} else {
					slog.Warn("access denied in ProjectAccess", "actor", session.GetActorID(), "actorType", session.GetSessionActorType(), "object", obj, "action", act, "projectSlug", project.Slug)
					return echo.NewHTTPError(404, "could not find project")
				}
			}

			return next(ctx)
		}
	}
}

// MultiOrganizationMiddlewareRBAC assumes ResourceFetchMiddleware has already
// resolved the org, the domain RBAC and the actor scope into the context - it
// never fetches anything itself, it only checks organization membership.
func MultiOrganizationMiddlewareRBAC() shared.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(ctx shared.Context) (err error) {
			org := shared.GetOrg(ctx)
			domainRBAC := shared.GetRBAC(ctx)
			session := shared.GetSession(ctx)
			actorScope := shared.GetActorScope(ctx)

			allowed, err := domainRBAC.HasAccess(ctx.Request().Context(), session, actorScope)
			if err != nil {
				if errors.Is(err, shared.ErrOauth2TokenNotValidRedirectionRequired) {
					slog.Info("oauth2 token not valid, asking user to reauthorize", "actor", session.GetActorID(), "actorType", session.GetSessionActorType(), "organization", org.Slug)
					return ctx.JSON(403, map[string]string{"error": "oauth2 token not valid, please reauthorize"})
				}
				if org.IsPublic {
					shared.SetIsPublicRequest(ctx)
					return next(ctx)
				}
				return ctx.JSON(401, map[string]string{"error": err.Error()})
			}

			if !allowed {
				if org.IsPublic {
					shared.SetIsPublicRequest(ctx)
				} else {
					// not allowed and not a public organization
					slog.Error("access denied in multiOrganizationMiddleware", "actor", session.GetActorID(), "actorType", session.GetSessionActorType(), "organization", org.Slug)
					return ctx.JSON(404, map[string]string{"error": "could not find organization"})
				}
			}

			// continue to the request
			return next(ctx)
		}
	}
}

// ResourceFetchMiddleware is the single place that resolves every entity a
// request needs, once each: the organization (always, by URL slug), the
// project/asset (when the matched route carries :projectSlug/:assetSlug, by
// URL slug - the authoritative resolution), and the session's own scoped
// entity (by owner ID, when the session is a project- or asset-scoped access
// token), reusing the path-resolved entity when it's the very same row. No
// other middleware or AccessControl method fetches anything itself.
func ResourceFetchMiddleware(rbacProvider shared.RBACProvider, organizationService shared.OrgService, projectRepository shared.ProjectRepository, assetRepository shared.AssetRepository) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(ctx shared.Context) error {
			organization, err := shared.GetURLDecodedParam(ctx, "organization")
			if err != nil {
				slog.Error("could not get organization from url", "err", err)
				return echo.NewHTTPError(400, "invalid organization")
			}
			if organization == "" {
				// no :organization URL path param on this route (e.g. the header-driven
				// fast-access routes) - fall back to the org slug AssetNameMiddleware set.
				organization, _ = shared.GetOrgSlug(ctx)
			}
			if organization == "" {
				slog.Error("no organization provided")
				return ctx.JSON(400, map[string]string{"error": "no organization"})
			}

			org, err := organizationService.ReadBySlug(ctx.Request().Context(), organization)
			if err != nil {
				return echo.NewHTTPError(404, "organization not found").WithInternal(err)
			}

			domainRBAC := rbacProvider.GetDomainRBAC(org.ID.String())
			shared.SetOrg(ctx, *org)
			shared.SetRBAC(ctx, domainRBAC)
			shared.SetOrgSlug(ctx, organization)
			ctx.SetRequest(ctx.Request().WithContext(shared.WithOwnershipScope(ctx.Request().Context(), shared.OwnershipScopeFromOrg(ctx, *org))))

			var resolvedProject *models.Project
			var resolvedAsset *models.Asset

			if projectSlug, slugErr := shared.GetProjectSlug(ctx); slugErr == nil {
				project, err := projectRepository.ReadBySlug(ctx.Request().Context(), nil, org.ID, projectSlug)
				if err != nil {
					return echo.NewHTTPError(404, "could not find project")
				}
				resolvedProject = &project
				shared.SetProject(ctx, project)
				ctx.SetRequest(ctx.Request().WithContext(shared.WithOwnershipScope(ctx.Request().Context(), shared.OwnershipScopeFromProject(ctx, project))))

				if assetSlug, aErr := shared.GetAssetSlug(ctx); aErr == nil {
					asset, err := assetRepository.ReadBySlug(ctx.Request().Context(), nil, project.ID, assetSlug)
					if err != nil {
						return echo.NewHTTPError(404, "could not find asset")
					}
					// the asset's project is exactly the one we just resolved -
					// backfill it without an extra query.
					asset.Project = project
					resolvedAsset = &asset
					shared.SetAsset(ctx, asset)
					ctx.SetRequest(ctx.Request().WithContext(shared.WithOwnershipScope(ctx.Request().Context(), shared.OwnershipScopeFromAsset(ctx, asset))))
				}
			}

			actorScope, err := resolveActorScope(ctx.Request().Context(), shared.GetSession(ctx), resolvedProject, resolvedAsset, projectRepository, assetRepository)
			if err != nil {
				return echo.NewHTTPError(404, "could not resolve access token scope").WithInternal(err)
			}
			shared.SetActorScope(ctx, actorScope)

			return next(ctx)
		}
	}
}

// resolveActorScope resolves the session's own scoped entity by owner ID -
// the identity-driven fetch AccessControl needs to verify a project/asset
// token belongs to the organization/project it's being used against. It
// reuses the path-resolved project/asset when the owner ID matches, avoiding
// a redundant fetch for the common case of a token used against its own
// resource.
func resolveActorScope(ctx context.Context, session shared.AuthSession, resolvedProject *models.Project, resolvedAsset *models.Asset, projectRepository shared.ProjectRepository, assetRepository shared.AssetRepository) (shared.ActorScope, error) {
	ownerID := session.GetActorID()
	switch session.GetSessionActorType() {
	case shared.SessionActorProject:
		if resolvedProject != nil && resolvedProject.ID.String() == ownerID {
			return shared.ActorScope{Project: resolvedProject}, nil
		}
		projectUUID, err := uuid.Parse(ownerID)
		if err != nil {
			return shared.ActorScope{}, fmt.Errorf("could not parse ownerID as UUID: %w", err)
		}
		project, err := projectRepository.Read(ctx, nil, projectUUID)
		if err != nil {
			return shared.ActorScope{}, err
		}
		return shared.ActorScope{Project: &project}, nil
	case shared.SessionActorAsset:
		if resolvedAsset != nil && resolvedAsset.ID.String() == ownerID {
			return shared.ActorScope{Asset: resolvedAsset}, nil
		}
		assetUUID, err := uuid.Parse(ownerID)
		if err != nil {
			return shared.ActorScope{}, fmt.Errorf("could not parse ownerID as UUID: %w", err)
		}
		asset, err := assetRepository.ReadWithProject(ctx, nil, assetUUID)
		if err != nil {
			return shared.ActorScope{}, err
		}
		return shared.ActorScope{Asset: &asset}, nil
	default:
		return shared.ActorScope{}, nil
	}
}

func ShareMiddleware(orgRepository shared.OrganizationRepository, projectRepository shared.ProjectRepository, assetRepository shared.AssetRepository, assetVersionRepository shared.AssetVersionRepository, artifactRepository shared.ArtifactRepository) echo.MiddlewareFunc {
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
			asset, err := assetRepository.Read(ctx.Request().Context(), nil, assetUUID)
			if err != nil {
				slog.Error("could not find asset in ShareMiddleware", "assetID", assetID, "err", err)
				return echo.NewHTTPError(404, "could not find asset")
			}
			// fetch org and project
			project, err := projectRepository.Read(ctx.Request().Context(), nil, asset.ProjectID)
			if err != nil {
				slog.Error("could not find project in ShareMiddleware", "assetID", assetID, "projectID", asset.ProjectID, "err", err)
				return echo.NewHTTPError(404, "could not find asset")
			}
			org, err := orgRepository.Read(ctx.Request().Context(), nil, project.OrganizationID)
			if err != nil {
				slog.Error("could not find organization in ShareMiddleware", "assetID", assetID, "organizationID", project.OrganizationID, "err", err)
				return echo.NewHTTPError(404, "could not find asset")
			}

			// check if sharing is enabled
			if !asset.SharesInformation {
				slog.Warn("access denied in ShareMiddleware - sharing not enabled", "assetID", assetID)
				return echo.NewHTTPError(404, "could not find asset")
			}

			// resolve asset version from path param
			assetVersionSlug, err := shared.GetURLDecodedParam(ctx, "assetVersionSlug")
			if err != nil {
				slog.Error("could not get assetVersionSlug from url", "err", err)
				return echo.NewHTTPError(400, "invalid assetVersionSlug")
			}
			assetVersion, err := assetVersionRepository.ReadBySlug(ctx.Request().Context(), nil, asset.ID, assetVersionSlug)
			if err != nil {
				slog.Error("could not find asset version in ShareMiddleware", "assetID", assetID, "assetVersionSlug", assetVersionSlug, "err", err)
				return echo.NewHTTPError(404, "could not find asset version")
			}

			// resolve artifact from path param
			artifactName, err := shared.GetURLDecodedParam(ctx, "artifactName")
			if err != nil {
				slog.Error("could not get artifactName from url", "err", err)
				return echo.NewHTTPError(400, "invalid artifactName")
			}
			artifact, err := artifactRepository.ReadArtifact(ctx.Request().Context(), nil, artifactName, assetVersion.Name, asset.ID)
			if err != nil {
				slog.Error("could not find artifact in ShareMiddleware", "assetID", assetID, "artifactName", artifactName, "err", err)
				return echo.NewHTTPError(404, "could not find artifact")
			}
			shared.SetArtifact(ctx, artifact)

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

			orgs, err := orgRepository.GetOrgsWithVulnSharingAssets(ctx.Request().Context(), nil)
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
			project, err := projectRepository.ReadBySlug(ctx.Request().Context(), nil, orgFound.ID, projectSlug)
			if err != nil {
				return echo.NewHTTPError(404, "could not find project")
			}

			// read the asset
			assetSlug, err := shared.GetURLDecodedParam(ctx, "assetSlug")
			if err != nil {
				return echo.NewHTTPError(404, "could not find asset")
			}
			asset, err := assetRepository.ReadBySlug(ctx.Request().Context(), nil, project.ID, assetSlug)
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
