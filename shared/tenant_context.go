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

package shared

import (
	"context"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
)

type ownershipScopeKey struct{}

// WithOwnershipScope stores models.OwnershipScope in a plain context.Context so
// that repository methods can retrieve it without depending on echo.Context.
func WithOwnershipScope(ctx context.Context, scope models.OwnershipScope) context.Context {
	return context.WithValue(ctx, ownershipScopeKey{}, scope)
}

// OwnershipScopeFromCtx retrieves an OwnershipScope from ctx.
// Returns (scope, true) when present, (zero-value, false) otherwise.
func OwnershipScopeFromCtx(ctx context.Context) (models.OwnershipScope, bool) {
	scope, ok := ctx.Value(ownershipScopeKey{}).(models.OwnershipScope)
	return scope, ok
}

// OwnershipScopeFromAsset builds an OwnershipScope from a fully-resolved asset
// on the echo.Context. ProjectID and OrgID are carried from any existing scope
// already in the request context so that coarser-grained middleware that ran
// earlier is not lost.
func OwnershipScopeFromAsset(ctx Context, asset models.Asset) models.OwnershipScope {
	existing, _ := OwnershipScopeFromCtx(ctx.Request().Context())
	existing.AssetID = asset.ID
	if asset.ProjectID != uuid.Nil {
		existing.ProjectID = asset.ProjectID
	}
	return existing
}

// OwnershipScopeFromProject builds an OwnershipScope from a fully-resolved
// project, preserving any OrgID already stored.
func OwnershipScopeFromProject(ctx Context, project models.Project) models.OwnershipScope {
	existing, _ := OwnershipScopeFromCtx(ctx.Request().Context())
	existing.ProjectID = project.ID
	if project.OrganizationID != uuid.Nil {
		existing.OrgID = project.OrganizationID
	}
	return existing
}

// OwnershipScopeFromOrg builds an OwnershipScope from a fully-resolved org.
func OwnershipScopeFromOrg(_ Context, org models.Org) models.OwnershipScope {
	return models.OwnershipScope{
		OrgID: org.ID,
	}
}
