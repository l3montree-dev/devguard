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

type tenantContextKey struct{}

// WithTenantIDs stores models.TenantIDs in a plain context.Context so that
// repository methods can retrieve them without depending on echo.Context.
func WithTenantIDs(ctx context.Context, ids models.TenantIDs) context.Context {
	return context.WithValue(ctx, tenantContextKey{}, ids)
}

// TenantIDsFromCtx retrieves TenantIDs from ctx.
// Returns (ids, true) when present, (zero-value, false) otherwise.
func TenantIDsFromCtx(ctx context.Context) (models.TenantIDs, bool) {
	ids, ok := ctx.Value(tenantContextKey{}).(models.TenantIDs)
	return ids, ok
}

// TenantIDsFromAsset builds TenantIDs from a fully-resolved asset on the
// echo.Context. ProjectID and OrgID are carried from any existing TenantIDs
// already in the request context so that coarser-grained middleware that ran
// earlier is not lost.
func TenantIDsFromAsset(ctx Context, asset models.Asset) models.TenantIDs {
	existing, _ := TenantIDsFromCtx(ctx.Request().Context())
	existing.AssetID = asset.ID
	if asset.ProjectID != uuid.Nil {
		existing.ProjectID = asset.ProjectID
	}
	return existing
}

// TenantIDsFromProject builds TenantIDs from a fully-resolved project on the
// echo.Context, preserving any OrgID already stored.
func TenantIDsFromProject(ctx Context, project models.Project) models.TenantIDs {
	existing, _ := TenantIDsFromCtx(ctx.Request().Context())
	existing.ProjectID = project.ID
	if project.OrganizationID != uuid.Nil {
		existing.OrgID = project.OrganizationID
	}
	return existing
}

// TenantIDsFromOrg builds TenantIDs from a fully-resolved org on the
// echo.Context.
func TenantIDsFromOrg(_ Context, org models.Org) models.TenantIDs {
	return models.TenantIDs{
		OrgID: org.ID,
	}
}
