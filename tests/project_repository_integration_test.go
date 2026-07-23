// Copyright (C) 2026 l3montree GmbH
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

package tests

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/database/repositories"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProjectRepositoryUpsertSplitReturnsIDForUpdatedProject(t *testing.T) {
	db, _, terminate := InitDatabaseContainer("../initdb.sql")
	defer terminate()

	org := models.Org{Name: "External sync test", Slug: "external-sync-test"}
	require.NoError(t, db.Create(&org).Error)

	providerID := "gitlab"
	externalEntityID := "group-123"
	repo := repositories.NewProjectRepository(db)
	ctx := context.Background()

	firstSyncProject := &models.Project{
		Name:                     "Original name",
		Slug:                     "external-project",
		OrganizationID:           org.ID,
		ExternalEntityProviderID: &providerID,
		ExternalEntityID:         &externalEntityID,
	}
	created, updated, err := repo.UpsertSplit(ctx, nil, providerID, []*models.Project{firstSyncProject})
	require.NoError(t, err)
	require.Len(t, created, 1)
	require.Empty(t, updated)
	require.NotEqual(t, uuid.Nil, created[0].ID)
	persistedID := created[0].ID

	secondSyncProject := &models.Project{
		Name:                     "Updated name",
		Slug:                     "external-project",
		OrganizationID:           org.ID,
		ExternalEntityProviderID: &providerID,
		ExternalEntityID:         &externalEntityID,
	}
	created, updated, err = repo.UpsertSplit(ctx, nil, providerID, []*models.Project{secondSyncProject})

	require.NoError(t, err)
	require.Empty(t, created)
	require.Len(t, updated, 1)
	assert.Equal(t, persistedID, updated[0].ID)
	assert.NotEqual(t, uuid.Nil, updated[0].ID)
}
