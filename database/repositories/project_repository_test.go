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

package repositories

import (
	"testing"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAssignPersistedProjectIDs(t *testing.T) {
	providerID := "gitlab"
	createdExternalID := "created"
	updatedExternalID := "updated"
	createdID := uuid.New()
	updatedID := uuid.New()

	projects := []*models.Project{
		{ExternalEntityProviderID: &providerID, ExternalEntityID: &createdExternalID},
		{ExternalEntityProviderID: &providerID, ExternalEntityID: &updatedExternalID},
	}
	persistedProjects := []models.Project{
		{Model: models.Model{ID: updatedID}, ExternalEntityID: &updatedExternalID},
		{Model: models.Model{ID: createdID}, ExternalEntityID: &createdExternalID},
	}

	err := assignPersistedProjectIDs(projects, persistedProjects)

	require.NoError(t, err)
	assert.Equal(t, createdID, projects[0].ID)
	assert.Equal(t, updatedID, projects[1].ID)
}

func TestAssignPersistedProjectIDsRejectsMissingProject(t *testing.T) {
	externalID := "missing"
	projects := []*models.Project{{ExternalEntityID: &externalID}}

	err := assignPersistedProjectIDs(projects, nil)

	require.Error(t, err)
	assert.Contains(t, err.Error(), externalID)
	assert.Equal(t, uuid.Nil, projects[0].ID)
}
