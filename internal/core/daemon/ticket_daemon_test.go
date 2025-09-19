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

package daemon

import (
	"testing"

	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/utils"
	"github.com/l3montree-dev/devguard/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	gitlab "gitlab.com/gitlab-org/api/client-go"
)

func TestCompareStatesAndResolveDifferences(t *testing.T) {
	t.Run("the same state should result in no changes", func(t *testing.T) {
		depVulnIIDs := []int{57, 42} // we have 2 vulnerabilities in our database
		client := mocks.NewGitlabClientFacade(t)

		asset := models.Asset{
			RepositoryID: utils.Ptr("gitlab:a73edfce-10f6-402d-9073-157cbc220c0f:69787207"),
		}
		projectID := 69787207
		issue1 := gitlab.Issue{IID: 57, State: "opened", Labels: []string{"devguard"}}
		issue2 := gitlab.Issue{IID: 42, State: "opened", Labels: []string{"devguard"}}
		client.On("GetProjectIssues", projectID).Return([]*gitlab.Issue{&issue1, &issue2}, nil)

		err := CompareStatesAndResolveDifferences(client, asset, depVulnIIDs)
		assert.Nil(t, err)
	})
	t.Run("if we have 2 excess tickets we should close these tickets", func(t *testing.T) {
		depVulnIIDs := []int{} // we have 2 vulnerabilities in our database
		client := mocks.NewGitlabClientFacade(t)

		asset := models.Asset{
			RepositoryID: utils.Ptr("gitlab:a73edfce-10f6-402d-9073-157cbc220c0f:69787207"),
		}
		projectID := 69787207
		issue1 := gitlab.Issue{IID: 57, State: "opened", Labels: []string{"devguard"}}
		issue2 := gitlab.Issue{IID: 42, State: "opened", Labels: []string{"devguard"}}

		client.On("GetProjectIssues", projectID).Return([]*gitlab.Issue{&issue1, &issue2}, nil)
		client.On("EditIssue", mock.Anything, projectID, 57, mock.Anything).Return(nil, nil, nil)
		client.On("EditIssue", mock.Anything, projectID, 42, mock.Anything).Return(nil, nil, nil)

		err := CompareStatesAndResolveDifferences(client, asset, depVulnIIDs)
		assert.Nil(t, err)

	})
	t.Run("if we provide an invalid repository id we should fail", func(t *testing.T) {
		depVulnIIDs := []int{} // we have 2 vulnerabilities in our database
		client := mocks.NewGitlabClientFacade(t)

		asset := models.Asset{
			RepositoryID: utils.Ptr("gitlaba73edfce-10f6-402d-9073-157cbc220c0f6978720d7"),
		}

		err := CompareStatesAndResolveDifferences(client, asset, depVulnIIDs)
		assert.Equal(t, "invalid repository id (gitlaba73edfce-10f6-402d-9073-157cbc220c0f6978720d7)", err.Error())
	})
	t.Run("if we use another integration than gitlab, we should get no error but wont do any function calls", func(t *testing.T) {
		depVulnIIDs := []int{} // we have 2 vulnerabilities in our database
		client := mocks.NewGitlabClientFacade(t)

		asset := models.Asset{
			RepositoryID: utils.Ptr("gitschlapp:a73edfce-10f6-402d-9073-157cbc220c0f6978720d7"),
		}

		err := CompareStatesAndResolveDifferences(client, asset, depVulnIIDs)
		assert.Nil(t, err)
	})
}
