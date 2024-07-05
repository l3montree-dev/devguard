// Copyright (C) 2024 Tim Bastin, l3montree UG (haftungsbeschränkt)
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

package integrations

import (
	"context"

	"github.com/google/go-github/v62/github"
	"github.com/l3montree-dev/devguard/internal/utils"
)

type githubOrgClient struct {
	clients []*github.Client
}

func (githubOrgClient *githubOrgClient) ListRepositories() ([]*github.Repository, error) {
	wg := utils.ErrGroup[[]*github.Repository](10)

	for _, client := range githubOrgClient.clients {
		wg.Go(func() ([]*github.Repository, error) {
			result, _, err := client.Apps.ListRepos(context.Background(), nil)
			if err != nil {
				return nil, err
			}
			return result.Repositories, nil
		})
	}

	results, err := wg.WaitAndCollect()
	if err != nil {
		return nil, err
	}
	return utils.Flat(results), nil
}
