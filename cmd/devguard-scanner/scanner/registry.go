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

package scanner

import (
	"context"

	"oras.land/oras-go/v2/registry"
	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"
	"oras.land/oras-go/v2/registry/remote/credentials"
)

func Login(ctx context.Context, username, password, registryURL string) error {
	store, err := credentials.NewStoreFromDocker(credentials.StoreOptions{
		AllowPlaintextPut:        true,
		DetectDefaultNativeStore: true,
	})
	if err != nil {
		return err
	}

	return credentials.Login(ctx, store, &remote.Registry{
		RepositoryOptions: remote.RepositoryOptions{
			Reference: registry.Reference{
				Registry: registryURL,
			},
		},
	}, auth.Credential{
		Username: username,
		Password: password,
	})
}
