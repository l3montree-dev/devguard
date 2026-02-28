// Copyright (C) 2026 l3montree GmbH
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package main

import (
	"fmt"
	"net/http"

	"github.com/package-url/packageurl-go"
)

func getCratesRegistry(pkg packageurl.PackageURL) (*http.Response, error) {
	var req *http.Response
	var err error

	if pkg.Version != "" {
		req, err = httpClient.Get("https://crates.io/api/v1/crates/" + pkg.Name + "/" + pkg.Version)
	} else {
		req, err = httpClient.Get("https://crates.io/api/v1/crates/" + pkg.Name)
	}

	if err != nil {
		if req != nil {
			req.Body.Close()
		}
		return nil, err
	}

	if req.StatusCode != 200 {
		req.Body.Close()
		return nil, fmt.Errorf("failed to fetch data for %s: %s", pkg.Name, req.Status)
	}
	return req, nil

}
