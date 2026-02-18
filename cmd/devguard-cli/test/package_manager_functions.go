// Copyright 2026 lars hermges @ l3montree GmbH

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

package main

import (
	"fmt"
	"net/http"
	"strings"
)

type RegistryRequest struct {
	Dependency string
	Version    string // empty string means "all versions"
}

// get all versions if no version is specified
func GetNPMRegistry(pkg RegistryRequest) (*http.Response, error) {
	var req *http.Response
	var err error

	normalizedVersion := strings.Trim(pkg.Version, "/") // remove quotes if present

	if pkg.Version != "" {
		req, err = http.Get("https://registry.npmjs.org/" + pkg.Dependency + "/" + normalizedVersion)
	} else {
		req, err = http.Get("https://registry.npmjs.org/" + pkg.Dependency)
	}

	if err != nil {
		if req != nil {
			defer req.Body.Close()
		}
		return nil, err
	}

	if req.StatusCode != 200 {
		defer req.Body.Close()
		return nil, fmt.Errorf("failed to fetch data for %s: %s", pkg.Dependency, req.Status)
	}
	return req, nil
}

func GetCratesRegistry(pkg RegistryRequest) (*http.Response, error) {
	var req *http.Response
	var err error

	if pkg.Version != "" {
		req, err = http.Get("https://crates.io/api/v1/crates/" + pkg.Dependency + "/" + pkg.Version)
	} else {
		req, err = http.Get("https://crates.io/api/v1/crates/" + pkg.Dependency)
	}

	if err != nil {
		if req != nil {
			defer req.Body.Close()
		}
		return nil, err
	}

	if req.StatusCode != 200 {
		defer req.Body.Close()
		return nil, fmt.Errorf("failed to fetch data for %s: %s", pkg.Dependency, req.Status)
	}
	return req, nil
}

// func getMavenRegistry(DirectDependency string, packageManager string) (*http.Response, error) {
// insert http request for maven registry here later
// }
