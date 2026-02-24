// Copyright 2026 larshermges
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"fmt"
	"net/http"

	"github.com/package-url/packageurl-go"
)

func GetCratesRegistry(pkg packageurl.PackageURL) (*http.Response, error) {
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
