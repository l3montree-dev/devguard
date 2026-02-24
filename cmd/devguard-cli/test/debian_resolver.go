// Copyright 2026 larshermges
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	https://www.apache.org/licenses/LICENSE-2.0
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
	"strings"

	"github.com/package-url/packageurl-go"
)

type DebianResolver struct{}

// CheckIfVulnerabilityIsFixed implements [Resolver].
func (d *DebianResolver) CheckIfVulnerabilityIsFixed(vulnVersion string, fixedVersion string) bool {
	panic("unimplemented")
}

// FetchPackageMetadata implements [Resolver].
func (d *DebianResolver) FetchPackageMetadata(purl packageurl.PackageURL) (DebianResponse, error) {
	panic("unimplemented")
}

// FindDependencyVersionInMeta implements [Resolver].
func (d *DebianResolver) FindDependencyVersionInMeta(depMeta DebianResponse, pkgName string) VersionConstraint {
	panic("unimplemented")
}

// GetRecommendedVersions implements [Resolver].
func (d *DebianResolver) GetRecommendedVersions(allVersionsMeta DebianResponse, currentVersion string) ([]string, error) {
	panic("unimplemented")
}

// ResolveBestVersion implements [Resolver].
func (d *DebianResolver) ResolveBestVersion(allVersionsMeta DebianResponse, versionConstraint VersionConstraint, currentVersion string) (string, error) {
	panic("unimplemented")
}

type DebianResponse struct{}

var _ Resolver[DebianResponse] = &DebianResolver{}

func GetDebRegistry(pkg packageurl.PackageURL) (*http.Response, error) {
	var req *http.Response
	var err error
	// pkg:deb/debian/apt@2.6.1A~5.2.0.202311171811?arch=amd64&distro=debian-12.8

	if pkg.Version != "" {
		req, err = httpClient.Get("https://sources.debian.org/data/main/" + debianPrefix(pkg.Name) + "/" + pkg.Name + "/" + pkg.Version + "/debian/control")
	} else {
		req, err = httpClient.Get("https://snapshot.debian.org/mr/package/" + pkg.Name)
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

func debianPrefix(pkgName string) string {

	runes := []rune(pkgName)

	// special rule for lib* packages
	if strings.HasPrefix(pkgName, "lib") && len(runes) > 3 {
		return "lib" + string(runes[3])
	}

	// default: first rune
	return string(runes[0])
}
