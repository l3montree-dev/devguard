// Copyright 2026 larshermges @ l3montree GmbH

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

func timeoutDetection(err error) {
	// check if error is a timeout error
}

// VersionExists checks if a package version exists on npm registry
func VersionExists(dependency string, version string) bool {
	normalizedVersion := strings.Trim(version, "/^\"")
	url := "https://registry.npmjs.org/" + dependency + "/" + normalizedVersion

	resp, err := http.Head(url)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	return resp.StatusCode == 200
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
		return nil, err
	}

	if req.StatusCode != 200 {
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
		return nil, err
	}

	if req.StatusCode != 200 {
		return nil, fmt.Errorf("failed to fetch data for %s: %s", pkg.Dependency, req.Status)
	}
	return req, nil
}

// func getMavenRegistry(DirectDependency string, packageManager string) (*http.Response, error) {
// insert http request for maven registry here later
// }
