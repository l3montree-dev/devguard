// Copyright 2026 larshermges @ l3montree GmbH

package main

import (
	"fmt"
	"net/http"
)

// get all versions if no version is specified
func GetNPMRegistry(DirectDependency string, packageManager string, version *string) (*http.Response, error) {
	var req *http.Response
	var err error

	if version != nil {
		req, err = http.Get("https://registry.npmjs.org/" + DirectDependency + "/" + *version)
	} else {
		req, err = http.Get("https://registry.npmjs.org/" + DirectDependency)
	}

	if err != nil {
		return nil, err
	}

	if req.StatusCode != 200 {
		return nil, fmt.Errorf("failed to fetch data for %s: %s", DirectDependency, req.Status)
	}
	return req, nil
}

func GetCratesRegistry(DirectDependency string, packageManager string, version *string) (*http.Response, error) {
	var req *http.Response
	var err error

	if version != nil {
		req, err = http.Get("https://crates.io/api/v1/crates/" + DirectDependency + "/" + *version)
	} else {
		req, err = http.Get("https://crates.io/api/v1/crates/" + DirectDependency)
	}

	if err != nil {
		return nil, err
	}

	if req.StatusCode != 200 {
		return nil, fmt.Errorf("failed to fetch data for %s: %s", DirectDependency, req.Status)
	}
	return req, nil
}

// func getMavenRegistry(DirectDependency string, packageManager string) (*http.Response, error) {
// insert http request for maven registry here later
// }
