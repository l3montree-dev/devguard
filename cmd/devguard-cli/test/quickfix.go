// Copyright 2026 larshermges @ l3montree GmbH

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

func getPackageManager(Package string) string {
	// insert future Package Managers later
	switch Package {

	case "npm", "yarn", "pnpm":
		return "node"

	case "pip", "pipenv", "poetry":
		return "python"

	case "cargo":
		return "crates"
	}
	return "unknown"
}

func getVersion(packageManager string, pkg RegistryRequest) (*http.Response, error) {

	switch packageManager {
	case "node":
		return GetNPMRegistry(pkg)
	case "crates":
		return GetCratesRegistry(pkg)
	}
	// add more in the future
	return nil, nil
}

func filterMajorVersions(resp []byte) []string {
	var npmResponseObject NPMResponse

	err := json.Unmarshal(resp, &npmResponseObject)

	if err != nil {
		fmt.Println("Error unmarshalling JSON:", err)
		return nil
	}

	for _, Obj := range npmResponseObject.Versions {
		fmt.Println(Obj.Version)
	}
	return nil
}

func main() {
	DirectDependency := "lodash"

	resp, err := getVersion(getPackageManager("npm"), RegistryRequest{Dependency: DirectDependency})
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error reading body:", err)
		return
	}
	defer resp.Body.Close()

	filterMajorVersions(body)

}
