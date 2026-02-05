// Copyright 2026 larshermges @ l3montree GmbH

package main

import (
	"fmt"
	"io"
	"net/http"
	"strings"
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

func filterMajorVersions(version string) []string {
	for range version {
		if strings.Contains(version, "-") {
			continue
		}
		versionArray := strings.Split(version, ".")[0]
		for range versionArray[0] {
			// if versionArray[0] == "" {
			fmt.Println(versionArray[0])

			return nil
		}
	}
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

	fmt.Println(string(body))
}
