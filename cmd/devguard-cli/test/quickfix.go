// Copyright 2026 larshermges @ l3montree GmbH

package main

import (
	"encoding/json"
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

func generalizeAllVersions(resp []byte) [][]string {
	var npmResponseObject NPMResponse

	err := json.Unmarshal(resp, &npmResponseObject)

	if err != nil {
		fmt.Println("Error unmarshalling JSON:", err)
		return nil
	}

	var versions [][]string
	for _, Obj := range npmResponseObject.Versions {
		// skip release candidates since recommending alpha version is not a good idea for security updates haha
		if strings.Contains(Obj.Version, "-") {
			continue
		}
		// split numbers into array to easily compare major versions later
		versionParts := strings.Split(Obj.Version, ".")
		versions = append(versions, versionParts)

	}
	return versions
}

func filterMajorVersions(versionHistory [][]string, currentVersion string) ([]string, error) {
	for i, version := range versionHistory {
		if version[i][0] == currentVersion[0] {
			if version[i][1] >= currentVersion[1] {
				if version[i][2] >= currentVersion[2] {
					fmt.Println("Recommended version: ", version[i])
				}
			}
		} else {
			continue
		}
	}
	return nil, nil
}

func main() {
	DirectDependency := "tar"

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

	filterMajorVersions(generalizeAllVersions(body), "7.4.3")

}
