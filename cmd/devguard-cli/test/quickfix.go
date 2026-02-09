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
	currentParts := strings.Split(currentVersion, ".")
	var recommended []string

	for _, version := range versionHistory {
		if version[0] == currentParts[0] {
			if version[1] >= currentParts[1] {
				if version[2] >= currentParts[2] {
					// fmt.Println(strings.Join(version, "."))
					recommended = append(recommended, strings.Join(version, "."))
				}
			}
		}
	}
	fmt.Println(recommended)
	return recommended, nil
}

func walkDependencyTree(npmRegisterResp []byte) map[string]string {
	var jsonData NPMResponse

	if err := json.Unmarshal(npmRegisterResp, &jsonData); err != nil {
		fmt.Println("Error unmarshalling JSON:", err)
		return nil
	}
	// fmt.Println(jsonData)
	fmt.Println(jsonData.Dependencies)
	for jsonData.Dependencies != nil {
		for key, value := range jsonData.Dependencies {
			fmt.Printf("Dependency: %s, Version: %s\n", key, value)
	return jsonData.Dependencies
}

func main() {
	DirectDependency := "playwright"

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

	versions, err := filterMajorVersions(generalizeAllVersions(body), "1.50.1")
	if err != nil {
		fmt.Println("Error filtering versions:", err)
		return
	}
	for _, version := range versions {

		npmResponse, err := GetNPMRegistry(RegistryRequest{Dependency: DirectDependency, Version: version})
		response, err := io.ReadAll(npmResponse.Body)
		fmt.Println(string(response))
		if err != nil {
			fmt.Println("Error fetching version details:", err)
			continue
		}
		walkDependencyTree(response)

		}
	}
}
