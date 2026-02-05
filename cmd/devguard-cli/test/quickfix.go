// Copyright 2026 larshermges @ l3montree GmbH

package main

import (
	"fmt"
	"io"
	"net/http"
)

var DirectDependency string = "lodash"

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

func getAllVersions(DirectDependency string, packageManager string, version *string) (*http.Response, error) {

	switch packageManager {
	case "node":
		return GetNPMRegistry(DirectDependency, packageManager, nil)
	case "crates":
		return GetCratesRegistry(DirectDependency, packageManager, nil)
	}
	// add more in the future
	return nil, nil
}

func main() {
	resp, err := getVersions(DirectDependency, getPackageManager("npm"))
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
	fmt.Println("Response:", string(body))
}
