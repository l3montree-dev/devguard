// Copyright 2026 larshermges @ l3montree GmbH

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

type VersionData struct {
	Name         string     `json:"name"`
	Version      string     `json:"version"`
	Keywords     []string   `json:"keywords"`
	Author       Person     `json:"author"`
	License      string     `json:"license"`
	Id           string     `json:"_id"`
	Maintainers  []Person   `json:"maintainers"`
	Contributors []Person   `json:"contributors"`
	Homepage     string     `json:"homepage"`
	Bugs         Bugs       `json:"bugs"`
	Jam          []string   `json:"jam"`
	Dist         Dist       `json:"dist"`
	Main         string     `json:"main"`
	From         string     `json:"from"`
	Engines      []string   `json:"engines"`
	NpmUser      Person     `json:"_npmUser"`
	Repository   Repository `json:"repository"`
	NpmVersion   string     `json:"_npmVersion"`
	Description  string     `json:"description"`
	Directories  []string   `json:"directories"`

	// ... weitere Felder...
}

type Person struct {
	URL   string `json:"url"`
	Name  string `json:"name"`
	Email string `json:"email"`
}

type Bugs struct {
	URL string `json:"url"`
}

type Dist struct {
	Shasum     string       `json:"shasum"`
	Tarball    string       `json:"tarball"`
	Integrity  string       `json:"integrity"`
	Signatures []Signatures `json:"signatures"`
}

type Repository struct {
	URL  string `json:"url"`
	Type string `json:"type"`
}

type Signatures struct {
	Sig   string `json:"sig"`
	KeyId string `json:"keyid"`
}

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

	var npmResponseObject VersionData

	json.Unmarshal(body, &npmResponseObject)
	fmt.Println(npmResponseObject.Maintainers)
	// fmt.Println(string(body))
}
