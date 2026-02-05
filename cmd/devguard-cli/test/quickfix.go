// Copyright 2026 larshermges @ l3montree GmbH

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

type NPMResponse struct {
	Id             string          `json:"_id"`
	Rev            string          `json:"_rev"`
	Name           string          `json:"name"`
	Description    string          `json:"description"`
	distTags       DistTags        `json:"dist-tags"`
	Versions       []VersionData   `json:"versions"`
	Time           string          `json:"time"`
	Bugs           Bugs            `json:"bugs"`
	Author         Person          `json:"author"`
	License        string          `json:"license"`
	Homepage       string          `json:"homepage"`
	Keywords       []string        `json:"keywords"`
	Repository     Repository      `json:"repository"`
	Contributors   []Person        `json:"contributors"`
	Maintainers    []Person        `json:"maintainers"`
	ReadMe         string          `json:"readme"`
	ReadMeFilename string          `json:"readmeFilename"`
	Users          map[string]bool `json:"users"`
}

type DistTags struct {
	Latest string `json:"latest"`
}

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

func filterMajorVersions(resp []byte) []string {
	var npmResponseObject NPMResponse

	json.Unmarshal(resp, &npmResponseObject)

	for range npmResponseObject.Versions {

		fmt.Println("Version:", npmResponseObject.Versions[0].Version)

		return nil
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

	// fmt.Println(string(body))
}
