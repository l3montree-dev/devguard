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

// single node in the dependency tree
type DependencyNode struct {
	Name         string
	Version      string
	Dependencies map[string]*DependencyNode
}

func caretHandler(version string) string {
	//version range detection:
	// example
	/*
		| Dependency               | Caret Range | Actual Range |
		| ------------------------ | ----------- | ------------------- |
		| socks-proxy-agent@^7.0.0 | ^7.0.0      | >=7.0.0 <8.0.0      |
		| debug@^4.3.3             | ^4.3.3      | >=4.3.3 <5.0.0      |
		| ip@^1.1.5                | ^1.1.5      | >=1.1.5 <2.0.0      |
		| test@^0.2.3              | ^0.0.1      | >= 0.2.3 < 0.3.0    |
		caret applies to the most left non-zero digit in the version
	*/
}

func walkDependencyTree(npmRegisterResp []byte, depName string, depVersion string, visited map[string]bool, vulnerablePackage string, vulnerableVersion string) *DependencyNode {
	var jsonData NPMResponse

	if err := json.Unmarshal(npmRegisterResp, &jsonData); err != nil {
		// fmt.Println("Error unmarshalling JSON:", err)
		return nil
	}

	nodeKey := depName + "@" + depVersion
	if visited[nodeKey] {
		return nil
	}
	visited[nodeKey] = true

	node := &DependencyNode{
		Name:         depName,
		Version:      depVersion,
		Dependencies: make(map[string]*DependencyNode),
	}

	if jsonData.Dependencies == nil {
		//fmt.Printf("No dependencies found for %s@%s\n", depName, depVersion)
		return node
	}

	for depKey, depVal := range jsonData.Dependencies {
		//fmt.Printf("Fetching dependency: %s@%s\n", depKey, depVal)

		depResp, err := GetNPMRegistry(RegistryRequest{Dependency: depKey, Version: depVal})
		if err != nil {
			fmt.Printf("Error fetching %s@%s: %v\n", depKey, depVal, err)
			continue
		}

		depBody, err := io.ReadAll(depResp.Body)
		depResp.Body.Close()
		if err != nil {
			fmt.Printf("Error reading response for %s@%s: %v\n", depKey, depVal, err)
			continue
		}

		// Recursive call
		childNode := walkDependencyTree(depBody, depKey, depVal, visited, vulnerablePackage, vulnerableVersion)
		if childNode != nil {
			node.Dependencies[depKey] = childNode
		}
	}

	return node
}

// func printDependencyTree(node *DependencyNode, indent string) {
// 	if node == nil {
// 		return
// 	}

// 	fmt.Printf("%s%s@%s\n", indent, node.Name, node.Version)

// 	for _, dep := range node.Dependencies {
// 		printDependencyTree(dep, indent+"  ")
// 	}
// }

func main() {
	DirectDependency := "make-fetch-happen"
	currentVersion := "10.1.6"
	vulnerablePackage := "ip"
	vulnerableVersion := "1.1.5"
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

	versions, err := filterMajorVersions(generalizeAllVersions(body), currentVersion)
	if err != nil {
		fmt.Println("Error filtering versions:", err)
		return
	}

	for _, version := range versions {
		npmResponse, err := GetNPMRegistry(RegistryRequest{Dependency: DirectDependency, Version: version})
		if err != nil {
			fmt.Println("Error fetching version details:", err)
			continue
		}

		response, err := io.ReadAll(npmResponse.Body)
		npmResponse.Body.Close()
		if err != nil {
			fmt.Println("Error reading response:", err)
			continue
		}

		// Build dependency tree recursively
		visited := make(map[string]bool)
		tree := walkDependencyTree(response, DirectDependency, version, visited, vulnerablePackage, vulnerableVersion)

		fmt.Println(tree)
		for _, dep := range tree.Dependencies {
			fmt.Println(dep)
		}
	}
}
