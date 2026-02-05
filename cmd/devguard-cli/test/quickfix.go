// Copyright 2026 larshermges @ l3montree GmbH

package test

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
	"net/http"
	"github.com/l3montree-dev/devguard/cmd/devguard-cli/commands"
)

func getPackageManager(Package string) string {
	// insert future Package Managers later
	switch Package {
	case "npm", "yarn", "pnpm":
		return "node"
	case "pip", "pipenv", "poetry":
		return "python"
	}
}

func fetchAllPackageRegistryData(DirectDependency string, packageManager string) (string, error) {
	switch packageManager {
	case "node":
		// http request
		return ""
	}
}

func getAllVersions(DirectDependency string, packageManager string) []string {
	fmt.Printf(DirectDependency, packageManager)
}
