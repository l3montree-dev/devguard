package controllers

import (
	"encoding/json"
	"fmt"

	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/labstack/echo/v4"
)

// dependencyProxyConfigFileID is the key under which dependency-proxy settings
// are stored in an org/project/asset ConfigFiles map.
const dependencyProxyConfigFileID = "dependency-proxy-configs"

// validateConfigFile validates a config-file payload before it is persisted.
// Only config files with known schemas are checked; unknown ones pass through.
func validateConfigFile(configID string, content []byte) error {
	if configID != dependencyProxyConfigFileID || len(content) == 0 {
		return nil
	}

	var cfg dtos.DependencyProxyConfig
	if err := json.Unmarshal(content, &cfg); err != nil {
		return echo.NewHTTPError(400, "invalid dependency proxy config").WithInternal(err)
	}
	if err := shared.V.Struct(cfg); err != nil {
		return echo.NewHTTPError(400, fmt.Sprintf("could not validate request: %s", err.Error()))
	}
	return nil
}
