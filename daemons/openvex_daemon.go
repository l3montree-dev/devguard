package daemons

import (
	"context"
	"log/slog"
	"os"
	"strings"

	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/services"
)

func (runner *DaemonRunner) UpdateSystemVEXRulesFromGitHubSources(ctx context.Context) error {
	enviromentSources := os.Getenv("GITHUB_SOURCES")
	if enviromentSources == "" {
		slog.Info("no OpenVEX sources set in env variables, skipped fetching OpenVEX from static sources")
		return nil
	}
	staticOpenVEXSources := strings.Split(os.Getenv("GITHUB_SOURCES"), ",")
	if len(staticOpenVEXSources) == 0 {
		slog.Info("no OpenVEX sources set in env variables, skipped fetching OpenVEX from static sources")
		return nil
	}

	slog.Info("fetching OpenVEX from static sources")
	rules := make([]models.SystemVEXRule, 0, len(staticOpenVEXSources)*100)
	for _, source := range staticOpenVEXSources {
		r, err := services.FetchVexFromGitHub(ctx, source, "main")
		if err != nil {
			slog.Error("failed to fetch OpenVEX report from static source", "source", source, "error", err)
			continue
		}
		rules = append(rules, r...)
	}

	return nil
}
