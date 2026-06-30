package daemons

import (
	"context"
	"log/slog"
	"os"
	"strings"

	"github.com/l3montree-dev/devguard/normalize"
)

func (runner *DaemonRunner) UpdateSystemVEXRulesFromOpenVEXSources(ctx context.Context) error {
	enviromentSources := os.Getenv("OPENVEX_SOURCES")
	if enviromentSources == "" {
		slog.Info("no OpenVEX sources set in env variables, skipped fetching OpenVEX from static sources")
		return nil
	}
	staticOpenVEXSources := strings.Split(os.Getenv("OPENVEX_SOURCES"), ",")
	if len(staticOpenVEXSources) == 0 {
		slog.Info("no OpenVEX sources set in env variables, skipped fetching OpenVEX from static sources")
		return nil
	}

	slog.Info("fetching OpenVEX from static sources")
	var results []*normalize.VexReportOpenVEX
	for _, source := range staticOpenVEXSources {
		reports, err := runner.scanService.FetchOpenVexFromGitHub(ctx, source, "main")
		if err != nil {
			slog.Error("failed to fetch OpenVEX report from static source", "source", source, "error", err)
			continue
		}
		results = append(results, reports...)
	}

	err := runner.vexRuleService.UpdateSystemVEXRulesFromStaticSources(ctx, results)

	if err != nil {
		slog.Error("failed to update VEX rules from static sources", "error", err)
		return err
	}

	return nil
}
