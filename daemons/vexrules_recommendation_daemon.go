package daemons

import (
	"context"

	"github.com/l3montree-dev/devguard/shared"
)

func (runner *DaemonRunner) RunVEXRuleRecommendationDaemon(ctx context.Context) error {
	return runner.db.WithContext(ctx).Transaction(func(tx shared.DB) error {
		return runner.vexRuleService.BuildAndSaveRecommendationsForAll(ctx, tx)
	})
}
