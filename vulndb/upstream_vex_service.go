// Copyright (C) 2026 l3montree GmbH
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.
package vulndb

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/jackc/pgx/v5"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/shared"
)

var upstreamSources = []string{"https://github.com/rancher/vexhub"}

func FetchVexRulesFromGitHubSources(ctx context.Context, ghVexFetcher shared.GitHubVexFetcher) ([]models.UpstreamVEXRule, error) {
	rules := make([]models.UpstreamVEXRule, 0, len(upstreamSources)*100)
	for _, source := range upstreamSources {
		slog.Info("fetching system VEX rules from GitHub source", "source", source)
		r, err := ghVexFetcher.FetchVexFromGitHub(ctx, source, "main")
		if err != nil {
			return nil, err
		}
		rules = append(rules, r...)
	}

	return rules, nil
}

// insertSystemVexRulesBulk streams system VEX rules into the given staging table
// (created up front by CreateStagingTables). Call flushUpstreamVEXRulesStagingTable
// (export path, where the live table is already truncated) or SyncAllTables
// (import path, EXCEPT-based sync against a possibly non-empty live table) once
// afterwards.
func insertSystemVexRulesBulk(ctx context.Context, tx pgx.Tx, rules []models.UpstreamVEXRule, table string) error {
	if len(rules) == 0 {
		return nil
	}

	// Deduplicate by ID - postgres cannot affect the same row twice within a
	// single INSERT ... ON CONFLICT DO UPDATE statement (SQLSTATE 21000), and
	// duplicate ids across GitHub sources would otherwise violate the primary key.
	seen := make(map[string]struct{}, len(rules))
	deduped := make([]models.UpstreamVEXRule, 0, len(rules))
	for i := range rules {
		rules[i].EnsureID()
		if _, ok := seen[rules[i].ID]; ok {
			continue
		}
		seen[rules[i].ID] = struct{}{}
		deduped = append(deduped, rules[i])
	}

	if _, err := tx.CopyFrom(ctx, pgx.Identifier{table},
		[]string{"id", "vex_source", "title", "justification", "mechanical_justification", "event_type", "cel_expression"},
		pgx.CopyFromSlice(len(deduped), func(i int) ([]any, error) {
			r := deduped[i]
			return []any{r.ID, r.VexSource, r.Title, r.Justification, string(r.MechanicalJustification), string(r.EventType), r.CELExpression}, nil
		})); err != nil {
		return fmt.Errorf("could not copy system vex rules into staging table: %w", err)
	}

	return nil
}

// flushUpstreamVEXRulesStagingTable performs a plain insert from upstream_vex_rules_stage
// into the live table. Only valid on the export path, where upstream_vex_rules was
// already truncated by truncateUpstreamVEXRules.
func flushUpstreamVEXRulesStagingTable(ctx context.Context, tx pgx.Tx) error {
	if _, err := tx.Exec(ctx, `
		INSERT INTO upstream_vex_rules (id, vex_source, title, justification, mechanical_justification, event_type, cel_expression, created_at, updated_at)
		SELECT id, vex_source, title, justification, mechanical_justification, event_type, cel_expression, now(), now()
		FROM upstream_vex_rules_stage`); err != nil {
		return fmt.Errorf("could not flush system vex rules: %w", err)
	}
	return nil
}
