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

package listeners

import (
	"context"
	"log/slog"

	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/l3montree-dev/devguard/vexexchange"
	"github.com/l3montree-dev/devguard/vexrules"
	"github.com/lib/pq"
	"github.com/pkg/errors"
	"gorm.io/gorm/clause"
)

const vexRuleExchangeRegistrationKey = "vexrules.exchange.registration"

func (runner *DaemonRunner) RunVEXRuleExchangeSubmitDaemon(ctx context.Context) error {
	if !runner.vexRuleExchangeClient.Enabled() {
		slog.Debug("VEX rule exchange is disabled, skipping the submission")
		return nil
	}

	var rules []models.VEXRule
	if err := runner.vexRuleRepository.GetDB(ctx, nil).
		Where("was_recommended = ? AND enabled = ? AND event_type IN ?", false, true, vexexchange.EventTypes).
		Find(&rules).Error; err != nil {
		return errors.Wrap(err, "failed to fetch VEX rules for the exchange")
	}

	submission := vexrules.PrepareVEXRulesForExchange(rules)
	err := runner.withVEXExchangeRegistration(ctx, func() error {
		return runner.vexRuleExchangeClient.SubmitVEXRules(ctx, submission)
	})
	if err != nil {
		return errors.Wrap(err, "failed to submit VEX rules to the exchange server")
	}
	slog.Info("submitted VEX rules to the exchange server", "rules", len(rules), "submitted", len(submission))
	return nil
}

func (runner *DaemonRunner) RunVEXRuleExchangeFetchDaemon(ctx context.Context) error {
	if !runner.vexRuleExchangeClient.Enabled() {
		slog.Debug("VEX rule exchange is disabled, skipping the fetch")
		return nil
	}

	var recommendations []dtos.VEXExchangeRecommendationDTO
	err := runner.withVEXExchangeRegistration(ctx, func() error {
		var err error
		recommendations, err = runner.vexRuleExchangeClient.FetchRecommendations(ctx)
		return err
	})
	if err != nil {
		return errors.Wrap(err, "failed to fetch recommendations from the exchange server")
	}

	rules, err := vexrules.RecommendationsToVEXExchangeRules(recommendations)
	if err != nil {
		return errors.Wrap(err, "failed to convert the recommendations of the exchange server")
	}
	if len(recommendations) > 0 && len(rules) == 0 {
		return errors.New("no recommendation of the exchange server passed the validation, keeping the stored ones")
	}
	if err := runner.replaceVEXExchangeRules(ctx, rules); err != nil {
		return err
	}
	slog.Info("stored recommendations of the exchange server", "recommendations", len(recommendations), "stored", len(rules))
	return nil
}

func (runner *DaemonRunner) replaceVEXExchangeRules(ctx context.Context, rules []models.VEXExchangeRule) error {
	return runner.db.WithContext(ctx).Transaction(func(tx shared.DB) error {
		ids := utils.Map(rules, func(rule models.VEXExchangeRule) string { return rule.ID })
		if err := tx.Exec(`DELETE FROM vex_exchange_rules WHERE NOT (id = ANY(?))`, pq.Array(ids)).Error; err != nil {
			return errors.Wrap(err, "failed to delete outdated recommendations of the exchange server")
		}
		if len(rules) == 0 {
			return nil
		}
		if err := tx.Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "id"}},
			DoUpdates: clause.AssignmentColumns([]string{"confidence_score"}),
		}).CreateInBatches(rules, 1000).Error; err != nil {
			return errors.Wrap(err, "failed to store recommendations of the exchange server")
		}
		return nil
	})
}

func (runner *DaemonRunner) withVEXExchangeRegistration(ctx context.Context, request func() error) error {
	client := runner.vexRuleExchangeClient
	if !isRegisteredAtVEXExchange(ctx, runner.configService, client.Fingerprint()) {
		if err := client.Register(ctx); err != nil {
			return errors.Wrap(err, "failed to register at the VEX exchange server")
		}
		if err := runner.configService.SetJSONConfig(ctx, vexRuleExchangeRegistrationKey, client.Fingerprint()); err != nil {
			return err
		}
	}
	return request()
}

func isRegisteredAtVEXExchange(ctx context.Context, configService shared.ConfigService, fingerprint string) bool {
	var registeredFingerprint string
	if err := configService.GetJSONConfig(ctx, vexRuleExchangeRegistrationKey, &registeredFingerprint); err != nil {
		if !shared.IsNotFound(err) {
			slog.Warn("could not read the VEX exchange registration, registering again", "err", err)
		}
		return false
	}
	return registeredFingerprint == fingerprint
}
