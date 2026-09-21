// Copyright (C) 2025 l3montree GmbH
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

package monitoring

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/getsentry/sentry-go"
	"github.com/google/uuid"
	"github.com/pkg/errors"
	"gorm.io/gorm"
)

type AlertLogService interface {
	SaveLog(ctx context.Context, tx *gorm.DB, orgID, projectID, assetID *uuid.UUID, message string) error
}

type AlertOptions struct {
	OrgID     uuid.UUID
	ProjectID uuid.UUID
	AssetID   uuid.UUID
}

var logger AlertLogService

func SetLogger(ls AlertLogService) {
	logger = ls
}

func Alert(message string, err error) {
	// log it
	evID := sentry.CurrentHub().CaptureException(errors.Wrap(err, message))
	if evID == nil {
		slog.Error("critical error encountered - not sent to external error tracking", "msg", message, "error", err)
	} else {
		slog.Error("critical error encountered", "msg", message, "error", err, "id", *evID)
	}
}

func SaveAlertInErrorLog(ctx context.Context, tx *gorm.DB, opts AlertOptions, message string, err error) {
	if logger == nil {
		slog.Error("could not store error in database", "msg", "logger has not been set yet")
		return
	}
	storedMsg := message
	if err != nil {
		storedMsg = fmt.Sprintf("%s: %v", message, err)
	}
	loggerErr := logger.SaveLog(ctx, tx, &opts.OrgID, &opts.ProjectID, &opts.AssetID, storedMsg)
	if loggerErr != nil {
		slog.Error("could not store error in database", "msg", message, "err", loggerErr)
	}
}

func AlertAndSaveInErrorLog(ctx context.Context, tx *gorm.DB, opts AlertOptions, message string, err error) {
	Alert(message, err)
	SaveAlertInErrorLog(ctx, tx, opts, message, err)
}

func RecoverAndAlert(ctx context.Context, tx *gorm.DB, opts AlertOptions, message string, err error) {
	evID := sentry.CurrentHub().Recover(err)
	slog.Error("critical error encountered (recover)", "msg", message, "error", err, "id (<nil> if not sent to error tracking)", evID)
	sentry.Flush(10 * time.Second)
	if logger == nil {
		slog.Error("could not store error in database", "msg", "logger has not been set yet")
		return
	}
	storedMsg := message
	if err != nil {
		storedMsg = fmt.Sprintf("%s: %v", message, err)
	}
	loggerErr := logger.SaveLog(ctx, tx, &opts.OrgID, &opts.ProjectID, &opts.AssetID, storedMsg)
	if loggerErr != nil {
		slog.Error("could not store error in database", "msg", message, "err", loggerErr)
	}
}

func RecoverPanic(ctx context.Context, tx *gorm.DB, opts AlertOptions, msg string) {
	if r := recover(); r != nil {
		AlertAndSaveInErrorLog(ctx, tx, opts, msg, fmt.Errorf("panic recovered: %v", r))
	}
}
