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

type LogService interface {
	StoreCaptureException(ctx context.Context, tx *gorm.DB, orgID uuid.UUID, projectID uuid.UUID, assetID uuid.UUID, assetVersionName string, message string) error
	StoreRecoverPanic(ctx context.Context, tx *gorm.DB, orgID uuid.UUID, projectID uuid.UUID, assetID uuid.UUID, assetVersionName string, message string) error
}

type AlertOptions struct {
	Ctx              context.Context
	Tx               *gorm.DB
	OrgID            uuid.UUID
	ProjectID        uuid.UUID
	AssetID          uuid.UUID
	AssetVersionName string
}

var logger LogService

func SetLogger(ls LogService) {
	logger = ls
}

func Alert(message string, err error, opts AlertOptions) {
	// log it
	evID := sentry.CurrentHub().CaptureException(errors.Wrap(err, message))
	if evID == nil {
		slog.Error("critical error encountered - not send to external error tracking", "msg", message, "error", err)
	} else {
		slog.Error("critical error encountered", "msg", message, "error", err, "id", *evID)
	}
	ctx := opts.Ctx
	if ctx == nil {
		ctx = context.Background()
	}
	loggerErr := logger.StoreCaptureException(ctx, opts.Tx, opts.OrgID, opts.ProjectID, opts.AssetID, opts.AssetVersionName, message)
	if loggerErr != nil {
		slog.Error("could not store error in database", "msg", message, "error", err)
	}
}

func RecoverAndAlert(message string, err error, opts AlertOptions) {
	evID := sentry.CurrentHub().Recover(err)
	slog.Error("critical error encountered (recover)", "msg", message, "error", err, "id (<nil> if not sent to error tracking)", evID)
	sentry.Flush(10 * time.Second)
	ctx := opts.Ctx
	if ctx == nil {
		ctx = context.Background()
	}
	loggerErr := logger.StoreCaptureException(ctx, opts.Tx, opts.OrgID, opts.ProjectID, opts.AssetID, opts.AssetVersionName, message)
	if loggerErr != nil {
		slog.Error("could not store error in database", "msg", message, "error", err)
	}
}

func RecoverPanic(msg string, opts AlertOptions) {
	if r := recover(); r != nil {
		Alert(msg, fmt.Errorf("panic recovered: %v", r), opts)
	}
	ctx := opts.Ctx
	if ctx == nil {
		ctx = context.Background()
	}
	loggerErr := logger.StoreRecoverPanic(ctx, opts.Tx, opts.OrgID, opts.ProjectID, opts.AssetID, opts.AssetVersionName, msg)
	if loggerErr != nil {
		slog.Error("could not store error in database", "msg", msg, "err", loggerErr)
	}
}
