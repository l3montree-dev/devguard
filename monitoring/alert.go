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
	"fmt"
	"log/slog"
	"time"

	"github.com/getsentry/sentry-go"
	"github.com/pkg/errors"
)

func Alert(message string, err error) {
	// log it
	evID := sentry.CurrentHub().CaptureException(errors.Wrap(err, message))
	if evID == nil {
		slog.Error("critical error encountered - not send to error tracking", "msg", message, "error", err)
	} else {
		slog.Error("critical error encountered", "msg", message, "error", err, "id", *evID)
	}
}

func RecoverAndAlert(message string, err error) {
	evID := sentry.CurrentHub().Recover(err)
	slog.Error("critical error encountered (recover)", "msg", message, "error", err, "id (<nil> if not sent to error tracking)", evID)
	sentry.Flush(10 * time.Second)
}

func RecoverPanic(msg string) {
	if r := recover(); r != nil {
		Alert(msg, fmt.Errorf("panic recovered: %v", r))
	}
}
