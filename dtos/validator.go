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
package dtos

import (
	"time"

	"github.com/go-playground/validator/v10"
)

var V = func() *validator.Validate {
	v := validator.New()
	// future_max_1y: value must be a Unix timestamp between now and now+1 year
	v.RegisterValidation("future_max_1y", func(fl validator.FieldLevel) bool { //nolint:errcheck
		ts := fl.Field().Int()
		now := time.Now().Unix()
		return ts > now && ts <= now+31536000
	})
	return v
}()
