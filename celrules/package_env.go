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

package celrules

import (
	"sync"

	"github.com/google/cel-go/cel"
)

var packageCelEnv = sync.OnceValues(func() (*cel.Env, error) {
	return newPackageCelEnv()
})

func newPackageCelEnv() (*cel.Env, error) {
	base, err := baseEnv()
	if err != nil {
		return nil, err
	}
	return base.Extend(cel.Variable("pkg", cel.AnyType))
}
