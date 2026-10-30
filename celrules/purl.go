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
	"fmt"

	"github.com/Masterminds/semver"
	"github.com/package-url/packageurl-go"
)

func PurlVersionMatches(patternPurl, pathPurl packageurl.PackageURL) (bool, error) {
	if patternPurl.Type != pathPurl.Type || patternPurl.Namespace != pathPurl.Namespace || patternPurl.Name != pathPurl.Name {
		return false, nil
	}

	constraint, err := semver.NewConstraint(patternPurl.Version)
	if err != nil {
		return false, fmt.Errorf("invalid pattern version constraint: %w", err)
	}
	version, err := semver.NewVersion(pathPurl.Version)
	if err != nil {
		return false, fmt.Errorf("invalid path version: %w", err)
	}
	return constraint.Check(version), nil
}
