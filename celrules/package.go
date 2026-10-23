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
	"time"
)

type Package struct {
	Name       string
	Version    string
	Ecosystem  string
	Purl       string
	Registry   string
	ReleasedAt time.Time
	Publisher  *Publisher
	Provenance *Provenance
}

type Publisher struct {
	Name                    string
	ChangedSinceLastVersion bool
}

type Provenance struct {
	SourceRepository string
	Builder          string
}

func timeToCEL(t time.Time) string {
	return t.Format(time.RFC3339Nano)
}

func (p Package) ToCELMap() map[string]any {
	m := map[string]any{
		"name":      p.Name,
		"version":   p.Version,
		"ecosystem": p.Ecosystem,
		"purl":      p.Purl,
		"registry":  p.Registry,
	}

	if !p.ReleasedAt.IsZero() {
		m["releasedAt"] = timeToCEL(p.ReleasedAt)
	}

	if p.Publisher != nil {
		m["publisher"] = map[string]any{
			"name":                    p.Publisher.Name,
			"changedSinceLastVersion": p.Publisher.ChangedSinceLastVersion,
		}
	}

	if p.Provenance != nil {
		m["provenance"] = map[string]any{
			"sourceRepository": p.Provenance.SourceRepository,
			"builder":          p.Provenance.Builder,
		}
	}

	return m
}
