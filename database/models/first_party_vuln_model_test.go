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

package models

import (
	"testing"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/stretchr/testify/assert"
)

func TestBeforeSave(t *testing.T) {
	t.Run("Normal Vuln with a valid line", func(t *testing.T) {
		firstPartyVuln := FirstPartyVuln{}
		err := firstPartyVuln.BeforeSave(nil)
		if err != nil {
			t.Fail()
		}
		assert.Equal(t, firstPartyVuln.CalculateHash(), firstPartyVuln.ID)
	})
}

func TestTitle(t *testing.T) {
	t.Run("URI is empty", func(t *testing.T) {
		firstPartyVuln := FirstPartyVuln{RuleName: "tralalero tralala"}
		assert.Equal(t, "tralalero tralala", firstPartyVuln.Title())
	})
	t.Run("URI not empty", func(t *testing.T) {
		firstPartyVuln := FirstPartyVuln{URI: "tung/tung/tung/sahur", RuleName: "tralalero tralala"}
		assert.Equal(t, "tralalero tralala found in tung/tung/tung/sahur", firstPartyVuln.Title())
	})
}

func TestTableName(t *testing.T) {
	t.Run("Normal Vuln with a valid line", func(t *testing.T) {
		firstPartyVuln := FirstPartyVuln{}
		assert.Equal(t, "first_party_vulnerabilities", firstPartyVuln.TableName())
	})
}

func TestGetType(t *testing.T) {
	t.Run("Normal Vuln with a valid line", func(t *testing.T) {
		firstPartyVuln := FirstPartyVuln{}
		assert.Equal(t, dtos.VulnType("firstPartyVuln"), firstPartyVuln.GetType())
	})
}

func TestCalculateHash(t *testing.T) {
	t.Run("Normal Vuln with a valid line", func(t *testing.T) {
		firstPartyVuln := FirstPartyVuln{
			RuleID:           "no smoking on airplanes",
			URI:              "",
			Vulnerability:    Vulnerability{AssetID: uuid.New(), AssetVersionID: uuid.New()},
			AssetVersionName: "bombardini krokodili",
		}
		expectedHash := uuid.MustParse(utils.HashString(firstPartyVuln.RuleID + "/" + firstPartyVuln.URI + "/" + firstPartyVuln.ScannerIDs + "/" + firstPartyVuln.AssetID.String() + "/" + firstPartyVuln.AssetVersionName + "/" + firstPartyVuln.AssetVersionID.String())[:32])
		assert.Equal(t, expectedHash, firstPartyVuln.CalculateHash())
	})

	t.Run("Fingerprint is scoped to the asset version", func(t *testing.T) {
		fingerprint := "same-finding"
		assetVersionID := uuid.New()
		firstPartyVuln := FirstPartyVuln{
			Vulnerability: Vulnerability{AssetVersionID: assetVersionID},
			Fingerprint:   fingerprint,
		}
		sameVersionVuln := FirstPartyVuln{
			Vulnerability: Vulnerability{AssetVersionID: assetVersionID},
			Fingerprint:   fingerprint,
		}
		otherVersionVuln := FirstPartyVuln{
			Vulnerability: Vulnerability{AssetVersionID: uuid.New()},
			Fingerprint:   fingerprint,
		}

		assert.Equal(t, firstPartyVuln.CalculateHash(), sameVersionVuln.CalculateHash())
		assert.NotEqual(t, firstPartyVuln.CalculateHash(), otherVersionVuln.CalculateHash())
	})
}
