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

package transformer

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	gocsaf "github.com/gocsaf/csaf/v3/csaf"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestCSAFtoVexRules(t *testing.T) {
	// read the csaf_vex.json from testdata
	data, err := os.ReadFile("testdata/csaf_vex.json")
	if err != nil {
		t.Fatalf("could not read testdata/csaf_vex.json: %v", err)
	}

	var advisory gocsaf.Advisory
	err = json.Unmarshal(data, &advisory)
	if err != nil {
		t.Fatalf("could not unmarshal testdata/csaf_vex.json: %v", err)
	}

	assetID := uuid.New()
	assetVersionName := "1.0.0"
	rules, err := CSAFVEXToRules(&advisory, assetID, assetVersionName, "test")
	if err != nil {
		t.Fatalf("CSAFVEXToRules failed: %v", err)
	}

	// two distinct paths are marked known_not_affected in the testdata, so we expect one rule per path
	if len(rules) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(rules))
	}

	gotPaths := make([]string, 0, len(rules))
	for _, r := range rules {
		gotPaths = append(gotPaths, strings.Join(r.PathPattern, ","))
	}

	expectedPaths := []string{
		strings.Join([]string{
			"pkg:golang/github.com/l3montree-dev/devguard@main",
			"pkg:golang/oras.land/oras-go/v2@v2.6.1",
		}, ","),
		strings.Join([]string{
			"pkg:golang/github.com/l3montree-dev/devguard@main",
			"pkg:golang/github.com/open-policy-agent/opa@v1.18.2",
			"pkg:golang/oras.land/oras-go/v2@v2.6.1",
		}, ","),
	}
	assert.ElementsMatch(t, expectedPaths, gotPaths, "PathPatterns do not match expected")
}
