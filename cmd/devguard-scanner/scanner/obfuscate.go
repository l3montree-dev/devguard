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

package scanner

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/l3montree-dev/devguard/dtos/sarif"
	"github.com/l3montree-dev/devguard/utils"
)

func ObfuscateString(str string) string {
	// split into lines so we preserve newlines exactly
	lines := strings.Split(str, "\n")

	for li, line := range lines {
		if line == "" {
			continue
		}

		// We want to obfuscate high-entropy tokens but preserve all original
		// intra-line whitespace (including tabs). To do this, split the line
		// into tokens while keeping the separators using a regexp.
		// This regexp matches sequences of non-whitespace characters (tokens)
		// or sequences of whitespace characters (separators).
		reg := regexp.MustCompile(`([^\t\s]+|[\t ]+)`)
		parts := reg.FindAllString(line, -1)

		for pi, part := range parts {
			// only consider non-whitespace tokens for obfuscation
			if strings.TrimSpace(part) == "" {
				continue
			}

			entropy := utils.ShannonEntropy(part)
			if entropy > 4 {
				// keep first half + 1 char, obfuscate the rest with asterisks
				parts[pi] = part[:1+len(part)/2] + strings.Repeat("*", len(part)/2)
			}
		}

		lines[li] = strings.Join(parts, "")
	}

	return strings.Join(lines, "\n")
}

// add obfuscation function for snippet
func ObfuscateSecretAndAddFingerprint(sarifScan *sarif.SarifSchema210Json) {
	// obfuscate the snippet
	for ru, run := range sarifScan.Runs {
		for re, result := range run.Results {
			if len(result.Locations) == 0 {
				continue
			}
			// make sure to set the result.Fingerprints
			if result.Fingerprints == nil {
				result.Fingerprints = map[string]string{}
			}
			// obfuscate the snippet
			for lo, location := range result.Locations {
				snippet := utils.OrDefault(location.PhysicalLocation.Region.Snippet.Text, "")
				snippetMax := 20
				if len(snippet) < snippetMax {
					snippetMax = len(snippet) / 2
				}
				snippet = snippet[:snippetMax] + strings.Repeat("*", len(snippet)-snippetMax)
				// set the snippet
				sarifScan.Runs[ru].Results[re].Locations[lo].PhysicalLocation.Region.Snippet.Text = &snippet
			}

			//set the fingerprint to the calculated fingerprint if it exists
			result.Fingerprints["calculatedFingerprint"] = result.PartialFingerprints["commitSha"] + ":" + utils.OrDefault(result.Locations[0].PhysicalLocation.ArtifactLocation.URI, "") + ":" + utils.OrDefault(result.RuleID, "") + ":" + strconv.Itoa(utils.OrDefault(result.Locations[0].PhysicalLocation.Region.StartLine, 0))

		}
	}
}
