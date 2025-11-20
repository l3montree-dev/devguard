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

package normalize

import (
	"encoding/json"
	"slices"
	"sort"
	"strings"

	"github.com/secure-systems-lab/go-securesystemslib/cjson"
)

func SortStringsSlice(slice []string) []string {
	sorted := make([]string, len(slice))
	copy(sorted, slice)
	sort.Strings(sorted)
	return sorted
}

// this is a deep sort function that sorts all maps and slices recursively
// it is REALLY expensive, so use it wisely!
// it treats any arrays as sets and sorts them by their canonical JSON representation
func DeepSort(el any) any {
	// make sure to have low level types.
	// we need to convert complex structures to basic types first
	b, _ := json.Marshal(el)
	var v any
	_ = json.Unmarshal(b, &v)

	switch val := v.(type) {
	case map[string]any:
		result := make(map[string]any)
		for k, v := range val {
			result[k] = DeepSort(v)
		}
		return result

	case []any:
		sorted := make([]any, len(val))
		for i, item := range val {
			sorted[i] = DeepSort(item)
		}

		// Sort by marshaled representation
		slices.SortFunc(sorted, func(i, j any) int {
			iBytes, _ := cjson.EncodeCanonical(i)
			jBytes, _ := cjson.EncodeCanonical(j)
			return strings.Compare(string(iBytes), string(jBytes))
		})
		return sorted

	default:
		return val
	}
}
