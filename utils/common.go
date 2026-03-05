// Copyright (C) 2024 Tim Bastin, l3montree GmbH
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

package utils

import (
	"math"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// we use Set 1 of ISO 639 language codes to identify languages based on 2 letters
var supportedLanguageCodes = []string{"de", "en"}

func Ptr[T any](t T) *T {
	return &t
}

func SlicePtr[T any](t []T) []*T {
	res := make([]*T, len(t))
	for i := range t {
		res[i] = &t[i]
	}
	return res
}

func RunsInCI() bool {
	if val, ok := os.LookupEnv("CI"); ok {
		return val == "true"
	}
	return false
}

func RemovePrefixInsensitive(input string, prefix string) string {
	if strings.HasPrefix(strings.ToLower(input), strings.ToLower(prefix)) {
		return input[len(prefix):]
	}
	return input
}
func SafeDereference(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func EmptyThenNil(s string) *string {
	if s == "" {
		return nil
	}
	return Ptr(s)
}

func OrDefault[T any](val *T, def T) T {
	if val == nil {
		return def
	}
	return *val
}

func Or[T any](
	val *T,
	fallback *T,
) *T {
	if val == nil {
		return fallback
	}
	return val
}

func AddToWhitespaceSeparatedStringList(s string, item string) string {
	itemEls := strings.Fields(item)
	// parse all scanner ids
	els := strings.Fields(s)
	// check if the scanner id is already in the list
	for _, itemEl := range itemEls {
		if !slices.Contains(els, itemEl) {
			els = append(els, itemEl)
		}
	}

	return strings.Join(els, " ")
}

func RemoveFromWhitespaceSeparatedStringList(s string, item string) string {
	// parse all scanner els
	els := strings.Fields(s)

	var res []string
	for _, id := range els {
		if id != item {
			res = append(res, id)
		}
	}

	return strings.Join(res, " ")
}

func ContainsInWhitespaceSeparatedStringList(s string, item string) bool {
	els := strings.Fields(s)
	return slices.Contains(els, item)
}

func CompareFirstTwoDecimals(a, b float64) bool {

	aRounded := math.Round(a*100) / 100
	bRounded := math.Round(b*100) / 100

	return aRounded == bRounded
}

func ShannonEntropy(str string) float64 {
	frequencies := make(map[rune]float64)

	for _, i := range str {
		frequencies[i]++
	}

	var sum float64

	for _, v := range frequencies {
		f := v / float64(len(str))
		sum += -f * math.Log2(f)
	}

	return sum
}

// supported languages are declared in `supportedLanguageCodes` at the start of this file
func CheckForValidLanguageCode(languageCode string) bool {
	return slices.Contains(supportedLanguageCodes, languageCode)
}

func GetDirFromPath(path string) string {
	fi, err := os.Stat(path)
	if err != nil {
		return path
	}
	switch mode := fi.Mode(); {
	case mode.IsDir():
		return path
	case mode.IsRegular():
		return filepath.Dir(path)
	}
	return path
}

// DeduplicateSlice deduplicates a slice in O(n) out of place.
func DeduplicateSlice[T any](slice []T, idFunc func(t T) string) []T {
	deduplicatedSlice := make([]T, 0, len(slice))
	seen := make(map[string]struct{}, len(slice))
	for i := range slice {
		id := idFunc(slice[i])
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		deduplicatedSlice = append(deduplicatedSlice, slice[i])
	}
	return deduplicatedSlice
}

func CheckIfDeleted(name string) bool {
	return strings.Contains(name, "-deletion_scheduled-")
}
